import os
from datetime import datetime, timedelta, UTC
import time
import re
import imaplib
import email
from email.header import decode_header
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, url_for, render_template, redirect, session, send_from_directory
from flask_cors import CORS
import jwt
from functools import wraps
from pymongo import MongoClient
from bson import ObjectId

# ----------------------------------
# Configuration
# ----------------------------------
app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# Add CORS headers to all responses
@app.after_request
def after_request(response):
    # Only add CORS headers for API routes
    if request.path.startswith('/api/'):
        origin = request.headers.get('Origin')
        if origin:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Vary'] = 'Origin'
        else:
            response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,Accept,Origin,X-Requested-With'
        response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
        response.headers['Access-Control-Max-Age'] = '3600'
        # لا تفرض Content-Type إلا إذا كان الرد فعلاً JSON
        if response.is_json:
            response.headers['Content-Type'] = 'application/json'
    return response

# معالجة جميع الأخطاء لتعيد JSON بدلاً من HTML
from flask import jsonify
@app.errorhandler(Exception)
def handle_exception(e):
    from werkzeug.exceptions import HTTPException
    code = 500
    if isinstance(e, HTTPException):
        code = e.code
        description = e.description
    else:
        description = str(e)
    response = jsonify({
        "error": description or "حدث خطأ غير متوقع"
    })
    response.status_code = code
    return response

# استخدم متغير بيئة للسرية أو افتراضي
app.secret_key = "aslam2001aslaam23456"

# MongoDB Configuration

try:
    client = MongoClient(
        "mongodb+srv://aslamfilex:yX49fFOzrALzxuTO@cluster0.kl0lt7u.mongodb.net/",
        tls=True,
        tlsAllowInvalidCertificates=True,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=10000,
    )
    db = client["netflix_bot_db"]
except Exception as e:
    print(
        "MongoDB connection failed. If you use an Atlas SRV URI, ensure the DNS "
        "record exists and your network can resolve it. You can also set "
        "MONGO_URI to a standard mongodb://host:port URI.",
    )
    raise

# Collections
admins_coll = db['admins']
users_coll = db['users']
requests_coll = db['requests']
subscriptions_coll = db['subscriptions']



# إعدادات JWT
JWT_SECRET = "oamrkali3jjeiodfijlsd"
JWT_ALGORITHM = 'HS256'

# إعدادات البريد الإلكتروني
EMAIL = 'mtgrflix199@gmail.com'
PASSWORD =  'xwwd txyj kuck ypjl'
IMAP_SERVER ='imap.gmail.com'

# فتح الاتصال بالبريد مرة واحدة فقط
mail = None

# ----------------------------------
# وظائف مساعدة للبريد
# ----------------------------------

def clean_text(text):
    return text.strip()

def retry_imap_connection():
    global mail
    try:
        if mail:
            try:
                mail.noop()
                return
            except:
                mail = None
    except:
        mail = None
    for attempt in range(3):
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(EMAIL, PASSWORD)
            try:
                mail.enable("UTF8=ACCEPT")
                mail._encoding = "utf-8"
            except Exception:
                pass
            print("✅ اتصال IMAP ناجح.")
            return
        except Exception as e:
            print(f"❌ فشل الاتصال (المحاولة {attempt + 1}): {e}")
            mail = None
    print("❌ فشل إعادة الاتصال بعد عدة محاولات.")
    raise Exception("فشل الاتصال بخادم البريد الإلكتروني")

def retry_on_error(func):
    """ديكورتر لإعادة المحاولة عند حدوث خطأ في جلب الرسائل."""
    def wrapper(*args, **kwargs):
        retries = 3
        for attempt in range(retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if "EOF occurred" in str(e) or "socket" in str(e):
                    # time.sleep(2)  # إزالة الانتظار بعد خطأ في الاتصال
                    print(f"Retrying... Attempt {attempt + 1}/{retries}")
                else:
                    return f"Error fetching emails: {e}"
        return "Error: Failed after multiple retries."
    return wrapper

def build_gmail_query(account, subject_keywords):
    subject_query = " OR ".join([f'subject:"{keyword}"' for keyword in subject_keywords])
    return f'to:{account} ({subject_query})'


def quote_gmail_query(query):
    escaped = query.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def safe_gmail_search(account, subject_keywords):
    try:
        gmail_query = quote_gmail_query(build_gmail_query(account, subject_keywords))
        return mail.search("UTF-8", "X-GM-RAW", gmail_query)
    except Exception as e:
        print(f"IMAP UTF-8 search failed, fallback to ASCII: {e}")
        fallback_query = quote_gmail_query(f"to:{account}")
        return mail.search(None, "X-GM-RAW", fallback_query)


def fetch_email_with_link(account, subject_keywords, button_text):
    retry_imap_connection()
    try:
        mail.select("inbox", readonly=True)

        _, data = safe_gmail_search(account, subject_keywords)
        mail_ids = data[0].split()

        if not mail_ids:
            # Fallback to broader search if Gmail query yields no results
            _, data = mail.search(None, "ALL")
            mail_ids = data[0].split()[-20:]
        
        result = "طلبك غير موجود."
        for mail_id in reversed(mail_ids[-20:]):
            try:
                _, msg_data = mail.fetch(mail_id, "(RFC822)")
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                # التحقق من عنوان البريد الإلكتروني
                to_address = msg.get('To', '')
                if account.lower() not in to_address.lower():
                    continue

                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")

                if any(keyword in subject for keyword in subject_keywords):
                    for part in msg.walk():
                        if part.get_content_type() == "text/html":
                            html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            if account.lower() in html_content.lower():  # Case-insensitive search
                                soup = BeautifulSoup(html_content, 'html.parser')
                                for a in soup.find_all('a', href=True):
                                    if button_text in a.get_text():
                                        result = a['href']
                                        break
                if result != "طلبك غير موجود.":
                    break
            except Exception as e:
                print(f"Error processing email {mail_id}: {str(e)}")
                continue
                
        # Close the connection
        return result
    except Exception as e:
        print(f"Error in fetch_email_with_link: {str(e)}")  # Added logging
        return f"Error fetching emails: {e}"

@retry_on_error
def fetch_email_with_code(account, subject_keywords, code_length=4):
    retry_imap_connection()
    try:
        mail.select("inbox", readonly=True)

        _, data = safe_gmail_search(account, subject_keywords)
        mail_ids = data[0].split()

        if not mail_ids:
            # Fallback to broader search if Gmail query yields no results
            _, data = mail.search(None, "ALL")
            mail_ids = data[0].split()[-20:]
        
        result = "طلبك غير موجود."
        for mail_id in reversed(mail_ids[-20:]):
            try:
                _, msg_data = mail.fetch(mail_id, "(RFC822)")
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                # التحقق من عنوان البريد الإلكتروني
                to_address = msg.get('To', '')
                if account.lower() not in to_address.lower():
                    continue

                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")

                if any(keyword in subject for keyword in subject_keywords):
                    for part in msg.walk():
                        if part.get_content_type() == "text/html":
                            html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            if account.lower() in html_content.lower():  # Case-insensitive search
                                code_pattern = rf'\b\d{{{code_length}}}\b'
                                code_match = re.search(code_pattern, BeautifulSoup(html_content, 'html.parser').get_text())
                                if code_match:
                                    result = code_match.group(0)
                                    break
                if result != "طلبك غير موجود.":
                    break
            except Exception as e:
                print(f"Error processing email {mail_id}: {str(e)}")
                continue
                
        # Close the connection
        return result
    except Exception as e:
        print(f"Error in fetch_email_with_code: {str(e)}")  # Added logging
        return f"Error fetching emails: {e}"

# ----------------------------------
# مصادقة المدير
# ----------------------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------
# المسارات (Routes)
# ----------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/public/<path:filename>')
def public_file(filename):
    public_dir = os.path.join(os.path.dirname(__file__), "public")
    return send_from_directory(public_dir, filename)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin = admins_coll.find_one({
            "username": username,
            "password": password  # In production, use proper password hashing
        })
        
        if admin:
            session['admin_logged_in'] = True
            session['admin_id'] = str(admin['_id'])
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html', error='بيانات الدخول غير صحيحة')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Get statistics
    total_users = users_coll.count_documents({})
    active_subscriptions = subscriptions_coll.count_documents({
        "expires_at": {"$gt": datetime.now(UTC)}
    })
    recent_requests = list(requests_coll.find().sort("timestamp", -1).limit(10))
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         active_subscriptions=active_subscriptions,
                         recent_requests=recent_requests)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route('/api/generate-subscription-link', methods=['POST'])
@admin_required
def generate_subscription_link():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        role = data.get('role')
        
        if not user_id or role not in ['normal1', 'normal2']:
            return jsonify(error='Invalid user_id or role'), 400
        
        # Create or update user
        users_coll.update_one(
            {"username": user_id},
            {"$set": {"username": user_id}},
            upsert=True
        )
        
        # Create subscription
        expires_at = datetime.now(UTC) + timedelta(days=30)
        subscriptions_coll.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "user_id": user_id,
                    "role": role,
                    "created_at": datetime.now(UTC),
                    "expires_at": expires_at
                }
            },
            upsert=True
        )
        
        # Generate JWT token
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': expires_at
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        link = f"{request.host_url}user/{token}"
        
        return jsonify(link=link), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/user/<token>')
def user_page(token):
    try:
        # Set session lifetime to 30 days
        app.permanent_session_lifetime = timedelta(days=30)
        session.permanent = True

        # Decode and verify token
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get('user_id')
            role = payload.get('role')
            
            if not user_id or not role:
                print(f"Invalid token data - user_id: {user_id}, role: {role}")
                session.clear()
                return render_template('invalid.html')
        except jwt.ExpiredSignatureError:
            print("Token expired")
            session.clear()
            return render_template('expired.html')
        except jwt.InvalidTokenError:
            print("Invalid token")
            session.clear()
            return render_template('invalid.html')
        
        # Check subscription
        subscription = subscriptions_coll.find_one({
            "user_id": user_id,
            "expires_at": {"$gt": datetime.now(UTC)}
        })
        
        if not subscription:
            print(f"Subscription expired for user: {user_id}")
            session.clear()
            return render_template('expired.html')
        
        # Store user info in session
        session['user_id'] = user_id
        session['user_role'] = role
        session['token'] = token
        session['last_activity'] = datetime.now(UTC).isoformat()
        
        print(f"Session created successfully for user: {user_id}")
        return render_template('user.html', user_id=user_id, role=role)
    except Exception as e:
        print(f"Unexpected error in user_page: {str(e)}")
        session.clear()
        return render_template('error.html', error="حدث خطأ في قراءة البيانات من الخادم")

# Email-fetch APIs with logging
@app.route('/api/fetch-residence-update-link', methods=['POST', 'OPTIONS'])
def fetch_residence_update_link():
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Origin,X-Requested-With')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        response.headers.add('Access-Control-Max-Age', '3600')
        return response
    try:
        if not request.is_json:
            return jsonify(error='Content-Type must be application/json'), 400, {'Content-Type': 'application/json'}
            
        data = request.get_json()
        if not data:
            return jsonify(error='No data provided'), 400, {'Content-Type': 'application/json'}
            
        account = data.get('account')
        if not account:
            return jsonify(error='Account is required'), 400, {'Content-Type': 'application/json'}
            
        account = account.strip()
        if not account:
            return jsonify(error='Account cannot be empty'), 400, {'Content-Type': 'application/json'}
        
        link = fetch_email_with_link(account, ["تحديث السكن"], "نعم، أنا قدمت الطلب")
        log_request(session.get('admin_id', 'unknown'), 'residence_update_link', account, 'success' if link else 'not_found', link)
        return jsonify(link=link), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        print(f"Error in fetch_residence_update_link: {str(e)}")
        log_request(session.get('admin_id', 'unknown'), 'residence_update_link', account, 'error', str(e))
        return jsonify(error=str(e)), 500, {'Content-Type': 'application/json'}

@app.route('/api/fetch-residence-code', methods=['POST', 'OPTIONS'])
def fetch_residence_code():
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Origin,X-Requested-With')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        response.headers.add('Access-Control-Max-Age', '3600')
        return response
    try:
        if not request.is_json:
            return jsonify(error='Content-Type must be application/json'), 400, {'Content-Type': 'application/json'}
            
        data = request.get_json()
        if not data:
            return jsonify(error='No data provided'), 400, {'Content-Type': 'application/json'}
            
        account = data.get('account')
        if not account:
            return jsonify(error='Account is required'), 400, {'Content-Type': 'application/json'}
            
        account = account.strip()
        if not account:
            return jsonify(error='Account cannot be empty'), 400, {'Content-Type': 'application/json'}
        
        code = fetch_email_with_link(account, ["رمز الوصول المؤقت"], "الحصول على الرمز")
        log_request(session.get('admin_id', 'unknown'), 'residence_code', account, 'success' if code else 'not_found', code)
        return jsonify(code=code), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        print(f"Error in fetch_residence_code: {str(e)}")
        log_request(session.get('admin_id', 'unknown'), 'residence_code', account, 'error', str(e))
        return jsonify(error=str(e)), 500, {'Content-Type': 'application/json'}

@app.route('/api/fetch-password-reset-link', methods=['POST', 'OPTIONS'])
def fetch_password_reset_link():
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Origin,X-Requested-With')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        response.headers.add('Access-Control-Max-Age', '3600')
        return response
    try:
        if not request.is_json:
            return jsonify(error='Content-Type must be application/json'), 400, {'Content-Type': 'application/json'}
            
        data = request.get_json()
        if not data:
            return jsonify(error='No data provided'), 400, {'Content-Type': 'application/json'}
            
        account = data.get('account')
        if not account:
            return jsonify(error='Account is required'), 400, {'Content-Type': 'application/json'}
            
        account = account.strip()
        if not account:
            return jsonify(error='Account cannot be empty'), 400, {'Content-Type': 'application/json'}
        
        link = fetch_email_with_link(account, ["إعادة تعيين كلمة المرور"], "إعادة تعيين كلمة المرور")
        log_request(session.get('admin_id', 'unknown'), 'password_reset_link', account, 'success' if link else 'not_found', link)
        return jsonify(link=link), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        print(f"Error in fetch_password_reset_link: {str(e)}")
        log_request(session.get('admin_id', 'unknown'), 'password_reset_link', account, 'error', str(e))
        return jsonify(error=str(e)), 500, {'Content-Type': 'application/json'}

@app.route('/api/fetch-login-code', methods=['POST', 'OPTIONS'])
def fetch_login_code():
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Origin,X-Requested-With')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        response.headers.add('Access-Control-Max-Age', '3600')
        return response
    try:
        if not request.is_json:
            return jsonify(error='Content-Type must be application/json'), 400, {'Content-Type': 'application/json'}
            
        data = request.get_json()
        if not data:
            return jsonify(error='No data provided'), 400, {'Content-Type': 'application/json'}
            
        account = data.get('account')
        if not account:
            return jsonify(error='Account is required'), 400, {'Content-Type': 'application/json'}
            
        account = account.strip()
        if not account:
            return jsonify(error='Account cannot be empty'), 400, {'Content-Type': 'application/json'}
        
        code = fetch_email_with_code(account, ["رمز تسجيل الدخول"])
        log_request(session.get('admin_id', 'unknown'), 'login_code', account, 'success' if code else 'not_found', code)
        return jsonify(code=code), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        print(f"Error in fetch_login_code: {str(e)}")
        log_request(session.get('admin_id', 'unknown'), 'login_code', account, 'error', str(e))
        return jsonify(error=str(e)), 500, {'Content-Type': 'application/json'}

@app.route('/api/fetch-verification-code', methods=['POST', 'OPTIONS'])
def fetch_verification_code():
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Origin,X-Requested-With')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        response.headers.add('Access-Control-Max-Age', '3600')
        return response
    try:
        if not request.is_json:
            return jsonify(error='Content-Type must be application/json'), 400, {'Content-Type': 'application/json'}

        data = request.get_json()
        if not data:
            return jsonify(error='No data provided'), 400, {'Content-Type': 'application/json'}

        account = data.get('account')
        if not account:
            return jsonify(error='Account is required'), 400, {'Content-Type': 'application/json'}

        account = account.strip()
        if not account:
            return jsonify(error='Account cannot be empty'), 400, {'Content-Type': 'application/json'}

        code = fetch_email_with_code(account, ["رمز التحقق"], code_length=6)
        log_request(session.get('admin_id', 'unknown'), 'verification_code', account, 'success' if code else 'not_found', code)
        return jsonify(code=code), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        print(f"Error in fetch_verification_code: {str(e)}")
        log_request(session.get('admin_id', 'unknown'), 'verification_code', account, 'error', str(e))
        return jsonify(error=str(e)), 500, {'Content-Type': 'application/json'}

@app.route('/api/fetch-suspended-account-link', methods=['POST', 'OPTIONS'])
def fetch_suspended_account_link():
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Origin,X-Requested-With')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        response.headers.add('Access-Control-Max-Age', '3600')
        return response
    try:
        if not request.is_json:
            return jsonify(error='Content-Type must be application/json'), 400, {'Content-Type': 'application/json'}
            
        data = request.get_json()
        if not data:
            return jsonify(error='No data provided'), 400, {'Content-Type': 'application/json'}
            
        account = data.get('account')
        if not account:
            return jsonify(error='Account is required'), 400, {'Content-Type': 'application/json'}
            
        account = account.strip()
        if not account:
            return jsonify(error='Account cannot be empty'), 400, {'Content-Type': 'application/json'}
        
        link = fetch_email_with_link(account, ["عضويتك في Netflix معلّقة"], "إضافة معلومات الدفع")
        log_request(session.get('admin_id', 'unknown'), 'suspended_account_link', account, 'success' if link else 'not_found', link)
        return jsonify(link=link), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        print(f"Error in fetch_suspended_account_link: {str(e)}")
        log_request(session.get('admin_id', 'unknown'), 'suspended_account_link', account, 'error', str(e))
        return jsonify(error=str(e)), 500, {'Content-Type': 'application/json'}

# ----------------------------------
# Database Initialization
# ----------------------------------
def init_db():
    # Create indexes
    admins_coll.create_index("username", unique=True)
    users_coll.create_index("username", unique=True)
    requests_coll.create_index([("timestamp", -1)])
    subscriptions_coll.create_index([("expires_at", 1)])

def log_request(admin_id, request_type, account, status, result=None):
    requests_coll.insert_one({
        "admin_id": admin_id,
        "request_type": request_type,
        "account": account,
        "status": status,
        "result": result,
        "timestamp": datetime.now(UTC)
    })

def check_subscription(user_id):
    subscription = subscriptions_coll.find_one({
        "user_id": user_id,
        "expires_at": {"$gt": datetime.now(UTC)}
    })
    return subscription is not None

def create_subscription(user_id, role):
    created_at = datetime.now(UTC)
    expires_at = created_at + timedelta(days=30)
    subscriptions_coll.insert_one({
        "user_id": user_id,
        "role": role,
        "created_at": created_at,
        "expires_at": expires_at
    })
    return expires_at

def delete_expired_users():
    """حذف المستخدمين والاشتراكات منتهية الصلاحية"""
    try:
        # حذف الاشتراكات منتهية الصلاحية
        expired_subscriptions = subscriptions_coll.find({
            "expires_at": {"$lt": datetime.now(UTC)}
        })
        
        for subscription in expired_subscriptions:
            # حذف المستخدم
            users_coll.delete_one({"username": subscription["user_id"]})
            # حذف الاشتراك
            subscriptions_coll.delete_one({"_id": subscription["_id"]})
            
        print("✅ تم حذف المستخدمين منتهيي الصلاحية بنجاح")
    except Exception as e:
        print(f"❌ خطأ في حذف المستخدمين: {e}")

# إضافة دالة لفحص وحذف المستخدمين منتهيي الصلاحية كل ساعة
def schedule_cleanup():
    while True:
        delete_expired_users()
        time.sleep(3600)  # انتظار ساعة واحدة

if __name__ == '__main__':
    init_db()
    # بدء عملية التنظيف التلقائي في خيط منفصل
    import threading
    cleanup_thread = threading.Thread(target=schedule_cleanup, daemon=True)
    cleanup_thread.start()
    
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
