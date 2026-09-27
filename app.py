import os
import secrets
import string
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
from threading import Lock

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
            response.headers['Access-Control-Allow-Credentials'] = 'true'
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
PASSWORD =  'yovk bkkt qadm rbbg'
IMAP_SERVER ='imap.gmail.com'

# فتح الاتصال بالبريد مرة واحدة فقط
mail = None
imap_lock = Lock()

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
                current_state = getattr(mail, "state", "").upper()
                if current_state in {"AUTH", "SELECTED"}:
                    return
                print(f"IMAP session not ready (state={current_state}), reconnecting.")
                mail = None
            except Exception:
                mail = None
    except Exception:
        mail = None
    for attempt in range(3):
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER, timeout=15)
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


def get_decoded_subject(msg):
    raw_subject = msg.get("Subject", "")
    if not raw_subject:
        return ""
    try:
        decoded_parts = decode_header(raw_subject)
        subject_str = ""
        for content, enc in decoded_parts:
            if isinstance(content, bytes):
                subject_str += content.decode(enc or 'utf-8', errors='ignore')
            else:
                subject_str += str(content)
        return subject_str
    except Exception:
        return str(raw_subject)


def ensure_selected_mailbox(mailbox="inbox", readonly=True):
    global mail
    retry_imap_connection()
    try:
        current_state = getattr(mail, "state", "").upper()
        if current_state == "SELECTED":
            return
        status, data = mail.select(mailbox, readonly=readonly)
        if status == "OK":
            return
    except (imaplib.IMAP4.abort, imaplib.IMAP4.error) as e:
        print(f"IMAP SELECT transient failure, reconnecting: {e}")

    mail = None
    retry_imap_connection()
    try:
        status, data = mail.select(mailbox, readonly=readonly)
    except (imaplib.IMAP4.abort, imaplib.IMAP4.error) as e:
        raise imaplib.IMAP4.error(f"IMAP SELECT failed after reconnect: {e}")
    if status != "OK":
        raise imaplib.IMAP4.error(f"IMAP SELECT failed after reconnect: {status} {data}")


def run_imap_search(charset, *criteria):
    global mail
    try:
        status, data = mail.search(charset, *criteria)
    except (imaplib.IMAP4.abort, imaplib.IMAP4.error) as e:
        err = str(e).lower()
        # Gmail IMAP can sometimes return out-of-sync SEARCH responses.
        if "unexpected response" in err or "command: search" in err or "eof occurred" in err or "socket" in err:
            print(f"IMAP SEARCH transient failure, reconnecting: {e}")
            mail = None
            ensure_selected_mailbox("inbox", readonly=True)
            status, data = mail.search(charset, *criteria)
        else:
            raise
    if status != "OK":
        raise imaplib.IMAP4.error(f"IMAP SEARCH failed: {status} {data}")
    return status, data


def retry_on_error(func):
    """ديكورتر لإعادة المحاولة عند حدوث خطأ في جلب الرسائل."""
    def wrapper(*args, **kwargs):
        global mail
        retries = 3
        for attempt in range(retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                err = str(e).lower()
                if "eof occurred" in err or "socket" in err or "unexpected response" in err or "command: search" in err:
                    mail = None
                    print(f"Retrying... Attempt {attempt + 1}/{retries}")
                else:
                    return f"Error fetching emails: {e}"
        return "Error: Failed after multiple retries."
    return wrapper


def quote_gmail_query(query):
    escaped = query.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def safe_gmail_search_account(account):
    """البحث السريع عن رسائل الحساب (آخر يومين أولاً للسرعة القصوى، ثم البحث الشامل كخطة بديلة)"""
    account_clean = account.strip().lower()
    # 1. البحث السريع في رسائل آخر يومين (أسرع بكثير لأن عدد الرسائل قليل)
    try:
        query_recent = quote_gmail_query(f"to:{account_clean} newer_than:2d")
        _, data = run_imap_search(None, "X-GM-RAW", query_recent)
        mail_ids = data[0].split() if data and data[0] else []
        if mail_ids:
            return mail_ids
    except Exception as e:
        print(f"Recent search failed: {e}")

    # 2. في حال لم نجد رسائل حديثة، نبحث في كل الرسائل
    try:
        query_all = quote_gmail_query(f"to:{account_clean}")
        _, data = run_imap_search(None, "X-GM-RAW", query_all)
        mail_ids = data[0].split() if data and data[0] else []
        if mail_ids:
            return mail_ids
    except Exception as e:
        print(f"All search failed: {e}")

    # 3. خطة بديلة أخيرة
    try:
        _, data = run_imap_search(None, "ALL")
        return data[0].split()[-10:] if data and data[0] else []
    except Exception as e:
        print(f"ALL fallback failed: {e}")
        return []


def find_target_email_msg(account, subject_keywords):
    """العثور على أحدث رسالة مطابقة بأقل عدد ممكن من أوامر IMAP لضمان السرعة والدقة"""
    mail_ids = safe_gmail_search_account(account)
    if not mail_ids:
        return None

    # الخطوة 1: فحص أحدث رسالة فوراً (في 95% من الحالات تكون هي الرسالة المطلوبة)
    latest_id = mail_ids[-1]
    try:
        status, msg_data = mail.fetch(latest_id, '(BODY.PEEK[])')
        if status == "OK" and msg_data and msg_data[0]:
            msg = email.message_from_bytes(msg_data[0][1])
            subj = get_decoded_subject(msg).lower()
            if any(k.lower() in subj for k in subject_keywords):
                return msg
    except Exception as e:
        print(f"Error fetching latest email {latest_id}: {e}")

    # الخطوة 2: إذا لم تكن الرسالة الأخيرة هي المطلوبة، نجلب عناوين الرسائل السابقة دفعة واحدة بأمر واحد فقط
    if len(mail_ids) > 1:
        candidates = mail_ids[-5:-1]
        try:
            batch_str = b','.join(candidates)
            status, batch_data = mail.fetch(batch_str, '(BODY.PEEK[HEADER.FIELDS (SUBJECT TO)])')
            if status == "OK" and batch_data:
                target_id = None
                for item in reversed(batch_data):
                    if isinstance(item, tuple):
                        hdr_msg = email.message_from_bytes(item[1])
                        subj = get_decoded_subject(hdr_msg).lower()
                        if any(k.lower() in subj for k in subject_keywords):
                            target_id = item[0].split()[0]
                            break
                if target_id:
                    s, m_data = mail.fetch(target_id, '(BODY.PEEK[])')
                    if s == "OK" and m_data and m_data[0]:
                        return email.message_from_bytes(m_data[0][1])
        except Exception as e:
            print(f"Error in batch candidate search: {e}")

    return None


def extract_code_from_email(msg, code_length=4):
    if not msg:
        return None
    for part in msg.walk():
        if part.get_content_type() in ("text/html", "text/plain"):
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            text = payload.decode('utf-8', errors='ignore')
            if part.get_content_type() == "text/html":
                text = BeautifulSoup(text, 'html.parser').get_text()
            matches = re.findall(rf'\b\d{{{code_length}}}\b', text)
            for m in matches:
                # استبعاد سنوات حقوق النشر مثل 2024, 2025, 2026 إذا كان الرمز 4 أرقام
                if code_length == 4 and m in ("2023", "2024", "2025", "2026", "2027"):
                    continue
                return m
    return None


def extract_link_from_email(msg, button_keywords):
    if not msg:
        return None
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            html = payload.decode('utf-8', errors='ignore')
            soup = BeautifulSoup(html, 'html.parser')
            # 1. البحث بنص الزر
            for a in soup.find_all('a', href=True):
                txt = a.get_text().strip().lower()
                if any(btn.lower() in txt for btn in button_keywords):
                    return a['href']
            # 2. خطة بديلة: البحث عن روابط Netflix المميزة
            for a in soup.find_all('a', href=True):
                href = a['href']
                if 'netflix.com' in href and any(kw in href.lower() for kw in ('nftoken', 'password', 'household', 'travel', 'code')):
                    return href
    return None


@retry_on_error
def fetch_email_with_link(account, subject_keywords, button_keywords):
    try:
        with imap_lock:
            ensure_selected_mailbox("inbox", readonly=True)
            if isinstance(button_keywords, str):
                button_keywords = [button_keywords]
            if isinstance(subject_keywords, str):
                subject_keywords = [subject_keywords]
            msg = find_target_email_msg(account, subject_keywords)
            if msg:
                link = extract_link_from_email(msg, button_keywords)
                if link:
                    return link
            return "طلبك غير موجود."
    except Exception as e:
        print(f"Error in fetch_email_with_link: {str(e)}")
        return f"Error fetching emails: {e}"


@retry_on_error
def fetch_email_with_code(account, subject_keywords, code_length=4):
    try:
        with imap_lock:
            ensure_selected_mailbox("inbox", readonly=True)
            if isinstance(subject_keywords, str):
                subject_keywords = [subject_keywords]
            msg = find_target_email_msg(account, subject_keywords)
            if msg:
                code = extract_code_from_email(msg, code_length)
                if code:
                    return code
            return "طلبك غير موجود."
    except Exception as e:
        print(f"Error in fetch_email_with_code: {str(e)}")
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
        
        if not user_id or role not in ['normal1', 'normal2', 'normal3']:
            return jsonify(error='Invalid user_id or role'), 400
        
        # Create or update user
        users_coll.update_one(
            {"username": user_id},
            {"$set": {"username": user_id}},
            upsert=True
        )
        
        # Create subscription
        expires_at = datetime.now(UTC) + timedelta(days=30)
        update_payload = {
            "user_id": user_id,
            "role": role,
            "created_at": datetime.now(UTC),
            "expires_at": expires_at
        }
        
        if role == 'normal3':
            # روابط قصيرة جداً لنوع 3: /s/XXXXXX فقط (6 أحرف)
            alphabet = string.ascii_letters + string.digits
            for _ in range(50):
                short_code = ''.join(secrets.choice(alphabet) for _ in range(6))
                if not subscriptions_coll.find_one({"short_code": short_code}):
                    update_payload["short_code"] = short_code
                    break
            else:
                return jsonify(error='تعذر إنشاء رمز قصير، جرّب مرة أخرى'), 500
        
        update_doc = {"$set": update_payload}
        if role != 'normal3':
            update_doc["$unset"] = {"short_code": ""}
        subscriptions_coll.update_one(
            {"user_id": user_id},
            update_doc,
            upsert=True
        )
        
        if role == 'normal3':
            link = f"{request.host_url.rstrip('/')}/s/{update_payload['short_code']}"
        else:
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

@app.route('/s/<short_code>')
def short_subscribe(short_code):
    """رابط قصير لنوع المستخدم 3: مثال /s/Ab12Xy"""
    try:
        app.permanent_session_lifetime = timedelta(days=30)
        session.permanent = True
        subscription = subscriptions_coll.find_one({
            "short_code": short_code,
            "expires_at": {"$gt": datetime.now(UTC)}
        })
        if not subscription:
            session.clear()
            return render_template('invalid.html')
        user_id = subscription["user_id"]
        role = subscription["role"]
        if role != 'normal3':
            session.clear()
            return render_template('invalid.html')
        session['user_id'] = user_id
        session['user_role'] = role
        session['last_activity'] = datetime.now(UTC).isoformat()
        return render_template('user.html', user_id=user_id, role=role)
    except Exception as e:
        print(f"Error in short_subscribe: {e}")
        session.clear()
        return render_template('error.html', error="حدث خطأ في قراءة البيانات من الخادم")


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

# ----------------------------------
# تخزين مؤقت للرموز والروابط لمنع تكرار البحث وتسريع الاستجابة الفورية
# ----------------------------------
recent_code_cache = {}
CACHE_TTL = 20  # ثانية واحدة كافية لالتقاط النقرات المتكررة فورياً

def get_cached_result(account, req_type):
    key = (account.lower().strip(), req_type)
    if key in recent_code_cache:
        val, ts = recent_code_cache[key]
        if time.time() - ts < CACHE_TTL and val and val != "طلبك غير موجود.":
            return val
    return None

def set_cached_result(account, req_type, result):
    if result and result != "طلبك غير موجود.":
        key = (account.lower().strip(), req_type)
        recent_code_cache[key] = (result, time.time())

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
    account = ""
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

        cached = get_cached_result(account, 'residence_update_link')
        if cached:
            return jsonify(link=cached), 200, {'Content-Type': 'application/json'}
        
        link = fetch_email_with_link(
            account,
            ["تحديث السكن", "household", "primary location"],
            ["نعم، أنا قدمت الطلب", "Yes, this was me", "تحديث السكن", "Update Household", "confirm"]
        )
        if link and link != "طلبك غير موجود.":
            set_cached_result(account, 'residence_update_link', link)
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
    account = ""
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

        cached = get_cached_result(account, 'residence_code')
        if cached:
            return jsonify(code=cached), 200, {'Content-Type': 'application/json'}
        
        code = fetch_email_with_link(
            account,
            ["رمز الوصول المؤقت", "temporary access", "household", "رمز الوصول"],
            ["الحصول على الرمز", "Get Code", "احصل على الرمز", "رمز الوصول"]
        )
        if code and code != "طلبك غير موجود.":
            set_cached_result(account, 'residence_code', code)
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
    account = ""
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

        cached = get_cached_result(account, 'password_reset_link')
        if cached:
            return jsonify(link=cached), 200, {'Content-Type': 'application/json'}
        
        link = fetch_email_with_link(
            account,
            ["إعادة تعيين كلمة المرور", "password reset", "reset your password"],
            ["إعادة تعيين كلمة المرور", "Reset Password"]
        )
        if link and link != "طلبك غير موجود.":
            set_cached_result(account, 'password_reset_link', link)
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
    account = ""
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

        cached = get_cached_result(account, 'login_code')
        if cached:
            return jsonify(code=cached), 200, {'Content-Type': 'application/json'}
        
        code = fetch_email_with_code(
            account,
            ["رمز تسجيل الدخول", "sign-in code", "sign in code", "login code"]
        )
        if code and code != "طلبك غير موجود.":
            set_cached_result(account, 'login_code', code)
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
    account = ""
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

        cached = get_cached_result(account, 'verification_code')
        if cached:
            return jsonify(code=cached), 200, {'Content-Type': 'application/json'}

        code = fetch_email_with_code(
            account,
            ["رمز التحقق", "verification code", "verify your account"],
            code_length=6
        )
        if code and code != "طلبك غير موجود.":
            set_cached_result(account, 'verification_code', code)
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
    account = ""
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

        cached = get_cached_result(account, 'suspended_account_link')
        if cached:
            return jsonify(link=cached), 200, {'Content-Type': 'application/json'}
        
        link = fetch_email_with_link(
            account,
            ["عضويتك في Netflix معلّقة", "معلّقة", "membership on hold", "membership paused"],
            ["إضافة معلومات الدفع", "Update payment", "إعادة تفعيل العضوية", "Restart Membership"]
        )
        if link and link != "طلبك غير موجود.":
            set_cached_result(account, 'suspended_account_link', link)
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
    subscriptions_coll.create_index("short_code", unique=True, sparse=True)

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
    try:
        import threading
        cleanup_thread = threading.Thread(target=schedule_cleanup, daemon=True)
        cleanup_thread.start()
    except Exception as e:
        print(f"Cleanup thread failed: {e}")
    
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
