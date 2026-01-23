from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash, make_response, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime
import re, os, requests, base64, json, validators, csv, random
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
from openai import OpenAI
import markdown
from io import BytesIO, StringIO
from sqlalchemy import text
from youtube_transcript_api import YouTubeTranscriptApi
from collections import Counter
from fpdf import FPDF
from threading import Thread

# ==========================================
# 1. CONFIGURATION - RAILWAY READY
# ==========================================
load_dotenv()

app = Flask(__name__)

# Secret Key
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-me-in-production')

# Database Configuration (Works on Railway + Local)
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///dev.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration (Hostinger SSL)
app.config['MAIL_SERVER'] = 'smtp.hostinger.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('My SEO King Tool Team', os.environ.get('MAIL_USERNAME', 'support@myseokingtool.com'))
app.config['MAIL_DEBUG'] = False

# PayPal Configuration
PAYPAL_EMAIL = os.environ.get('PAYPAL_EMAIL', 'your-paypal@email.com')

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize Mail (with safety check)
try:
    mail = Mail(app)
except Exception as e:
    print(f"⚠️ Mail initialization skipped: {e}")
    mail = None

# OpenAI Client
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
if OPENAI_API_KEY:
    try:
        client = OpenAI(api_key=OPENAI_API_KEY, timeout=30.0, max_retries=2)
        print("✅ OpenAI client initialized")
    except Exception as e:
        print(f"❌ OpenAI initialization failed: {e}")
        client = None
else:
    print("⚠️ OPENAI_API_KEY not set")
    client = None

# Global Tool List
TOOL_LIST = [
    'competitor-analyzer', 'keyword-research', 'sitemap-generator', 
    'robots-generator', 'image-seo', 'social-posts', 'alt-text-generator', 
    'content-outline', 'content-brief', 'lsi-keywords', 'email-subject', 
    'headline-analyzer', 'internal-linking', 'schema-generator', 'readability-checker',
    'faq-schema', 'youtube-script', 'meta-tags', 'plagiarism-checker', 'serp-analysis',
    'youtube-to-blog', 'image-generator', 'site-auditor', 'content-humanizer', 
    'article-wizard', 'bulk-writer', 'gbp-tool', 'geo-optimizer', 'backlink-outreach',
    'social-preview', 'keyword-density'
]

# Piped Mirror Instances
PIPED_INSTANCES = [
    "https://pipedapi.kavin.rocks",
    "https://api.piped.privacy.com.de",
    "https://pipedapi.moomoo.me",
    "https://pipedapi.smnz.de",
    "https://pipedapi.adminforge.de"
]

# ==========================================
# 1.5 ASYNC EMAIL HELPER (PREVENTS 502 ERRORS)
# ==========================================
def send_async_email(app_obj, msg):
    """Background task to send email without blocking requests"""
    with app_obj.app_context():
        try:
            mail.send(msg)
            print(f"✅ Email sent to {msg.recipients}")
        except Exception as e:
            print(f"❌ Email send failed: {e}")

def send_email_background(subject, recipient, body):
    """Send emails in background to prevent timeouts"""
    if not mail or not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        print(f"⚠️ Email not configured - skipping email to {recipient}")
        return
    
    try:
        msg = Message(subject, recipients=[recipient])
        msg.body = body
        app_obj = current_app._get_current_object()
        thr = Thread(target=send_async_email, args=[app_obj, msg])
        thr.start()
        print(f"📧 Email thread started for: {recipient}")
    except Exception as e:
        print(f"❌ Failed to start email thread: {e}")

# ==========================================
# 2. DATABASE MODELS
# ==========================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    tier = db.Column(db.String(20), default='free')
    content_count = db.Column(db.Integer, default=0)
    ai_requests_this_month = db.Column(db.Integer, default=0)
    last_reset_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    contents = db.relationship('Content', backref='author', lazy=True, cascade="all, delete-orphan")
    
    def check_password(self, password): 
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def get_limits(self):
        limits = {'free': 50, 'pro': 500, 'pro king': 500, 'enterprise': 9999}
        return {'ai_requests_per_month': limits.get(self.tier.lower(), 50)}

class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    keyword = db.Column(db.String(100))
    content = db.Column(db.Text, nullable=False)
    html_content = db.Column(db.Text)
    seo_score = db.Column(db.Integer, default=0)
    word_count = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payment_id = db.Column(db.String(100), unique=True, nullable=True)
    payer_email = db.Column(db.String(120))
    amount = db.Column(db.Float, default=0)
    plan = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verified_at = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship('User', backref=db.backref('payments', lazy=True))

@login_manager.user_loader
def load_user(user_id): 
    return User.query.get(int(user_id))

# ==========================================
# 2.5 DATABASE INITIALIZATION ROUTES
# ==========================================

@app.route('/setup-database')
def setup_database():
    """Manual database initialization endpoint"""
    try:
        db.create_all()
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        admin_created = False
        admin_exists = User.query.filter_by(email='admin@myseokingtool.com').first()
        
        if not admin_exists:
            hashed = bcrypt.generate_password_hash('AdminPassword123!').decode('utf-8')
            admin = User(
                username='admin',
                email='admin@myseokingtool.com',
                password_hash=hashed,
                is_admin=True,
                tier='enterprise',
                ai_requests_this_month=0,
                content_count=0,
                is_active=True
            )
            db.session.add(admin)
            db.session.commit()
            admin_created = True
        
        user_count = User.query.count()
        content_count = Content.query.count()
        payment_count = Payment.query.count()
        
        return jsonify({
            'success': True,
            'message': '✅ Database initialized successfully!',
            'tables': tables,
            'admin_user_created': admin_created,
            'stats': {
                'users': user_count,
                'content': content_count,
                'payments': payment_count
            },
            'admin_credentials': {
                'email': 'admin@myseokingtool.com',
                'password': 'AdminPassword123!' if admin_created else '(already exists)'
            }
        }), 200
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"❌ Database setup failed: {error_trace}")
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': error_trace.split('\n')
        }), 500

@app.route('/check-database')
def check_database():
    """Check database status"""
    try:
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        table_info = {}
        try:
            table_info['user'] = {'exists': 'user' in tables, 'count': User.query.count() if 'user' in tables else 0}
        except:
            table_info['user'] = {'exists': False, 'count': 0}
        
        try:
            table_info['content'] = {'exists': 'content' in tables, 'count': Content.query.count() if 'content' in tables else 0}
        except:
            table_info['content'] = {'exists': False, 'count': 0}
        
        try:
            table_info['payment'] = {'exists': 'payment' in tables, 'count': Payment.query.count() if 'payment' in tables else 0}
        except:
            table_info['payment'] = {'exists': False, 'count': 0}
        
        admin_exists = False
        if 'user' in tables:
            try:
                admin_exists = User.query.filter_by(email='admin@myseokingtool.com').first() is not None
            except:
                pass
        
        return jsonify({
            'success': True,
            'database_url_set': bool(os.environ.get('DATABASE_URL')),
            'tables_found': tables,
            'table_details': table_info,
            'admin_user_exists': admin_exists,
            'ready': len(tables) >= 3 and admin_exists
        }), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ==========================================
# 3. FAVICON ROUTES (FOR SEO)
# ==========================================
@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='favicon.ico'))

@app.route('/apple-touch-icon.png')
def apple_touch_icon():
    return redirect(url_for('static', filename='apple-touch-icon.png'))

@app.route('/favicon-32x32.png')
def favicon_32():
    return redirect(url_for('static', filename='favicon-32x32.png'))

@app.route('/favicon-16x16.png')
def favicon_16():
    return redirect(url_for('static', filename='favicon-16x16.png'))

@app.route('/site.webmanifest')
def webmanifest():
    manifest = {
        "name": "My SEO King Tool",
        "short_name": "MySEOKingTool",
        "icons": [
            {"src": "/static/android-chrome-192x192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/android-chrome-512x512.png", "sizes": "512x512", "type": "image/png"}
        ],
        "theme_color": "#4f46e5",
        "background_color": "#ffffff",
        "display": "standalone"
    }
    return jsonify(manifest)

# ==========================================
# 4. PAGE ROUTES
# ==========================================
@app.route('/')
def landing(): 
    if current_user.is_authenticated: 
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

app.add_url_rule('/', endpoint='home', view_func=landing)

@app.route('/dashboard')
@login_required
def dashboard():
    recent = Content.query.filter_by(user_id=current_user.id).order_by(Content.updated_at.desc()).limit(5).all()
    total = Content.query.filter_by(user_id=current_user.id).count()
    words = db.session.query(db.func.sum(Content.word_count)).filter_by(user_id=current_user.id).scalar() or 0
    
    avg_score = 0
    scores = [c.seo_score for c in Content.query.filter_by(user_id=current_user.id).all()]
    if scores: 
        avg_score = sum(scores) / len(scores)

    return render_template('index.html', recent_content=recent, total_content=total, 
                         total_words=words, avg_score=round(avg_score, 1), 
                         limits=current_user.get_limits())

@app.route('/editor')
@login_required
def editor():
    c = Content.query.filter_by(id=request.args.get('id'), user_id=current_user.id).first() if request.args.get('id') else None
    return render_template('editor.html', content=c)

app.add_url_rule('/editor', endpoint='content_generator', view_func=editor)

@app.route('/content-library')
@login_required
def content_library():
    contents = Content.query.filter_by(user_id=current_user.id).order_by(Content.updated_at.desc()).all()
    return render_template('content_library.html', contents=contents)

@app.route('/pricing')
def pricing(): 
    return render_template('pricing.html')

@app.route('/profile')
@login_required
def profile(): 
    return render_template('profile.html')

@app.route('/article-wizard')
@login_required
def article_wizard_page(): 
    return render_template('article_wizard.html')

@app.route('/alt-text-generator')
@login_required
def alt_text_generator_page(): 
    return render_template('alt_text_generator.html')

@app.route('/bulk-writer')
@login_required
def bulk_writer_page():
    if current_user.tier == 'free':
        flash("Bulk Writing is a Pro Feature!", "warning")
        return redirect('/pricing')
    return render_template('bulk_writer.html')

@app.route('/sitemap-generator')
@login_required
def sitemap_generator_page():
    return render_template('sitemap_generator.html')

@app.route('/robots-generator')
@login_required
def robots_generator_page():
    return render_template('robots_generator.html')

# ==========================================
# PASSWORD CHANGE ROUTE
# ==========================================
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            current_password = data.get('current_password')
            new_password = data.get('new_password')
            confirm_password = data.get('confirm_password')
            
            if not current_password or not new_password or not confirm_password:
                return jsonify({'error': 'All fields are required'}), 400
            
            if not current_user.check_password(current_password):
                return jsonify({'error': 'Current password is incorrect'}), 401
            
            if new_password != confirm_password:
                return jsonify({'error': 'New passwords do not match'}), 400
            
            if len(new_password) < 8:
                return jsonify({'error': 'Password must be at least 8 characters'}), 400
            
            current_user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Password changed successfully!'})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return render_template('change_password.html')

# ==========================================
# TECHNICAL SEO ROUTES
# ==========================================
@app.route('/robots.txt')
def robots_txt():
    lines = [
        "User-agent: *", 
        "Disallow: /dashboard", 
        "Disallow: /editor", 
        "Disallow: /admin", 
        "Disallow: /profile", 
        f"Sitemap: {request.url_root}sitemap.xml"
    ]
    return "\n".join(lines), 200, {'Content-Type': 'text/plain'}

@app.route('/robots.txt')
def robots_txt():
    lines = [
        "User-agent: *", 
        "Disallow: /dashboard", 
        "Disallow: /editor", 
        "Disallow: /admin", 
        "Disallow: /profile", 
        f"Sitemap: {request.url_root}sitemap.xml"
    ]
    return "\n".join(lines), 200, {'Content-Type': 'text/plain'}

@app.route('/sitemap.xml')
def sitemap_xml():
    base_url = request.url_root.rstrip('/')
    pages = ['/', '/pricing', '/login', '/signup']
    for slug in TOOL_LIST:
        pages.append(f'/tool/{slug}')

    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for page in pages:
        xml += f'  <url>\n    <loc>{base_url}{page}</loc>\n    <changefreq>weekly</changefreq>\n  </url>\n'
    xml += '</urlset>'
    return xml, 200, {'Content-Type': 'application/xml'}

# ==========================================
# 5. AUTH ROUTES
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        user = User.query.filter_by(email=data.get('email').lower()).first()
        if user and user.check_password(data.get('password')):
            if not user.is_active: 
                return jsonify({'error': 'Account banned'}), 403
            login_user(user)
            return jsonify({'success': True, 'redirect': '/dashboard'})
        return jsonify({'error': 'Invalid credentials'}), 401
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated: 
        return redirect('/dashboard')
    
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            email = data.get('email', '').strip().lower()
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            
            if not email or not username or not password:
                return jsonify({'error': 'All fields are required'}), 400
            
            if len(password) < 6:
                return jsonify({'error': 'Password must be at least 6 characters'}), 400
            
            if User.query.filter_by(email=email).first(): 
                return jsonify({'error': 'Email already exists'}), 400
            
            if User.query.filter_by(username=username).first():
                return jsonify({'error': 'Username already taken'}), 400
            
            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(
                username=username, 
                email=email, 
                password_hash=hashed,
                tier='free'
            )
            
            if User.query.count() == 0: 
                user.is_admin = True
                user.tier = 'enterprise'
            
            db.session.add(user)
            db.session.commit()
            login_user(user)
            
            try:
                welcome_body = f"""Hi {user.username},

Welcome to My SEO King Tool! 🎉

Your account has been created successfully.

Get started now: {request.url_root}dashboard

Best regards,
My SEO King Tool Team
"""
                send_email_background("Welcome to My SEO King Tool! 🎉", user.email, welcome_body)
                print(f"✅ Welcome email queued for: {user.email}")
            except Exception as email_error:
                print(f"⚠️ Welcome email failed (non-critical): {email_error}")
            
            return jsonify({'success': True, 'redirect': '/dashboard'})
            
        except Exception as e: 
            db.session.rollback()
            print(f"❌ Signup error: {str(e)}")
            return jsonify({'error': f'Signup failed: {str(e)}'}), 500
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout(): 
    logout_user()
    return redirect('/')

# ==========================================
# 6. ADMIN & PAYMENT ROUTES
# ==========================================
@app.route('/admin')
@login_required
def admin():
    if not getattr(current_user, 'is_admin', False): 
        return redirect('/dashboard')
    users = User.query.order_by(User.id.desc()).all()
    pending_payments = Payment.query.filter_by(status='pending').order_by(Payment.created_at.desc()).all()
    return render_template('admin.html', users=users, total_content=Content.query.count(), pending_payments=pending_payments)

@app.route('/admin/export-users')
@login_required
def admin_export_users():
    if not getattr(current_user, 'is_admin', False): 
        return "Unauthorized", 403
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Username', 'Email', 'Tier'])
    for u in User.query.all(): 
        cw.writerow([u.id, u.username, u.email, u.tier])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=users.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def admin_toggle_user(user_id):
    if not getattr(current_user, 'is_admin', False): 
        return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id != current_user.id:
        user.is_active = not user.is_active
        db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not getattr(current_user, 'is_admin', False): 
        return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id != current_user.id:
        db.session.delete(user)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/user/<int:user_id>/upgrade', methods=['POST'])
@login_required
def admin_upgrade_user(user_id):
    if not getattr(current_user, 'is_admin', False): 
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    user = User.query.get_or_404(user_id)
    user.tier = data.get('tier')
    db.session.commit()
    return jsonify({'success': True})

@app.route('/payment/success/<plan_name>')
@login_required
def payment_success(plan_name):
    if plan_name == 'pro': 
        current_user.tier = 'pro king'
    elif plan_name == 'enterprise': 
        current_user.tier = 'enterprise'
    db.session.commit()
    return redirect('/dashboard')

@app.route('/api/verify-payment', methods=['POST'])
@login_required
def api_verify_payment():
    try:
        data = request.get_json()
        transaction_id = data.get('transaction_id', '').strip().upper()
        email = data.get('email', '').strip().lower()
        
        if not transaction_id:
            return jsonify({'success': False, 'error': 'Transaction ID is required'}), 400
        
        if len(transaction_id) < 10:
            return jsonify({'success': False, 'error': 'Invalid Transaction ID format'}), 400
        
        existing = Payment.query.filter_by(payment_id=transaction_id).first()
        if existing:
            if existing.status == 'completed':
                return jsonify({'success': False, 'already_exists': True, 'message': 'This transaction has already been verified.'}), 400
            elif existing.status == 'pending':
                return jsonify({'success': False, 'already_exists': True, 'message': 'This transaction is already pending verification.'}), 400
        
        pending_payment = Payment.query.filter_by(user_id=current_user.id, status='pending', payment_id=None).order_by(Payment.created_at.desc()).first()
        
        if pending_payment:
            pending_payment.payment_id = transaction_id
            pending_payment.payer_email = email
            pending_payment.notes = f'Manual submission - awaiting verification. Submitted: {datetime.utcnow()}'
        else:
            pending_payment = Payment(
                user_id=current_user.id,
                payment_id=transaction_id,
                payer_email=email,
                amount=0,
                plan='pending_verification',
                status='pending',
                notes=f'Manual submission - awaiting verification. Submitted: {datetime.utcnow()}'
            )
            db.session.add(pending_payment)
        
        db.session.commit()
        
        admin_body = f"""🔔 New Payment Verification Request

User: {current_user.username} ({current_user.email})
Transaction ID: {transaction_id}
Payer Email: {email}

Please verify in PayPal and approve/reject in admin panel:
{url_for('admin', _external=True)}
"""
        send_email_background("🔔 Payment Verification Request", PAYPAL_EMAIL, admin_body)
        
        return jsonify({'success': True, 'message': 'Transaction submitted successfully! We will verify and upgrade your account within 24 hours.'})
        
    except Exception as e:
        print(f"Payment verification error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred. Please try again.'}), 500

@app.route('/admin/payment/<int:payment_id>/approve', methods=['POST'])
@login_required
def admin_approve_payment(payment_id):
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        payment = Payment.query.get_or_404(payment_id)
        
        if payment.status != 'pending':
            return jsonify({'error': 'Payment is not pending'}), 400
        
        payment.status = 'completed'
        payment.verified_at = datetime.utcnow()
        payment.amount = data.get('amount', 0)
        payment.plan = data.get('plan', 'pro king')
        payment.notes = f"{payment.notes}\nApproved by admin on {datetime.utcnow()}"
        
        user = User.query.get(payment.user_id)
        if user:
            user.tier = data.get('plan', 'pro king')
            user_body = f"""🎉 Payment Verified - Account Upgraded!

Hi {user.username},

Your payment has been verified and your account has been upgraded to {user.tier.upper()}.

Transaction ID: {payment.payment_id}

Best regards,
My SEO King Tool Team
"""
            send_email_background("🎉 Payment Verified - Account Upgraded!", user.email, user_body)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Payment approved and user upgraded!'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/payment/<int:payment_id>/reject', methods=['POST'])
@login_required
def admin_reject_payment(payment_id):
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        payment = Payment.query.get_or_404(payment_id)
        
        if payment.status != 'pending':
            return jsonify({'error': 'Payment is not pending'}), 400
        
        reason = data.get('reason', 'Transaction could not be verified')
        payment.status = 'rejected'
        payment.notes = f"{payment.notes}\nRejected by admin on {datetime.utcnow()}. Reason: {reason}"
        
        user = User.query.get(payment.user_id)
        if user:
            user_body = f"""⚠️ Payment Verification Issue

Hi {user.username},

We were unable to verify your payment submission.

Transaction ID: {payment.payment_id}
Reason: {reason}

If you believe this is an error, please contact support.

Best regards,
My SEO King Tool Team
"""
            send_email_background("⚠️ Payment Verification Issue", user.email, user_body)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Payment rejected and user notified.'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/pending-payments', methods=['GET'])
@login_required
def api_get_pending_payments():
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        payments = Payment.query.filter_by(status='pending').order_by(Payment.created_at.desc()).all()
        result = []
        for p in payments:
            user = User.query.get(p.user_id)
            result.append({
                'id': p.id,
                'transaction_id': p.payment_id,
                'payer_email': p.payer_email,
                'user_id': p.user_id,
                'username': user.username if user else 'Unknown',
                'user_email': user.email if user else 'Unknown',
                'submitted_at': p.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'notes': p.notes
            })
        return jsonify({'success': True, 'payments': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==========================================
# 7. TOOL ROUTER
# ==========================================
@app.route('/tool/<tool_name>')
@login_required
def tool_view(tool_name):
    if tool_name == 'image-generator' and current_user.tier == 'free':
        flash("Pro Feature!", "warning")
        return redirect('/pricing')
    
    if tool_name == 'article-wizard': 
        return redirect('/article-wizard')
    if tool_name == 'alt-text-generator': 
        return redirect('/alt-text-generator')
    if tool_name == 'bulk-writer': 
        return redirect('/bulk-writer')
    if tool_name == 'sitemap-generator': 
        return redirect('/sitemap-generator')
    if tool_name == 'robots-generator': 
        return redirect('/robots-generator')
    
    try:
        return render_template(f'{tool_name.replace("-", "_")}.html')
    except:
        return "Tool not found", 404

for t in TOOL_LIST:
    if t not in ['article-wizard', 'alt-text-generator', 'bulk-writer', 'sitemap-generator', 'robots-generator']:
        app.add_url_rule(f'/{t}', endpoint=t, view_func=lambda t=t: tool_view(t))
    if '-' in t: 
        app.add_url_rule(f'/{t}', endpoint=t.replace('-', '_'), view_func=lambda t=t: tool_view(t))

# ==========================================
# 8. API ENDPOINTS
# ==========================================

@app.route('/api/save-content', methods=['POST'])
@login_required
def api_save_content():
    d = request.get_json()
    if d.get('id'):
        c = Content.query.get(d.get('id'))
        if c and c.user_id == current_user.id:
            c.title = d.get('title')
            c.content = d.get('content')
            c.html_content = d.get('html_content')
            c.keyword = d.get('keyword')
            c.word_count = len(d.get('content','').split())
            db.session.commit()
            return jsonify({'success': True, 'id': c.id})
    new_c = Content(
        user_id=current_user.id, 
        title=d.get('title'), 
        content=d.get('content'), 
        html_content=d.get('html_content'), 
        keyword=d.get('keyword'), 
        word_count=len(d.get('content','').split())
    )
    db.session.add(new_c)
    current_user.content_count += 1
    db.session.commit()
    return jsonify({'success': True, 'id': new_c.id})

@app.route('/api/delete-content/<int:id>', methods=['POST'])
@login_required
def api_delete(id):
    c = Content.query.get_or_404(id)
    if c.user_id == current_user.id: 
        db.session.delete(c)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/api/research-keywords', methods=['POST'])
@login_required
def api_research_keywords():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Monthly limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        data = request.get_json()
        seed = data.get('seed', '').strip()
        
        if not seed:
            return jsonify({'error': 'Seed keyword required'}), 400
        
        prompt = f"""Generate 15 long-tail keywords for: "{seed}"

Return ONLY valid JSON array:
[
  {{"keyword": "example keyword", "intent": "Informational", "difficulty": 45, "content_idea": "Blog Title"}}
]

Use intent: Informational, Commercial, or Transactional
Difficulty: 1-100
No markdown, just JSON."""
        
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Return only JSON arrays"},
                {"role": "user", "content": prompt}
            ],
            timeout=30
        )
        
        raw = res.choices[0].message.content.replace('```json', '').replace('```', '').strip()
        keywords_data = json.loads(raw)
        
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        return jsonify({'success': True, 'keywords': keywords_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-content', methods=['POST'])
@login_required
def api_generate_content():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        keyword = request.get_json().get('keyword')
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "SEO Writer"}, {"role": "user", "content": f"Write SEO blog about: {keyword}"}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        content = res.choices[0].message.content
        return jsonify({'success': True, 'content': content, 'html_content': markdown.markdown(content)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/article-wizard', methods=['POST'])
@login_required
def api_article_wizard():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        topic = request.get_json().get('topic')
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "Blog Writer"}, {"role": "user", "content": f"Write comprehensive blog about: {topic}"}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        content = res.choices[0].message.content
        return jsonify({'success': True, 'content': content, 'html': markdown.markdown(content)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/bulk-write-single', methods=['POST'])
@login_required
def api_bulk_write_single():
    if current_user.tier == 'free':
        return jsonify({'error': 'Pro feature'}), 403
    
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()
        tone = data.get('tone', 'Professional')
        word_count = data.get('word_count', 800)
        
        prompt = f"""Write SEO blog post about: "{keyword}"
Tone: {tone}
Word count: ~{word_count}
Use markdown formatting with H2/H3 headings."""
        
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "SEO Writer"}, {"role": "user", "content": prompt}],
            max_tokens=2000
        )
        
        content = res.choices[0].message.content
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        return jsonify({
            'success': True,
            'keyword': keyword,
            'content': content,
            'html': markdown.markdown(content),
            'word_count': len(content.split())
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-sitemap', methods=['POST'])
@login_required
def api_generate_sitemap():
    try:
        data = request.get_json()
        base_url = data.get('url', '').rstrip('/')
        
        if not base_url.startswith('http'):
            base_url = 'https://' + base_url
        
        urls = data.get('urls', [])
        changefreq = data.get('changefreq', 'weekly')
        priority = data.get('priority', '0.8')
        
        if not urls:
            urls = [base_url]
        
        today = datetime.now().strftime('%Y-%m-%d')
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
        
        for url in urls:
            if url.strip():
                xml_lines.append('  <url>')
                xml_lines.append(f'    <loc>{url.strip()}</loc>')
                xml_lines.append(f'    <lastmod>{today}</lastmod>')
                xml_lines.append(f'    <changefreq>{changefreq}</changefreq>')
                xml_lines.append(f'    <priority>{priority}</priority>')
                xml_lines.append('  </url>')
        
        xml_lines.append('</urlset>')
        return jsonify({'success': True, 'sitemap': '\n'.join(xml_lines), 'url_count': len(urls)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-robots', methods=['POST'])
@login_required
def api_generate_robots():
    try:
        data = request.get_json()
        base_url = data.get('url', '').rstrip('/')
        if not base_url.startswith('http'):
            base_url = 'https://' + base_url
        
        disallow = data.get('disallow', ['/admin', '/dashboard'])
        sitemap = data.get('sitemap', f'{base_url}/sitemap.xml')
        
        lines = ['User-agent: *']
        for path in disallow:
            if path.strip():
                lines.append(f'Disallow: {path.strip()}')
        lines.append(f'Sitemap: {sitemap}')
        
        return jsonify({'success': True, 'robots': '\n'.join(lines)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/public-audit', methods=['POST'])
def api_public_audit():
    try:
        url = request.get_json().get('url')
        if not url.startswith('http'):
            url = 'https://' + url
        
        r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        soup = BeautifulSoup(r.content, 'html.parser')
        
        score = 100
        issues = []
        
        if not soup.title:
            score -= 20
            issues.append("Missing Title")
        if not soup.find('meta', attrs={'name': 'description'}):
            score -= 20
            issues.append("Missing Meta Description")
        if not soup.find('h1'):
            score -= 20
            issues.append("Missing H1")
        
        return jsonify({'success': True, 'score': max(0, score), 'issues': issues})
    except:
        return jsonify({'success': True, 'score': 45, 'issues': ['Connection timeout']})

@app.route('/api/audit-site', methods=['POST'])
@login_required
def api_audit_site():
    try:
        url = request.get_json().get('url')
        if not url.startswith('http'):
            url = 'https://' + url
        
        r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15)
        soup = BeautifulSoup(r.content, 'html.parser')
        
        score = 100
        issues = []
        passed = []
        
        if soup.title:
            passed.append("Title exists")
        else:
            score -= 20
            issues.append({"type": "critical", "msg": "Missing Title"})
        
        if soup.find('meta', attrs={'name': 'description'}):
            passed.append("Meta description found")
        else:
            score -= 20
            issues.append({"type": "critical", "msg": "Missing Meta Description"})
        
        if soup.find('h1'):
            passed.append("H1 found")
        else:
            score -= 20
            issues.append({"type": "critical", "msg": "Missing H1"})
        
        return jsonify({
            'success': True,
            'score': max(0, score),
            'meta': {
                'url': url,
                'title': soup.title.string if soup.title else "None",
                'word_count': len(soup.get_text().split())
            },
            'issues': issues,
            'passed': passed
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/youtube-to-blog', methods=['POST'])
@login_required
def api_youtube_to_blog():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        video_url = request.get_json().get('url')
        vid = video_url.split("v=")[1].split("&")[0] if "v=" in video_url else video_url.split("youtu.be/")[1].split("?")[0]
        
        transcript_list = YouTubeTranscriptApi.get_transcript(vid)
        full_text = " ".join([t['text'] for t in transcript_list])
        
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "Convert transcripts to blogs"}, {"role": "user", "content": f"Convert to blog:\n\n{full_text[:10000]}"}]
        )
        
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        content = res.choices[0].message.content
        return jsonify({'success': True, 'content': content, 'html': markdown.markdown(content)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/humanize-text', methods=['POST'])
@login_required
def api_humanize_text():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        text = request.get_json().get('content')
        res = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": "Humanize AI text"}, {"role": "user", "content": f"Humanize:\n{text}"}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-image', methods=['POST'])
@login_required
def api_generate_image():
    if current_user.tier == 'free':
        return jsonify({'error': 'Pro feature'}), 403
    
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        prompt = request.get_json().get('prompt')
        res = client.images.generate(model="dall-e-3", prompt=prompt, size="1024x1024", n=1)
        current_user.ai_requests_this_month += 5
        db.session.commit()
        return jsonify({'success': True, 'image_url': res.data[0].url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-readability', methods=['POST'])
@login_required
def api_readability():
    try:
        text = request.get_json().get('content', '')
        words = text.split()
        sentences = text.replace('!', '.').replace('?', '.').split('.')
        
        total_words = len(words)
        total_sentences = max(len([s for s in sentences if s.strip()]), 1)
        
        score = 206.835 - (1.015 * (total_words / total_sentences))
        score = max(0, min(100, score))
        
        if score >= 80:
            grade = "6th Grade"
            difficulty = "Easy"
        elif score >= 60:
            grade = "8th Grade"
            difficulty = "Standard"
        else:
            grade = "College"
            difficulty = "Difficult"
        
        return jsonify({
            'success': True,
            'stats': {
                'score': round(score, 1),
                'grade': grade,
                'difficulty': difficulty,
                'words': total_words,
                'sentences': total_sentences,
                'reading_time': f"{max(1, round(total_words / 200))} min"
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-schema', methods=['POST'])
@login_required
def api_schema():
    try:
        data = request.get_json()
        schema_type = data.get('type')
        result = {}
        
        if schema_type == 'faq':
            result = {
                "@context": "https://schema.org",
                "@type": "FAQPage",
                "mainEntity": []
            }
            for qa in data.get('questions', []):
                if qa.get('q') and qa.get('a'):
                    result["mainEntity"].append({
                        "@type": "Question",
                        "name": qa['q'],
                        "acceptedAnswer": {"@type": "Answer", "text": qa['a']}
                    })
        elif schema_type == 'article':
            result = {
                "@context": "https://schema.org",
                "@type": "Article",
                "headline": data.get('headline', ''),
                "author": {"@type": "Person", "name": data.get('author', '')}
            }
        
        return jsonify({'success': True, 'json': json.dumps(result, indent=4)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/publish-wordpress', methods=['POST'])
@login_required
def api_publish_wordpress():
    try:
        d = request.get_json()
        wp = d.get('url').rstrip('/')
        creds = f"{d.get('username')}:{d.get('password')}"
        token = base64.b64encode(creds.encode()).decode('utf-8')
        
        r = requests.post(
            f"{wp}/wp-json/wp/v2/posts",
            headers={'Authorization': f'Basic {token}', 'Content-Type': 'application/json'},
            json={'title': d.get('title'), 'content': d.get('content'), 'status': 'draft'}
        )
        return jsonify({'success': True, 'link': r.json().get('link')})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==========================================
# RAILWAY PRODUCTION START
# ==========================================

def init_db():
    """Initialize database tables and create default admin"""
    try:
        with app.app_context():
            db.create_all()
            print("✅ Database tables created/verified")
            
            if User.query.count() == 0:
                hashed = bcrypt.generate_password_hash('AdminPassword123!').decode('utf-8')
                admin = User(
                    username='admin',
                    email='admin@myseokingtool.com',
                    password_hash=hashed,
                    is_admin=True,
                    tier='enterprise'
                )
                db.session.add(admin)
                db.session.commit()
                print("✅ Default admin user created: admin@myseokingtool.com / AdminPassword123!")
    except Exception as e:
        print(f"⚠️ Database initialization error: {e}")

init_db()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
