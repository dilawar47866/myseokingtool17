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
    """
    Manual database initialization endpoint
    Visit: https://your-app.railway.app/setup-database
    """
    try:
        # Create all tables
        db.create_all()
        
        # Get list of created tables
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Create default admin user
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
        
        # Count existing data
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
    """
    Check database status without making changes
    Visit: https://your-app.railway.app/check-database
    """
    try:
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Try to query each table
        table_info = {}
        
        try:
            table_info['user'] = {
                'exists': 'user' in tables,
                'count': User.query.count() if 'user' in tables else 0
            }
        except:
            table_info['user'] = {'exists': False, 'count': 0}
        
        try:
            table_info['content'] = {
                'exists': 'content' in tables,
                'count': Content.query.count() if 'content' in tables else 0
            }
        except:
            table_info['content'] = {'exists': False, 'count': 0}
        
        try:
            table_info['payment'] = {
                'exists': 'payment' in tables,
                'count': Payment.query.count() if 'payment' in tables else 0
            }
        except:
            table_info['payment'] = {'exists': False, 'count': 0}
        
        # Check if admin exists
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
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

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

# Dedicated Tool Pages
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

# Technical SEO Routes
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
            
            # Validation
            if not email or not username or not password:
                return jsonify({'error': 'All fields are required'}), 400
            
            if len(password) < 6:
                return jsonify({'error': 'Password must be at least 6 characters'}), 400
            
            # Check if email already exists
            if User.query.filter_by(email=email).first(): 
                return jsonify({'error': 'Email already exists'}), 400
            
            # Check if username already exists
            if User.query.filter_by(username=username).first():
                return jsonify({'error': 'Username already taken'}), 400
            
            # Create new user
            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(
                username=username, 
                email=email, 
                password_hash=hashed,
                tier='free'
            )
            
            # First user becomes admin
            if User.query.count() == 0: 
                user.is_admin = True
                user.tier = 'enterprise'
            
            db.session.add(user)
            db.session.commit()
            
            # Log the user in
            login_user(user)
            
            # Send welcome email (async - won't block signup)
            try:
                welcome_body = f"""Hi {user.username},

Welcome to My SEO King Tool! 🎉

Your account has been created successfully.

Here's what you can do now:
✅ Generate SEO-optimized content with AI
✅ Use 30+ powerful SEO tools
✅ Create unlimited content pieces
✅ Track your SEO performance

Get started now: {request.url_root}dashboard

Need help? Reply to this email anytime.

Best regards,
My SEO King Tool Team
"""
                send_email_background(
                    subject="Welcome to My SEO King Tool! 🎉", 
                    recipient=user.email, 
                    body=welcome_body
                )
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

# Payment Verification API
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
                return jsonify({
                    'success': False, 
                    'already_exists': True,
                    'message': 'This transaction has already been verified.'
                }), 400
            elif existing.status == 'pending':
                return jsonify({
                    'success': False,
                    'already_exists': True,
                    'message': 'This transaction is already pending verification.'
                }), 400
        
        pending_payment = Payment.query.filter_by(
            user_id=current_user.id,
            status='pending',
            payment_id=None
        ).order_by(Payment.created_at.desc()).first()
        
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

User Details:
- Username: {current_user.username}
- Email: {current_user.email}
- User ID: {current_user.id}

Payment Details:
- Transaction ID: {transaction_id}
- Payer Email: {email}
- Submitted At: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

Please verify this transaction in PayPal and approve/reject in admin panel:
{url_for('admin', _external=True)}
"""
        send_email_background("🔔 Payment Verification Request", PAYPAL_EMAIL, admin_body)
        
        return jsonify({
            'success': True,
            'message': 'Transaction submitted successfully! We will verify and upgrade your account within 24 hours.'
        })
        
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

Great news! Your payment has been verified and your account has been upgraded to {user.tier.upper()}.

Transaction ID: {payment.payment_id}
Plan: {user.tier.upper()}

You now have access to all premium features. Enjoy!

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

If you believe this is an error, please contact support with your PayPal receipt.

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
# 8. API ENDPOINTS (SAMPLE - Add rest from your original file)
# ==========================================

# I'm including just a few critical APIs here. 
# Add the rest of your API routes from your original file after this section.

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

# ==========================================
# ADD THE REST OF YOUR API ROUTES HERE
# Copy all your /api/* routes from your original file
# (I'm skipping them here to keep this response manageable)
# ==========================================

# ==========================================
# RAILWAY PRODUCTION START (FLASK 3.0 COMPATIBLE)
# ==========================================

def init_db():
    """Initialize database tables and create default admin"""
    try:
        with app.app_context():
            db.create_all()
            print("✅ Database tables created/verified")
            
            # Create default admin user (only if no users exist)
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

# Initialize database when app starts
init_db()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
