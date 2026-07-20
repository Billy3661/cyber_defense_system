import os
import secrets
import logging
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, session
from werkzeug.middleware.proxy_fix import ProxyFix
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import database
from helpers import generate_csrf_token, limiter

# Load .env for local development (no-op in production)
load_dotenv()

# ReportLab Imports
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# Initialize database
try:
    database.init_db()
except Exception as e:
    logging.error("Database initialization failed: %s", e)

# ─────────────────────────────────────────────
#  FLASK APP INITIALIZATION
# ─────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
    logging.warning("No SECRET_KEY env var set. Generated a temporary key. Sessions will be invalidated on restart.")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

limiter.init_app(app)

_google_client_id = os.environ.get("GOOGLE_CLIENT_ID")
_google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
google = None
if _google_client_id and _google_client_secret:
    oauth = OAuth(app)
    google = oauth.register(
        name='google',
        client_id=_google_client_id,
        client_secret=_google_client_secret,
        access_token_url='https://oauth2.googleapis.com/token',
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params={'access_type': 'offline'},
        api_base_url='https://www.googleapis.com/oauth2/v1/',
        client_kwargs={'scope': 'email profile'},
    )
    logging.info("Google OAuth initialized successfully.")
else:
    logging.info("Google OAuth not configured \u2014 skipping registration.")

app.config["google_client"] = google

app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Session configuration — OWASP A07: Identification & Authentication Failures
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)  # Absolute session timeout: 12 hours
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_NAME"] = "__Host-session" if not app.debug else "session"
app.config["PREFERRED_URL_SCHEME"] = "https"
if not app.debug:
    app.config["SESSION_COOKIE_SECURE"] = True

# ─────────────────────────────────────────────
#  CONTEXT PROCESSORS & ERROR HANDLERS
# ─────────────────────────────────────────────

@app.context_processor
def inject_globals():
    import os as _os
    css_path = _os.path.join(app.root_path, "static", "css", "style.css")
    js_path = _os.path.join(app.root_path, "static", "js", "main.js")
    css_mtime = int(_os.path.getmtime(css_path)) if _os.path.exists(css_path) else 0
    js_mtime = int(_os.path.getmtime(js_path)) if _os.path.exists(js_path) else 0
    _admin = _os.environ.get("ADMIN_USERNAME", "").strip().lower()
    return dict(
        cache_bust=str(css_mtime + js_mtime),
        google_oauth_enabled=google is not None,
        is_admin=session.get("username", "").lower() == _admin if _admin else False,
    )


# ─────────────────────────────────────────────
#  SECURITY HEADERS — OWASP A05
# ─────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    if not app.debug:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
    return response


@app.errorhandler(429)
def rate_limit_exceeded(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": f"Rate limit exceeded. {e.description}"}), 429
    return render_template("404.html", error="Rate limit exceeded. Please slow down and try again later."), 429


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("404.html"), 500


# ─────────────────────────────────────────────
#  CSRF TOKEN SETUP
# ─────────────────────────────────────────────

app.jinja_env.globals["csrf_token"] = generate_csrf_token

# ─────────────────────────────────────────────
#  REGISTER BLUEPRINTS
# ─────────────────────────────────────────────

from blueprints.main import main_bp
from blueprints.auth import auth_bp
from blueprints.scanner import scanner_bp
from blueprints.simulator import simulator_bp
from blueprints.breach import breach_bp
from blueprints.chat import chat_bp
from blueprints.admin import admin_bp
from blueprints.phone import phone_bp

app.register_blueprint(main_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(scanner_bp)
app.register_blueprint(simulator_bp)
app.register_blueprint(breach_bp)
app.register_blueprint(chat_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(phone_bp)


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, host="0.0.0.0", port=port)
