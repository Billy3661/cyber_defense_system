import os
import re
import secrets
import logging
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import database
from helpers import login_required, validate_csrf, generate_csrf_token, limiter

auth_bp = Blueprint("auth", __name__)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    if request.method == "POST":
        if not validate_csrf():
            flash("Session expired. Please try again.", "error")
            return redirect(url_for("auth.register"))

        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not username or not password or not confirm_password:
            flash("All fields are required.", "error")
            return redirect(url_for("auth.register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("auth.register"))
            
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return redirect(url_for("auth.register"))

        if not re.search(r"[A-Z]", password):
            flash("Password must contain at least one uppercase letter.", "error")
            return redirect(url_for("auth.register"))
        if not re.search(r"[a-z]", password):
            flash("Password must contain at least one lowercase letter.", "error")
            return redirect(url_for("auth.register"))
        if not re.search(r"\d", password):
            flash("Password must contain at least one digit.", "error")
            return redirect(url_for("auth.register"))

        password_hash = generate_password_hash(password)
        if database.create_user(username, password_hash):
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("auth.login"))
        else:
            flash("Username already exists.", "error")
            return redirect(url_for("auth.register"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        if not validate_csrf():
            flash("Session expired. Please try again.", "error")
            return redirect(url_for("auth.login"))

        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("auth.login"))

        # Account lockout — OWASP A07
        lockout_until = session.get("lockout_until")
        if lockout_until:
            try:
                lockout_dt = datetime.fromisoformat(lockout_until)
                if datetime.utcnow() < lockout_dt:
                    remaining = (lockout_dt - datetime.utcnow()).seconds // 60 + 1
                    flash(f"Account locked. Try again in {remaining} minute(s).", "error")
                    return redirect(url_for("auth.login"))
                else:
                    session.pop("lockout_until", None)
                    session.pop("failed_attempts", None)
            except (ValueError, TypeError):
                session.pop("lockout_until", None)
                session.pop("failed_attempts", None)

        user = database.get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            # Session fixation prevention — regenerate session
            session.clear()
            session.regenerate() if hasattr(session, 'regenerate') else None
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["profile_image"] = user["profile_image"] if user["profile_image"] else ""
            session["logged_in_at"] = datetime.utcnow().isoformat()
            saved_key = database.get_user_vt_key(user["username"])
            if saved_key:
                session["vt_api_key"] = saved_key

            flash(f"Welcome back, {username}! You are now securely logged in.", "success")
            return redirect(url_for("main.index"))
        else:
            # Track failed attempts
            failed = session.get("failed_attempts", 0) + 1
            session["failed_attempts"] = failed
            if failed >= MAX_LOGIN_ATTEMPTS:
                session["lockout_until"] = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                session["failed_attempts"] = 0
                logging.warning("Account locked after %d failed attempts: %s", MAX_LOGIN_ATTEMPTS, username)
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.", "error")
            else:
                remaining = MAX_LOGIN_ATTEMPTS - failed
                flash(f"Invalid username or password. {remaining} attempt(s) remaining.", "error")
            return redirect(url_for("auth.login"))

    return render_template("login.html", login_failed=False)


@auth_bp.route('/login/google')
def login_google():
    from flask import current_app
    google = current_app.config.get("google_client")
    if google is None:
        flash("Google sign-in is not configured.", "error")
        return redirect(url_for('auth.login'))
    redirect_uri = url_for('auth.authorize_google', _external=True, _scheme='https')
    return google.authorize_redirect(redirect_uri)


@auth_bp.route('/authorize/google')
def authorize_google():
    from flask import current_app
    google = current_app.config.get("google_client")
    if google is None:
        flash("Google sign-in is not configured.", "error")
        return redirect(url_for('auth.login'))
    try:
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        user_info = resp.json()
    except Exception as e:
        logging.exception("Google OAuth callback failed")
        flash("Google sign-in failed. Please try again.", "error")
        return redirect(url_for("auth.login"))

    email = user_info.get('email', '').strip().lower()
    if not email:
        flash("Could not retrieve email from Google.", "error")
        return redirect(url_for("auth.login"))
    
    try:
        user = database.get_user_by_username(email)
        
        is_new_user = False
        if not user:
            oauth_marker = generate_password_hash(secrets.token_hex(32))
            created = database.create_user(email, oauth_marker)
            if not created:
                logging.error("Failed to create user via Google OAuth: %s", email)
                flash("Account creation failed.", "error")
                return redirect(url_for("auth.login"))
            user = database.get_user_by_username(email)
            if not user:
                logging.error("User not found after create: %s", email)
                flash("Account creation failed.", "error")
                return redirect(url_for("auth.login"))
            is_new_user = True
            flash("Your Google account has been registered successfully!", "success")
        else:
            flash(f"Welcome back, {email}! You are now securely logged in.", "success")
    except Exception as e:
        logging.exception("Database error during Google OAuth")
        flash("An error occurred during sign-in.", "error")
        return redirect(url_for("auth.login"))
    
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["profile_image"] = user["profile_image"] if user["profile_image"] else ""
    
    saved_key = database.get_user_vt_key(user["username"])
    if saved_key:
        session["vt_api_key"] = saved_key
    
    logging.info("Login notification: user %s (%s) signed in via Google OAuth at %s",
                 email, "new" if is_new_user else "existing",
                 datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))
    return redirect(url_for('main.index'))


@auth_bp.route("/edit-profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        if not validate_csrf():
            flash("Session expired. Please try again.", "error")
            return redirect(url_for("auth.edit_profile"))

        new_username = request.form.get("username")
        new_password = request.form.get("password")
        current_password = request.form.get("current_password", "")
        profile_img = request.files.get("profile_image")
        
        user_id = session.get("user_id")
        image_filename = None
        if profile_img and profile_img.filename:
            if profile_img.content_length and profile_img.content_length > 5 * 1024 * 1024:
                flash("Profile image must be under 5 MB.", "error")
                return redirect(url_for("auth.edit_profile"))

            ext = profile_img.filename.rsplit('.', 1)[1].lower() if '.' in profile_img.filename else ''
            if ext not in ['png', 'jpg', 'jpeg', 'gif']:
                flash("Only PNG, JPG, and GIF images are allowed.", "error")
                return redirect(url_for("auth.edit_profile"))

            image_filename = f"user_{user_id}_{secrets.token_hex(8)}.{ext}"
            import os
            from flask import current_app
            upload_dir = os.path.join(current_app.root_path, 'static', 'uploads')
            os.makedirs(upload_dir, exist_ok=True)
            profile_img.save(os.path.join(upload_dir, image_filename))
        
        if not new_username:
            flash("Username cannot be empty.", "error")
            return redirect(url_for("auth.edit_profile"))
            
        user_id = session.get("user_id")
        try:
            database.execute_query("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
            if new_password:
                if not current_password:
                    flash("Current password is required to set a new password.", "error")
                    return redirect(url_for("auth.edit_profile"))
                user = database.get_user_by_username(session.get("username", ""))
                if not user or not check_password_hash(user["password_hash"], current_password):
                    flash("Current password is incorrect.", "error")
                    return redirect(url_for("auth.edit_profile"))
                hashed_pwd = generate_password_hash(new_password)
                database.execute_query("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_pwd, user_id))
            
            if image_filename:
                database.execute_query("UPDATE users SET profile_image = ? WHERE id = ?", (image_filename, user_id))
                session["profile_image"] = image_filename
                
            session["username"] = new_username
            flash("Profile updated successfully.", "success")
            return redirect(url_for("auth.edit_profile"))
        except Exception as e:
            flash("Error updating profile. Username might already be taken.", "error")
            return redirect(url_for("auth.edit_profile"))
            
    user_id = session.get("user_id")
    current_user = database.execute_query("SELECT * FROM users WHERE id = ?", (user_id,), fetch_one=True)
    return render_template("edit_profile.html", current_user=current_user)


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.index"))
