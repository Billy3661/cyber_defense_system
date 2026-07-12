import os
import json
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, current_app
import database
from helpers import login_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _admin_username():
    import os
    return os.environ.get("ADMIN_USERNAME", "").strip().lower()


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        admin_user = _admin_username()
        if not admin_user:
            flash("Admin panel is not configured. Set ADMIN_USERNAME env var.", "error")
            return redirect(url_for("main.index"))
        if session.get("username", "").lower() != admin_user:
            flash("You do not have admin access.", "error")
            return redirect(url_for("main.index"))
        return f(*args, **kwargs)
    return decorated


@admin_bp.route("/")
@admin_required
def dashboard():
    conn = database.get_db_connection()
    cur = conn.cursor()

    stats = {}
    cur.execute(database._p("SELECT COUNT(*) FROM users"))
    stats["users"] = cur.fetchone()[0]
    cur.execute(database._p("SELECT COUNT(*) FROM malware_signatures"))
    stats["signatures"] = cur.fetchone()[0]
    cur.execute(database._p("SELECT COUNT(*) FROM user_phishing_stats"))
    stats["phishing_stats"] = cur.fetchone()[0]
    cur.execute(database._p("SELECT COUNT(*) FROM user_badges"))
    stats["badges"] = cur.fetchone()[0]
    cur.execute(database._p("SELECT COUNT(*) FROM chat_conversations"))
    stats["conversations"] = cur.fetchone()[0]
    cur.execute(database._p("SELECT COUNT(*) FROM chat_messages"))
    stats["messages"] = cur.fetchone()[0]

    cur.execute(database._p("""
        SELECT username, COUNT(*) as attempts,
               SUM(identified_correctly) as correct
        FROM user_phishing_stats
        GROUP BY username ORDER BY correct DESC LIMIT 5
    """))
    if database.using_postgres():
        cols = [d[0] for d in cur.description]
        top_players = [dict(zip(cols, r)) for r in cur.fetchall()]
    else:
        top_players = [dict(r) for r in cur.fetchall()]

    cur.execute(database._p("SELECT * FROM users ORDER BY created_at DESC LIMIT 5"))
    if database.using_postgres():
        cols = [d[0] for d in cur.description]
        recent_users = [dict(zip(cols, r)) for r in cur.fetchall()]
    else:
        recent_users = [dict(r) for r in cur.fetchall()]

    conn.close()
    return render_template("admin/dashboard.html", stats=stats, top_players=top_players, recent_users=recent_users)


@admin_bp.route("/users")
@admin_required
def users():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 20
    search = request.args.get("q", "").strip()

    conn = database.get_db_connection()
    cur = conn.cursor()

    if search:
        cur.execute(database._p("SELECT COUNT(*) FROM users WHERE username LIKE ?"), (f"%{search}%",))
    else:
        cur.execute(database._p("SELECT COUNT(*) FROM users"))
    total = cur.fetchone()[0]
    total_pages = max(1, (total + per_page - 1) // per_page)

    offset = (page - 1) * per_page
    if search:
        cur.execute(database._p("SELECT * FROM users WHERE username LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?"),
                    (f"%{search}%", per_page, offset))
    else:
        cur.execute(database._p("SELECT * FROM users ORDER BY id DESC LIMIT ? OFFSET ?"), (per_page, offset))

    if database.using_postgres():
        cols = [d[0] for d in cur.description]
        users_list = [dict(zip(cols, r)) for r in cur.fetchall()]
    else:
        users_list = [dict(r) for r in cur.fetchall()]

    conn.close()
    return render_template("admin/users.html", users=users_list, page=page, total_pages=total_pages, total=total, search=search)


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = database.execute_query("SELECT username FROM users WHERE id = ?", (user_id,), fetch_one=True)
    if user and user["username"].lower() == _admin_username():
        flash("Cannot delete the admin user.", "error")
        return redirect(url_for("admin.users"))

    database.execute_query("DELETE FROM chat_messages WHERE conversation_id IN (SELECT id FROM chat_conversations WHERE username = ?)", (user.get("username", ""),))
    database.execute_query("DELETE FROM chat_conversations WHERE username = ?", (user.get("username", ""),))
    database.execute_query("DELETE FROM user_badges WHERE username = ?", (user.get("username", ""),))
    database.execute_query("DELETE FROM user_phishing_stats WHERE username = ?", (user.get("username", ""),))
    database.execute_query("DELETE FROM user_settings WHERE username = ?", (user.get("username", ""),))
    database.execute_query("DELETE FROM users WHERE id = ?", (user_id,))
    flash(f"User '{user.get('username', '')}' deleted.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/signatures")
@admin_required
def signatures():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 20
    search = request.args.get("q", "").strip()

    conn = database.get_db_connection()
    cur = conn.cursor()

    if search:
        cur.execute(database._p("SELECT COUNT(*) FROM malware_signatures WHERE threat_name LIKE ? OR hash_value LIKE ?"),
                    (f"%{search}%", f"%{search}%"))
    else:
        cur.execute(database._p("SELECT COUNT(*) FROM malware_signatures"))
    total = cur.fetchone()[0]
    total_pages = max(1, (total + per_page - 1) // per_page)

    offset = (page - 1) * per_page
    if search:
        cur.execute(database._p("SELECT * FROM malware_signatures WHERE threat_name LIKE ? OR hash_value LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?"),
                    (f"%{search}%", f"%{search}%", per_page, offset))
    else:
        cur.execute(database._p("SELECT * FROM malware_signatures ORDER BY id DESC LIMIT ? OFFSET ?"), (per_page, offset))

    if database.using_postgres():
        cols = [d[0] for d in cur.description]
        sigs = [dict(zip(cols, r)) for r in cur.fetchall()]
    else:
        sigs = [dict(r) for r in cur.fetchall()]

    conn.close()
    return render_template("admin/signatures.html", signatures=sigs, page=page, total_pages=total_pages, total=total, search=search)


@admin_bp.route("/signatures/add", methods=["POST"])
@admin_required
def add_signature():
    hash_val = request.form.get("hash_value", "").strip()
    threat_name = request.form.get("threat_name", "").strip()
    severity = request.form.get("severity", "Medium").strip()
    details = request.form.get("details", "").strip()

    if not hash_val or not threat_name or not severity:
        flash("Hash, threat name, and severity are required.", "error")
        return redirect(url_for("admin.signatures"))

    if database.add_malware_signature(hash_val, threat_name, severity, details):
        flash("Signature added.", "success")
    else:
        flash("Failed to add signature (hash may already exist).", "error")
    return redirect(url_for("admin.signatures"))


@admin_bp.route("/signatures/<int:sig_id>/delete", methods=["POST"])
@admin_required
def delete_signature(sig_id):
    database.execute_query("DELETE FROM malware_signatures WHERE id = ?", (sig_id,))
    flash("Signature deleted.", "success")
    return redirect(url_for("admin.signatures"))


@admin_bp.route("/badges")
@admin_required
def badges():
    conn = database.get_db_connection()
    cur = conn.cursor()

    cur.execute(database._p("""
        SELECT b.id, b.username, b.badge_id, b.awarded_at
        FROM user_badges b
        ORDER BY b.awarded_at DESC
        LIMIT 200
    """))
    if database.using_postgres():
        cols = [d[0] for d in cur.description]
        badge_list = [dict(zip(cols, r)) for r in cur.fetchall()]
    else:
        badge_list = [dict(r) for r in cur.fetchall()]

    cur.execute(database._p("SELECT COUNT(*) FROM user_badges"))
    total = cur.fetchone()[0]

    conn.close()
    return render_template("admin/badges.html", badges=badge_list, total=total)


@admin_bp.route("/badges/<int:badge_id>/delete", methods=["POST"])
@admin_required
def delete_badge(badge_id):
    database.execute_query("DELETE FROM user_badges WHERE id = ?", (badge_id,))
    flash("Badge removed.", "success")
    return redirect(url_for("admin.badges"))


@admin_bp.route("/stats")
@admin_required
def phishing_stats():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 20
    search = request.args.get("q", "").strip()

    conn = database.get_db_connection()
    cur = conn.cursor()

    if search:
        cur.execute(database._p("SELECT COUNT(*) FROM user_phishing_stats WHERE username LIKE ?"), (f"%{search}%",))
    else:
        cur.execute(database._p("SELECT COUNT(*) FROM user_phishing_stats"))
    total = cur.fetchone()[0]
    total_pages = max(1, (total + per_page - 1) // per_page)

    offset = (page - 1) * per_page
    if search:
        cur.execute(database._p("SELECT * FROM user_phishing_stats WHERE username LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?"),
                    (f"%{search}%", per_page, offset))
    else:
        cur.execute(database._p("SELECT * FROM user_phishing_stats ORDER BY id DESC LIMIT ? OFFSET ?"), (per_page, offset))

    if database.using_postgres():
        cols = [d[0] for d in cur.description]
        stats_list = [dict(zip(cols, r)) for r in cur.fetchall()]
    else:
        stats_list = [dict(r) for r in cur.fetchall()]

    conn.close()
    return render_template("admin/stats.html", stats=stats_list, page=page, total_pages=total_pages, total=total, search=search)


@admin_bp.route("/conversations")
@admin_required
def conversations():
    conn = database.get_db_connection()
    cur = conn.cursor()

    cur.execute(database._p("""
        SELECT c.*, 
               (SELECT COUNT(*) FROM chat_messages m WHERE m.conversation_id = c.id) as msg_count
        FROM chat_conversations c
        ORDER BY c.updated_at DESC
        LIMIT 200
    """))
    if database.using_postgres():
        cols = [d[0] for d in cur.description]
        convos = [dict(zip(cols, r)) for r in cur.fetchall()]
    else:
        convos = [dict(r) for r in cur.fetchall()]

    cur.execute(database._p("SELECT COUNT(*) FROM chat_conversations"))
    total = cur.fetchone()[0]

    conn.close()
    return render_template("admin/conversations.html", conversations=convos, total=total)


@admin_bp.route("/conversations/<int:conv_id>/delete", methods=["POST"])
@admin_required
def delete_conversation(conv_id):
    database.delete_conversation(conv_id)
    flash("Conversation deleted.", "success")
    return redirect(url_for("admin.conversations"))


@admin_bp.route("/users/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    user = database.execute_query("SELECT username FROM users WHERE id = ?", (user_id,), fetch_one=True)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin.users"))
    flash("Admin role is managed via the ADMIN_USERNAME environment variable.", "info")
    return redirect(url_for("admin.users"))
