from flask import Blueprint, render_template, request, jsonify, session
from helpers import THREATS_DB, TROUBLESHOOT_GUIDES, login_required

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    stats = {
        "threats_count": len(THREATS_DB),
        "guides_count": len(TROUBLESHOOT_GUIDES),
        "links_scanned": session.get("links_scanned", 0),
    }
    recent_threats = THREATS_DB[:4]
    return render_template("index.html", stats=stats, recent_threats=recent_threats)


@main_bp.route("/threats")
def threats():
    category = request.args.get("category", "All")
    if category == "All":
        filtered = THREATS_DB
    else:
        filtered = [t for t in THREATS_DB if t["category"] == category]

    categories = list(set(t["category"] for t in THREATS_DB))
    categories.sort()
    return render_template("threats.html", threats=filtered, categories=categories, active_category=category)


@main_bp.route("/threat/<int:threat_id>")
def threat_detail(threat_id):
    threat = next((t for t in THREATS_DB if t["id"] == threat_id), None)
    if not threat:
        return render_template("404.html"), 404
    return render_template("threat_detail.html", threat=threat)


@main_bp.route("/awareness")
def awareness():
    return render_template("awareness.html")


@main_bp.route("/troubleshoot")
@login_required
def troubleshoot():
    return render_template("troubleshoot.html", guides=TROUBLESHOOT_GUIDES)


@main_bp.route("/troubleshoot/<guide_id>")
@login_required
def troubleshoot_detail(guide_id):
    guide = next((g for g in TROUBLESHOOT_GUIDES if g["id"] == guide_id), None)
    if not guide:
        return render_template("404.html"), 404
    return render_template("troubleshoot_detail.html", guide=guide)


@main_bp.route("/api/check-auth")
def check_auth():
    return jsonify({"authenticated": "user_id" in session})


@main_bp.route("/api/stats")
def api_stats():
    return jsonify({
        "threats": len(THREATS_DB),
        "guides": len(TROUBLESHOOT_GUIDES),
        "scans": session.get("links_scanned", 0),
    })
