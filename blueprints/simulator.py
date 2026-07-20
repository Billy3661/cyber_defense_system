import os
import json
import requests as req
from flask import Blueprint, render_template, request, jsonify, session
import database
from helpers import (
    login_required, MOCK_INBOX_EMAILS, BADGE_DEFINITIONS, CAMPAIGN_DATA, BOSS_BATTLE_EMAIL,
    check_and_award_badges, limiter
)

simulator_bp = Blueprint("simulator", __name__)


@simulator_bp.route("/simulator")
@login_required
def simulator_page():
    return render_template("simulator.html")


@simulator_bp.route("/api/simulator/emails")
@login_required
def api_simulator_emails():
    return jsonify(MOCK_INBOX_EMAILS)


@simulator_bp.route("/api/simulator/generate", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def api_simulator_generate():
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        return jsonify({"error": "AI generation requires GROQ_API_KEY to be configured."}), 500

    data = request.get_json() or {}
    count = min(int(data.get("count", 5)), 10)
    difficulty = data.get("difficulty", "medium")

    prompt = f"""You are a cybersecurity training system. Generate {count} realistic emails for a phishing awareness training game.
{difficulty.capitalize()} difficulty. Include a mix of phishing and legitimate emails.

Return ONLY valid JSON (no markdown, no explanation) with this exact structure:
{{
  "emails": [
    {{
      "id": 1,
      "sender_name": "Display name",
      "sender_email": "email@domain.com",
      "subject": "Email subject line",
      "date": "Today, 10:24 AM",
      "body_html": "<p>Email body with <a href='http://example.com'>links</a> if applicable</p>",
      "is_phishing": true,
      "red_flags": [
        {{"target": "suspicious element", "reason": "why it is suspicious"}}
      ],
      "explanation": "Brief explanation of why this is or isn't phishing"
    }}
  ]
}}

Rules:
- Each email must have realistic body_html with proper HTML formatting
- Phishing emails: include legitimate-looking links that point to suspicious domains, urgency/pressure tactics
- Legitimate emails: professional tone, no red flags, proper corporate domains
- Red flags should only be present for phishing emails (empty array for legitimate)
- Make each scenario unique and realistic for a corporate environment
- Difficulty {difficulty}: adjust subtlety of red flags accordingly
- Use varied scenarios: billing, security alerts, HR, IT, management, payroll, etc."""

    try:
        groq_api_base = os.environ.get("GROQ_API_BASE", "https://api.groq.com/openai/v1/chat/completions")
        groq_model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

        groq_response = req.post(
            groq_api_base,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": groq_model, "messages": [{"role": "system", "content": "You are a phishing simulation content generator. Output ONLY valid JSON."}, {"role": "user", "content": prompt}], "temperature": 0.8, "max_tokens": 4096},
            timeout=45
        )

        if groq_response.status_code != 200:
            err = groq_response.json().get("error", {}).get("message", "Unknown error")
            return jsonify({"error": f"AI generation error: {err}"}), 500

        reply = groq_response.json()["choices"][0]["message"]["content"]
        reply = reply.strip()
        if reply.startswith("```"):
            reply = reply.split("\n", 1)[-1]
            reply = reply.rsplit("```", 1)[0]
        parsed = json.loads(reply)
        return jsonify(parsed)

    except json.JSONDecodeError:
        return jsonify({"error": "AI returned invalid data. Please try again."}), 500
    except Exception:
        return jsonify({"error": "Email generation failed. Please try again."}), 500


@simulator_bp.route("/api/simulator/debrief", methods=["POST"])
@login_required
@limiter.limit("15 per minute")
def api_simulator_debrief():
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        return jsonify({"error": "AI debrief requires GROQ_API_KEY."}), 500

    data = request.get_json() or {}
    email = data.get("email", {})
    user_answered_phishing = data.get("userAnsweredPhishing", False)
    correct = data.get("correct", False)

    prompt = f"""You are a personalized cybersecurity coach. A user just analyzed an email in a phishing detection exercise. Generate a brief debrief (2-3 sentences).

Email subject: "{email.get('subject', 'N/A')}"
From: "{email.get('sender_name', 'N/A')} <{email.get('sender_email', 'N/A')}>"
Was actually phishing: {"YES" if email.get('is_phishing') else "NO"}
User classified it as: {"PHISHING" if user_answered_phishing else "LEGITIMATE"}
User was: {"CORRECT" if correct else "INCORRECT"}

{"" if correct else "They got it wrong. Gently point out what they missed and give one specific tip for next time."}

{"Briefly reinforce what made it " + ("phishing" if email.get('is_phishing') else "legitimate") + "." if correct else "Focus only on the key mistake and one clear tip."}

No emojis. No greetings. Just the feedback."""

    try:
        groq_api_base = os.environ.get("GROQ_API_BASE", "https://api.groq.com/openai/v1/chat/completions")
        groq_model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

        groq_response = req.post(
            groq_api_base,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": groq_model, "messages": [{"role": "system", "content": "You are a supportive cybersecurity coach."}, {"role": "user", "content": prompt}], "temperature": 0.7, "max_tokens": 500},
            timeout=15
        )

        if groq_response.status_code != 200:
            return jsonify({"debrief": "Great effort! Review the red flags above to sharpen your skills."})

        reply = groq_response.json()["choices"][0]["message"]["content"]
        return jsonify({"debrief": reply.strip()})

    except Exception:
        return jsonify({"debrief": "Keep practicing! Each email you analyze sharpens your threat detection skills."})


@simulator_bp.route("/api/phishing/stats", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def api_phishing_stats():
    data = request.get_json() or {}
    database.record_phishing_stat(
        session["username"],
        data.get("email_id", ""),
        data.get("campaign_id", 0),
        data.get("is_phishing", False),
        data.get("identified_correctly", False),
        data.get("response_time_ms", 0),
        data.get("red_flags_identified", 0),
        data.get("total_red_flags", 0),
        data.get("session_id", "")
    )
    check_and_award_badges(session["username"])
    return jsonify({"ok": True})


@simulator_bp.route("/api/phishing/leaderboard")
@login_required
def api_phishing_leaderboard():
    lb = database.get_leaderboard()
    badge_lb = database.get_badge_leaderboard()
    return jsonify({"leaderboard": lb, "badge_leaderboard": badge_lb})


@simulator_bp.route("/api/phishing/my-stats")
@login_required
def api_phishing_my_stats():
    stats = database.get_user_stats(session["username"])
    badges = database.get_user_badges(session["username"])

    total = len(stats)
    correct = sum(1 for s in stats if s["identified_correctly"])
    accuracy = round((correct / total * 100) if total > 0 else 0, 1)
    phishing_emails = sum(1 for s in stats if s["is_phishing"])
    phishing_correct = sum(1 for s in stats if s["is_phishing"] and s["identified_correctly"])
    legit_emails = total - phishing_emails
    legit_correct = correct - phishing_correct
    total_time = sum(s["response_time_ms"] for s in stats)

    return jsonify({
        "total": total,
        "correct": correct,
        "accuracy": accuracy,
        "phishing_encountered": phishing_emails,
        "phishing_correct": phishing_correct,
        "legit_encountered": legit_emails,
        "legit_correct": legit_correct,
        "total_time_ms": total_time,
        "avg_time_ms": round(total_time / total) if total > 0 else 0,
        "badges": [{"id": b["badge_id"], "awarded": b["awarded_at"]} for b in badges]
    })


@simulator_bp.route("/api/badges")
@login_required
def api_badges():
    return jsonify(BADGE_DEFINITIONS)


# ─────────────────────────────────────────────
#  CAMPAIGN MODE
# ─────────────────────────────────────────────

RANKS = [
    {"min_xp": 0, "name": "Intern", "icon": "school", "color": "#94a3b8"},
    {"min_xp": 100, "name": "Analyst", "icon": "search", "color": "#3b82f6"},
    {"min_xp": 300, "name": "Threat Hunter", "icon": "radar", "color": "#8b5cf6"},
    {"min_xp": 600, "name": "CISO", "icon": "shield", "color": "#f59e0b"},
    {"min_xp": 1000, "name": "SOC Legend", "icon": "emoji_events", "color": "#ef4444"},
]


def _get_rank(xp):
    rank = RANKS[0]
    for r in RANKS:
        if xp >= r["min_xp"]:
            rank = r
    return rank


@simulator_bp.route("/api/simulator/campaigns")
@login_required
def api_campaigns():
    username = session["username"]
    progress = database.get_or_create_user_xp(username)
    completed = json.loads(progress["campaigns_completed"]) if progress["campaigns_completed"] else []
    campaigns = []
    for c in CAMPAIGN_DATA:
        campaigns.append({
            "id": c["id"],
            "title": c["title"],
            "difficulty": c["difficulty"],
            "narrative": c["narrative"],
            "threat_type": c["threat_type"],
            "xp_reward": c["xp_reward"],
            "email_count": len(c["emails"]),
            "completed": c["id"] in completed,
        })
    return jsonify({"campaigns": campaigns, "completed_count": len(completed), "total": len(CAMPAIGN_DATA)})


@simulator_bp.route("/api/simulator/campaign/<campaign_id>")
@login_required
def api_campaign_emails(campaign_id):
    campaign = next((c for c in CAMPAIGN_DATA if c["id"] == campaign_id), None)
    if not campaign:
        return jsonify({"error": "Campaign not found"}), 404
    safe_emails = []
    for e in campaign["emails"]:
        safe_emails.append({
            "id": e["id"],
            "sender_name": e["sender_name"],
            "sender_email": e["sender_email"],
            "subject": e["subject"],
            "date": e["date"],
            "body_html": e["body_html"],
            "is_phishing": e["is_phishing"],
            "red_flags": e["red_flags"],
            "explanation": e["explanation"],
        })
    return jsonify({
        "campaign_id": campaign["id"],
        "title": campaign["title"],
        "narrative": campaign["narrative"],
        "threat_type": campaign["threat_type"],
        "xp_reward": campaign["xp_reward"],
        "emails": safe_emails,
    })


@simulator_bp.route("/api/simulator/campaign/complete", methods=["POST"])
@login_required
def api_complete_campaign():
    data = request.get_json() or {}
    campaign_id = data.get("campaign_id", "")
    xp_earned = data.get("xp_earned", 0)
    username = session["username"]

    campaign = next((c for c in CAMPAIGN_DATA if c["id"] == campaign_id), None)
    if not campaign:
        return jsonify({"error": "Invalid campaign"}), 400

    database.complete_campaign(username, campaign_id)
    database.add_xp(username, xp_earned)

    progress = database.get_or_create_user_xp(username)
    new_xp = progress["xp"]
    new_rank = _get_rank(new_xp)
    database.set_rank(username, RANKS.index(new_rank))

    all_completed = len(json.loads(progress["campaigns_completed"])) >= len(CAMPAIGN_DATA)
    is_boss_defeated = progress["boss_defeated"]

    return jsonify({
        "xp_earned": xp_earned,
        "total_xp": new_xp,
        "rank": new_rank,
        "all_campaigns_completed": all_completed,
        "boss_unlocked": all_completed and not is_boss_defeated,
    })


# ─────────────────────────────────────────────
#  BOSS BATTLE
# ─────────────────────────────────────────────

@simulator_bp.route("/api/simulator/boss-battle")
@login_required
def api_boss_battle():
    username = session["username"]
    progress = database.get_or_create_user_xp(username)
    all_completed = len(json.loads(progress["campaigns_completed"])) >= len(CAMPAIGN_DATA)
    if not all_completed:
        return jsonify({"error": "Complete all 6 campaigns to unlock the boss battle."}), 403
    return jsonify({"email": BOSS_BATTLE_EMAIL})


@simulator_bp.route("/api/simulator/boss/defeat", methods=["POST"])
@login_required
def api_defeat_boss():
    username = session["username"]
    progress = database.get_or_create_user_xp(username)
    if progress["boss_defeated"]:
        return jsonify({"message": "Boss already defeated.", "already_defeated": True})

    database.defeat_boss(username)
    database.add_xp(username, 200)

    progress = database.get_or_create_user_xp(username)
    new_xp = progress["xp"]
    new_rank = _get_rank(new_xp)
    database.set_rank(username, RANKS.index(new_rank))

    all_completed = len(json.loads(progress["campaigns_completed"])) >= len(CAMPAIGN_DATA)
    if all_completed and progress["boss_defeated"]:
        database.set_certified(username)

    return jsonify({
        "xp_earned": 200,
        "total_xp": new_xp,
        "rank": new_rank,
        "certified": all_completed and progress["boss_defeated"],
    })


# ─────────────────────────────────────────────
#  XP & RANK
# ─────────────────────────────────────────────

@simulator_bp.route("/api/simulator/xp")
@login_required
def api_xp():
    username = session["username"]
    progress = database.get_or_create_user_xp(username)
    xp = progress["xp"]
    rank = _get_rank(xp)
    completed = json.loads(progress["campaigns_completed"]) if progress["campaigns_completed"] else []

    next_rank = None
    for r in RANKS:
        if r["min_xp"] > xp:
            next_rank = r
            break

    return jsonify({
        "xp": xp,
        "rank": rank,
        "next_rank": next_rank,
        "campaigns_completed": completed,
        "boss_defeated": bool(progress["boss_defeated"]),
        "certified": bool(progress["certified"]),
    })


@simulator_bp.route("/api/simulator/xp/add", methods=["POST"])
@login_required
def api_add_xp():
    data = request.get_json() or {}
    amount = min(int(data.get("amount", 0)), 100)
    username = session["username"]
    database.add_xp(username, amount)
    progress = database.get_or_create_user_xp(username)
    new_rank = _get_rank(progress["xp"])
    database.set_rank(username, RANKS.index(new_rank))
    return jsonify({"xp": progress["xp"], "rank": new_rank})


# ─────────────────────────────────────────────
#  CERTIFICATION
# ─────────────────────────────────────────────

@simulator_bp.route("/api/simulator/certification")
@login_required
def api_certification():
    username = session["username"]
    progress = database.get_or_create_user_xp(username)
    completed = json.loads(progress["campaigns_completed"]) if progress["campaigns_completed"] else []
    certified = bool(progress["certified"])
    boss_defeated = bool(progress["boss_defeated"])

    return jsonify({
        "certified": certified,
        "campaigns_completed": len(completed),
        "total_campaigns": len(CAMPAIGN_DATA),
        "boss_defeated": boss_defeated,
        "username": username,
        "xp": progress["xp"],
        "rank": _get_rank(progress["xp"]),
    })
