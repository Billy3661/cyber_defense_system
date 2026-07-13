import os
import logging
import requests as req
from flask import Blueprint, request, jsonify, session
import database
from helpers import login_required, validate_csrf, limiter

chat_bp = Blueprint("chat", __name__)


@chat_bp.route("/api/chat", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def api_chat():
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        return jsonify({"error": "AI is not configured. Please contact the administrator."}), 500

    username = session["username"]

    try:
        data = request.json
        user_message = data.get("message", "").strip()
        conv_id = data.get("conversation_id")
        history = data.get("history", [])
        context = data.get("context", "")

        if not user_message:
            return jsonify({"error": "Empty message provided."}), 400

        if not conv_id:
            conv_id = database.create_conversation(username, user_message[:80])

        database.add_message(conv_id, "user", user_message)

        system_prompt = """You are Securix AI, a cybersecurity assistant. Answer in 2-4 short paragraphs maximum. Be direct and precise. Use Markdown only when it aids clarity (bullet points, bold). Never use emojis. If asked about a scan result, interpret it specifically. If you don't know, say so."""

        if context:
            system_prompt += f"\n\nContext:\n{context}"

        messages = [{"role": "system", "content": system_prompt}]
        for msg in history:
            role = "user" if msg.get("role") == "user" else "assistant"
            messages.append({"role": role, "content": msg.get("content", "")})
        messages.append({"role": "user", "content": user_message})

        groq_api_base = os.environ.get("GROQ_API_BASE", "https://api.groq.com/openai/v1/chat/completions")
        groq_model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

        groq_response = req.post(
            groq_api_base,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": groq_model,
                "messages": messages,
                "temperature": 0.4,
                "max_tokens": 1024
            },
            timeout=30
        )

        if groq_response.status_code != 200:
            err = groq_response.json().get("error", {}).get("message", "Unknown error")
            return jsonify({"error": f"AI service error: {err}"}), 500

        reply_text = groq_response.json()["choices"][0]["message"]["content"]

        database.add_message(conv_id, "assistant", reply_text)

        convs = database.get_conversations(username)
        for c in convs:
            if c["id"] == conv_id and not c.get("title"):
                database.update_conversation_title(conv_id, user_message[:80])
                break

        return jsonify({"response": reply_text, "conversation_id": conv_id})

    except req.exceptions.Timeout:
        return jsonify({"error": "AI took too long to respond. Please try again."}), 504
    except Exception as e:
        logging.exception("Chatbot error")
        return jsonify({"error": "Failed to reach AI service."}), 500


@chat_bp.route("/api/chat/history", methods=["GET"])
@login_required
def chat_history():
    username = session["username"]
    convs = database.get_conversations(username)
    return jsonify([{
        "id": c["id"],
        "title": c.get("title") or "New Chat",
        "created_at": c["created_at"],
        "updated_at": c["updated_at"]
    } for c in convs])


@chat_bp.route("/api/chat/history/<int:conv_id>", methods=["GET"])
@login_required
def chat_history_messages(conv_id):
    username = session["username"]
    convs = database.get_conversations(username)
    if not any(c["id"] == conv_id for c in convs):
        return jsonify({"error": "Conversation not found"}), 404
    msgs = database.get_messages(conv_id)
    return jsonify([{
        "id": m["id"],
        "role": m["role"],
        "content": m["content"],
        "created_at": m["created_at"]
    } for m in msgs])


@chat_bp.route("/api/chat/history/<int:conv_id>", methods=["DELETE"])
@login_required
def chat_delete_conversation(conv_id):
    if not validate_csrf():
        return jsonify({"error": "Session expired"}), 403

    username = session["username"]
    convs = database.get_conversations(username)
    if not any(c["id"] == conv_id for c in convs):
        return jsonify({"error": "Conversation not found"}), 404
    database.delete_conversation(conv_id)
    return jsonify({"ok": True})


@chat_bp.route("/api/chat/message/<int:msg_id>", methods=["DELETE"])
@login_required
def chat_delete_message(msg_id):
    if not validate_csrf():
        return jsonify({"error": "Session expired"}), 403

    database.delete_message(msg_id)
    return jsonify({"ok": True})
