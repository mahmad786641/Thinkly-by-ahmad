# ============================================================
# app.py — Flask Routes & Main Entry Point
# ============================================================
import uuid
import secrets
from flask import (
    Flask, request, jsonify, render_template,
    Response, stream_with_context, session,
)
from functools import wraps
import json
import re
import os
import time

# ---- Import our config and database modules ----
from config import (
    SECRET_KEY, IS_PROD, log,
    GROQ_API_KEY, GEMINI_API_KEY, GROQ_MODEL, GEMINI_MODEL,
    PROVIDER, PROVIDER_REASON, DEMO_FALLBACK,
    groq_client, gemini_client, gemini_types,
    HAS_SMTP, APP_URL,
    send_reset_email,
    SYSTEM_PROMPT, MAX_HISTORY_MESSAGES, MAX_CHARS_PER_MSG,
    MAX_CHARS_USER, MAX_OUTPUT_TOKENS, RESET_TOKEN_MINUTES,
    trim, _hash_token, generate_reset_token, reset_expiry_str,
)
from database import (
    get_db, save_message, get_history, get_all_messages, clear_user_messages,
    create_user, verify_user, get_user_name, set_user_name,
    update_user_password, find_user_by_username,
    purge_expired_resets, create_reset_token, find_valid_reset,
    mark_reset_used, extract_name_from_text,
)

# ------------------------------------------------------------
# Flask App
# ------------------------------------------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PROD,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7,
)

# ------------------------------------------------------------
# Rate limiting
# ------------------------------------------------------------
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        storage_uri="memory://",
    )
    HAS_LIMITER = True
except Exception:
    log.warning("Flask-Limiter not installed. Rate limiting disabled.")
    HAS_LIMITER = False

    class _DummyLimiter:
        def limit(self, *a, **kw):
            def deco(f):
                return f
            return deco

    limiter = _DummyLimiter()

# ------------------------------------------------------------
# Auth decorator + security headers
# ------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized. Please log in."}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


# ============================================================
# Auth routes
# ============================================================
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
PLAIN_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


@app.route("/api/register", methods=["POST"])
@limiter.limit("10 per hour")
def register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if len(username) < 3 or len(username) > 64:
        return jsonify({"error": "Username must be 3–64 characters"}), 400
    if not (EMAIL_RE.match(username) or PLAIN_RE.match(username)):
        return jsonify({"error": "Invalid username format"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    user_id, err = create_user(username, password)
    if err:
        return jsonify({"error": err}), 400

    session.permanent = True
    session["user_id"] = user_id
    session["username"] = username
    return jsonify({"ok": True, "username": username})


@app.route("/api/login", methods=["POST"])
@limiter.limit("20 per minute")
def login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    user_id = verify_user(username, password)
    if not user_id:
        return jsonify({"error": "Invalid username or password"}), 401

    session.permanent = True
    session["user_id"] = user_id
    session["username"] = username
    return jsonify({"ok": True, "username": username})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def me():
    if "user_id" in session:
        return jsonify({"logged_in": True, "username": session["username"]})
    return jsonify({"logged_in": False}), 401


# ============================================================
# Password reset routes
# ============================================================
@app.route("/api/forgot-password", methods=["POST"])
@limiter.limit("5 per hour")
def forgot_password():
    data = request.get_json() or {}
    identifier = (data.get("username") or "").strip()

    if not identifier:
        return jsonify({"error": "Username or email is required"}), 400

    purge_expired_resets()
    row = find_user_by_username(identifier)

    generic_response = {
        "ok": True,
        "message": "If that account exists, a reset link has been sent."
    }

    if not row:
        return jsonify(generic_response)

    user_id = row["id"]
    username = row["username"]

    token, token_hash = generate_reset_token()
    expires_at = reset_expiry_str(RESET_TOKEN_MINUTES)
    create_reset_token(user_id, token_hash, expires_at)

    reset_link = f"{APP_URL.rstrip('/')}/?reset_token={token}"

    email_sent = False
    if HAS_SMTP and EMAIL_RE.match(username):
        ok, _ = send_reset_email(username, reset_link)
        email_sent = ok

    payload = dict(generic_response)
    if not IS_PROD and not email_sent:
        payload["dev_reset_link"] = reset_link
        payload["message"] = "Dev mode: reset link included in response."

    return jsonify(payload)


@app.route("/api/reset-password", methods=["POST"])
@limiter.limit("10 per hour")
def reset_password():
    data = request.get_json() or {}
    token = (data.get("token") or "").strip()
    new_password = (data.get("password") or "").strip()

    if not token or not new_password:
        return jsonify({"error": "Token and new password are required"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    token_hash = _hash_token(token)
    purge_expired_resets()

    row = find_valid_reset(token_hash)
    if not row:
        return jsonify({"error": "Invalid or expired reset token"}), 400

    update_user_password(row["user_id"], new_password)
    mark_reset_used(row["id"])

    return jsonify({"ok": True, "message": "Password updated. You can now log in."})


@app.route("/api/verify-reset-token", methods=["POST"])
@limiter.limit("30 per hour")
def verify_reset_token():
    data = request.get_json() or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"valid": False}), 400

    row = find_valid_reset(_hash_token(token))
    return jsonify({"valid": bool(row)})


# ============================================================
# Main / Health / Chat routes
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({
        "ok": True,
        "provider": PROVIDER,
        "groq_key": bool(GROQ_API_KEY),
        "gemini_key": bool(GEMINI_API_KEY),
        "groq_model": GROQ_MODEL if PROVIDER == "groq" else None,
        "demo_fallback": DEMO_FALLBACK,
        "rate_limiter": HAS_LIMITER,
        "smtp": HAS_SMTP,
    })


@app.route("/api/history")
@login_required
def history():
    return jsonify(get_all_messages(session["user_id"]))


@app.route("/api/clear", methods=["POST"])
@login_required
def clear_chat():
    clear_user_messages(session["user_id"])
    return jsonify({"ok": True})


# ------------------------------------------------------------
# Provider streaming helpers
# ------------------------------------------------------------
def stream_groq(messages):
    stream = groq_client.chat.completions.create(
        model=GROQ_MODEL,
        messages=messages,
        temperature=0.7,
        max_tokens=MAX_OUTPUT_TOKENS,
        stream=True,
    )
    for chunk in stream:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta.content
        if delta:
            yield delta


def stream_gemini(system_prompt, history, user_message):
    contents = []
    for h in history:
        contents.append(
            gemini_types.Content(
                role=h["role"],
                parts=[gemini_types.Part(text=p) for p in h["parts"]],
            )
        )
    contents.append(
        gemini_types.Content(
            role="user",
            parts=[gemini_types.Part(text=user_message)],
        )
    )

    config = gemini_types.GenerateContentConfig(
        system_instruction=system_prompt,
        temperature=0.7,
        max_output_tokens=MAX_OUTPUT_TOKENS,
    )

    stream = gemini_client.models.generate_content_stream(
        model=GEMINI_MODEL,
        contents=contents,
        config=config,
    )
    for chunk in stream:
        text = getattr(chunk, "text", None)
        if text:
            yield text


def demo_stream(user_message: str):
    name = None
    m = re.search(r"\bmy name is\s+([A-Za-z][A-Za-z'\-]{1,30})", user_message, re.IGNORECASE)
    if m:
        name = m.group(1).title()
    greeting = f"Hey {name}!" if name else "Hi there!"
    reply = (
        f"{greeting} **Demo mode is active** — no AI provider is configured.\n\n"
        f"You said: *\"{user_message[:200]}\"*\n\n"
        f"**To enable real AI responses, add ONE of these to `.env`:**\n\n"
        f"```env\n"
        f"# Option A: Groq (easiest — 30 sec setup)\n"
        f"# Get key at https://console.groq.com/keys\n"
        f"GROQ_API_KEY=gsk_...\n\n"
        f"# Option B: Google Gemini\n"
        f"# Get key at https://aistudio.google.com/apikey\n"
        f"GEMINI_API_KEY=AIza...\n"
        f"```\n\n"
        f"Then restart Flask."
    )
    for chunk in reply.split(" "):
        yield chunk + " "
        time.sleep(0.03)


# ------------------------------------------------------------
# Main chat endpoint
# ------------------------------------------------------------
@app.route("/api/chat", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def chat():
    data = request.get_json() or {}
    message = (data.get("message") or "").strip()
    user_id = session["user_id"]

    if not message:
        return jsonify({"error": "empty message"}), 400

    message = trim(message, MAX_CHARS_USER)

    if not get_user_name(user_id):
        detected = extract_name_from_text(message)
        if detected:
            set_user_name(user_id, detected)

    save_message(user_id, "user", message)

    user_name = get_user_name(user_id)
    system_prompt = SYSTEM_PROMPT
    if user_name:
        system_prompt += f"\n\nThe user's name is {user_name}. Always address them by their name."

    recent = get_history(user_id, limit=MAX_HISTORY_MESSAGES)
    if recent and recent[-1]["content"] == message and recent[-1]["role"] == "user":
        recent = recent[:-1]

    clean_history = []
    for m in recent:
        c = trim(m.get("content", ""), MAX_CHARS_PER_MSG)
        if c:
            clean_history.append({"role": m["role"], "content": c})

    def generate_demo_only():
        notice = "⚠️ **Demo mode** — no AI provider configured.\n\n"
        full = notice
        yield f"data: {json.dumps({'delta': notice})}\n\n"
        for piece in demo_stream(message):
            full += piece
            yield f"data: {json.dumps({'delta': piece})}\n\n"
        save_message(user_id, "assistant", full)
        yield "data: [DONE]\n\n"

    def generate_real():
        full_response = ""
        try:
            if PROVIDER == "groq":
                msgs = [{"role": "system", "content": system_prompt}]
                for h in clean_history:
                    role = "user" if h["role"] == "user" else "assistant"
                    msgs.append({"role": role, "content": h["content"]})
                msgs.append({"role": "user", "content": message})

                for delta in stream_groq(msgs):
                    full_response += delta
                    yield f"data: {json.dumps({'delta': delta})}\n\n"

            elif PROVIDER == "gemini":
                gemini_history = []
                for h in clean_history:
                    role = "user" if h["role"] == "user" else "model"
                    gemini_history.append({"role": role, "parts": [h["content"]]})

                for delta in stream_gemini(system_prompt, gemini_history, message):
                    full_response += delta
                    yield f"data: {json.dumps({'delta': delta})}\n\n"

            if full_response:
                save_message(user_id, "assistant", full_response)
            yield "data: [DONE]\n\n"
            return

        except GeneratorExit:
            # User clicked Stop — save partial response
            log.info("Client disconnected during streaming. Saving partial response.")
            if full_response:
                save_message(user_id, "assistant", full_response)
            raise

        except Exception as e:
            err_str = str(e)
            log.exception("Provider error")

            if DEMO_FALLBACK:
                notice = f"⚠️ **Fallback to demo** — provider error: `{err_str[:200]}`\n\n"
                full = notice
                yield f"data: {json.dumps({'delta': notice})}\n\n"
                for piece in demo_stream(message):
                    full += piece
                    yield f"data: {json.dumps({'delta': piece})}\n\n"
                save_message(user_id, "assistant", full)
                yield "data: [DONE]\n\n"
            else:
                yield f"data: {json.dumps({'error': err_str})}\n\n"

    has_working_client = (
        (PROVIDER == "groq" and groq_client) or
        (PROVIDER == "gemini" and gemini_client)
    )

    if not has_working_client:
        if DEMO_FALLBACK:
            streamer = generate_demo_only
        else:
            return jsonify({
                "error": "No AI provider configured.",
                "hint": PROVIDER_REASON or "Add GROQ_API_KEY or GEMINI_API_KEY to .env"
            }), 500
    else:
        streamer = generate_real

    return Response(
        stream_with_context(streamer()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ============================================================
# Entry point
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1" and not IS_PROD
    app.run(host="0.0.0.0", port=port, debug=debug)