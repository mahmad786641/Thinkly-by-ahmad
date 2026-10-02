# ============================================================
# config.py — Configuration, Env, Logging, SDKs, Helpers
# ============================================================
import os
import re
import logging
import hashlib
import secrets
import smtplib
import importlib.util          # ← ADDED for the fix below
from datetime import datetime, timedelta
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import resend

def send_reset_email(to_email, reset_link):
    if not HAS_SMTP:
        return False, "Email not configured"
    try:
        resend.api_key = os.environ.get("RESEND_API_KEY")
        params = {
            "from": "Thinkly <onboarding@resend.dev>",
            "to": [to_email],
            "subject": "Reset your Thinkly password",
            "html": f"""
                <h2>Reset your Thinkly password</h2>
                <p>Click the link below (valid 30 min):</p>
                <a href="{reset_link}">Reset password</a>
            """,
        }
        resend.Emails.send(params)
        return True, None
    except Exception as e:
        log.exception("Resend send failed")
        return False, str(e)
# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("thinkly")

# ------------------------------------------------------------
# Env
# ------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_PATH, override=True)

SECRET_KEY = os.environ.get("SECRET_KEY")
IS_PROD = os.environ.get("FLASK_ENV", "development").lower() == "production"

if not SECRET_KEY:
    if IS_PROD:
        raise RuntimeError("SECRET_KEY is required in production.")
    SECRET_KEY = "dev-only-insecure-key-change-me"
    log.warning("Using insecure dev SECRET_KEY.")

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def clean_key(raw):
    if not raw:
        return None
    k = str(raw).strip()
    if len(k) >= 2 and k[0] == k[-1] and k[0] in ('"', "'"):
        k = k[1:-1]
    return k.strip() or None


# --- Provider detection ---
GROQ_API_KEY   = clean_key(os.environ.get("GROQ_API_KEY"))
GEMINI_API_KEY = clean_key(os.environ.get("GEMINI_API_KEY"))

GROQ_MODEL   = clean_key(os.environ.get("GROQ_MODEL"))   or "openai/gpt-oss-120b"
GEMINI_MODEL = clean_key(os.environ.get("GEMINI_MODEL")) or "gemini-2.0-flash"

# Decide which provider to use
PROVIDER = None
PROVIDER_REASON = ""

if GROQ_API_KEY and GROQ_API_KEY.startswith("gsk_"):
    PROVIDER = "groq"
elif GEMINI_API_KEY and GEMINI_API_KEY.startswith("AIza"):
    PROVIDER = "gemini"
elif GEMINI_API_KEY and GEMINI_API_KEY.startswith("AQ."):
    PROVIDER = "gemini_aq_invalid"
    PROVIDER_REASON = (
        "Your GEMINI_API_KEY starts with 'AQ.'. That is a Google Cloud OAuth key, "
        "NOT a Gemini API key. Get a proper key from https://aistudio.google.com/apikey "
        "(it will start with 'AIza')."
    )
elif GROQ_API_KEY:
    PROVIDER = "groq"
elif GEMINI_API_KEY:
    PROVIDER = "gemini"

DEMO_FALLBACK = os.environ.get("DEMO_FALLBACK", "1" if not IS_PROD else "0") == "1"

# ------------------------------------------------------------
# Load SDKs (only what's needed)
# ------------------------------------------------------------
groq_client = None
gemini_client = None
gemini_types = None

if PROVIDER == "groq":
    try:
        from groq import Groq
        groq_client = Groq(api_key=GROQ_API_KEY, timeout=60.0, max_retries=2)
        log.info("Groq client ready.")
    except Exception as e:
        log.error("Groq client init failed: %s", e)
        groq_client = None

elif PROVIDER == "gemini":
    try:
        from google import genai
        from google.genai import types as gemini_types
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
        log.info("Gemini client ready.")
    except Exception as e:
        log.error("Gemini client init failed: %s", e)
        gemini_client = None

# ------------------------------------------------------------
# SMTP config
# ------------------------------------------------------------
SMTP_HOST = clean_key(os.environ.get("SMTP_HOST"))
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = clean_key(os.environ.get("SMTP_USER"))
SMTP_PASS = clean_key(os.environ.get("SMTP_PASS"))
SMTP_FROM = clean_key(os.environ.get("SMTP_FROM")) or SMTP_USER
APP_URL   = clean_key(os.environ.get("APP_URL")) or "http://127.0.0.1:5001"

HAS_SMTP = bool(os.environ.get("RESEND_API_KEY")) or bool(SMTP_HOST and SMTP_USER and SMTP_PASS)

def send_reset_email(to_email, reset_link):
    if not HAS_SMTP:
        return False, "SMTP not configured"
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Reset your Thinkly password"
        msg["From"] = SMTP_FROM
        msg["To"] = to_email

        text = (
            f"Someone requested a password reset for your Thinkly account.\n\n"
            f"Reset link (valid for 30 minutes):\n{reset_link}\n\n"
            f"If you didn't request this, ignore this email."
        )
        html = f"""\
<html><body style="font-family:sans-serif;background:#0d0d0f;color:#e8e8ee;padding:24px;">
  <h2 style="color:#7c5cff;">Reset your Thinkly password</h2>
  <p><a href="{reset_link}" style="display:inline-block;background:#7c5cff;color:#fff;
     padding:10px 18px;border-radius:8px;text-decoration:none;">Reset password</a></p>
</body></html>"""
        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_FROM, [to_email], msg.as_string())
        return True, None
    except Exception as e:
        log.exception("SMTP send failed")
        return False, str(e)


# ------------------------------------------------------------
# Token helpers for password reset
# ------------------------------------------------------------
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_reset_token():
    token = secrets.token_urlsafe(32)
    return token, _hash_token(token)


def reset_expiry_str(minutes=30):
    return (datetime.utcnow() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------
# System prompt / limits
# ------------------------------------------------------------
SYSTEM_PROMPT = """You are Thinkly, a friendly, concise AI assistant.
Style guidelines:
- Use markdown formatting where it helps.
- Keep replies focused.
- Be warm, helpful, and direct.
- If the user tells you their name, remember it and use it in your responses.
- If the user asks 'what is my name?', answer with their name.
- If the user asks you to continue a previous response, continue exactly where you left off. Do not repeat yourself."""

MAX_HISTORY_MESSAGES = 20
MAX_CHARS_PER_MSG    = 1000
MAX_CHARS_USER       = 3000
MAX_OUTPUT_TOKENS    = 2000
RESET_TOKEN_MINUTES  = 30


def trim(text, limit):
    if not text:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    half = limit // 2 - 20
    return text[:half] + "\n…[truncated]…\n" + text[-half:]


# ------------------------------------------------------------
# Startup diagnostics (prints when this module is imported)
# ------------------------------------------------------------
log.info("=" * 60)
log.info("Thinkly Chatbot — Startup")
log.info("Mode           : %s", "production" if IS_PROD else "development")
log.info("Provider       : %s", PROVIDER or "NONE (demo mode)")
if PROVIDER_REASON:
    log.warning("Reason         : %s", PROVIDER_REASON)
log.info("Groq key       : %s", "LOADED ✅" if GROQ_API_KEY else "—")
log.info("Gemini key     : %s", "LOADED ✅" if GEMINI_API_KEY else "—")
log.info("Groq model     : %s", GROQ_MODEL if PROVIDER == "groq" else "N/A")
log.info("Rate limiter   : %s", "ON ✅" if importlib.util.find_spec("flask_limiter") else "OFF ⚠")
log.info("SMTP email     : %s", "ON ✅" if HAS_SMTP else "OFF ⚠")
log.info("Demo fallback  : %s", "ON ⚠" if DEMO_FALLBACK else "OFF")
log.info("=" * 60)