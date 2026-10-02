# ============================================================
# database.py — SQLite Connection, Tables, User/Message Helpers
# ============================================================
import os
import re
import sqlite3
from contextlib import contextmanager
from werkzeug.security import generate_password_hash, check_password_hash
from config import BASE_DIR, log


# ------------------------------------------------------------
# Database Path
# ------------------------------------------------------------
DB_NAME = os.path.join(BASE_DIR, "chatbot.db")


# ------------------------------------------------------------
# Connection helper
# ------------------------------------------------------------
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ------------------------------------------------------------
# Initialize DB tables
# ------------------------------------------------------------
def init_db():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id, id)")
        c.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at DATETIME NOT NULL,
                used_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_reset_token_hash ON password_resets(token_hash)")
        cols = [r["name"] for r in c.execute("PRAGMA table_info(users)").fetchall()]
        if "display_name" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN display_name TEXT")


# ------------------------------------------------------------
# User helpers
# ------------------------------------------------------------
def create_user(username, password):
    """Returns (user_id, error_message)."""
    try:
        with get_db() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            return cur.lastrowid, None
    except sqlite3.IntegrityError:
        return None, "Username already exists"


def verify_user(username, password):
    """Returns user_id if valid, else None."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    if row and check_password_hash(row["password_hash"], password):
        return row["id"]
    return None


def get_user_name(user_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT display_name FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    return row["display_name"] if row and row["display_name"] else None


def set_user_name(user_id, name):
    with get_db() as conn:
        conn.execute("UPDATE users SET display_name = ? WHERE id = ?", (name, user_id))


def update_user_password(user_id, new_password):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )


def find_user_by_username(username):
    with get_db() as conn:
        return conn.execute(
            "SELECT id, username FROM users WHERE username = ?", (username,)
        ).fetchone()


def cleanup_old_guests(days=7):
    """Delete guest accounts older than N days with no recent activity."""
    with get_db() as conn:
        conn.execute("""
            DELETE FROM users
            WHERE username LIKE 'guest_%'
              AND created_at < datetime('now', ?)
              AND id NOT IN (
                  SELECT DISTINCT user_id FROM messages
                  WHERE timestamp > datetime('now', ?)
              )
        """, (f'-{days} days', f'-{days} days'))


# ------------------------------------------------------------
# Message helpers
# ------------------------------------------------------------
def save_message(user_id, role, content):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO messages (user_id, role, content) VALUES (?, ?, ?)",
            (user_id, role, content),
        )


def get_history(user_id, limit=20):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT role, content FROM messages WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]


def get_all_messages(user_id):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT role, content, timestamp FROM messages WHERE user_id = ? ORDER BY id ASC",
            (user_id,),
        ).fetchall()
    return [
        {"role": r["role"], "content": r["content"], "timestamp": r["timestamp"]}
        for r in rows
    ]


def clear_user_messages(user_id):
    with get_db() as conn:
        conn.execute("DELETE FROM messages WHERE user_id = ?", (user_id,))


# ------------------------------------------------------------
# Password reset helpers
# ------------------------------------------------------------
def purge_expired_resets():
    with get_db() as conn:
        conn.execute("DELETE FROM password_resets WHERE expires_at < datetime('now')")


def create_reset_token(user_id, token_hash, expires_at):
    with get_db() as conn:
        conn.execute(
            "UPDATE password_resets SET used_at = datetime('now') "
            "WHERE user_id = ? AND used_at IS NULL",
            (user_id,),
        )
        conn.execute(
            "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user_id, token_hash, expires_at),
        )


def find_valid_reset(token_hash):
    with get_db() as conn:
        return conn.execute(
            """
            SELECT id, user_id FROM password_resets
            WHERE token_hash = ?
              AND used_at IS NULL
              AND expires_at > datetime('now')
            """,
            (token_hash,),
        ).fetchone()


def mark_reset_used(reset_id):
    with get_db() as conn:
        conn.execute(
            "UPDATE password_resets SET used_at = datetime('now') WHERE id = ?",
            (reset_id,),
        )


# ------------------------------------------------------------
# Name extraction from user text
# ------------------------------------------------------------
_NAME_PATTERNS = [
    re.compile(r"\bmy name is\s+([A-Za-z][A-Za-z'\-]{1,30})", re.IGNORECASE),
    re.compile(r"\bi(?:'m| am)\s+([A-Z][A-Za-z'\-]{1,30})\b"),
]


def extract_name_from_text(text: str):
    if not text:
        return None
    for pat in _NAME_PATTERNS:
        m = pat.search(text)
        if m:
            name = m.group(1).strip().title()
            name = re.split(r"[.,!?]", name)[0].strip()
            return name or None
    return None


# Auto-initialize tables when this module is imported
init_db()