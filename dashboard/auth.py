"""Verified Gmail accounts for the private defender dashboard, never decoy users."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from werkzeug.security import check_password_hash, generate_password_hash

from dashboard.mail_config import load_mail_config


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "runtime" / "dashboard_users.db"
DEFAULT_SECRET_PATH = PROJECT_ROOT / "data" / "runtime" / "dashboard_session.key"
PASSWORD_METHOD = "pbkdf2:sha256:600000"
LOGIN_WINDOW_SECONDS = 15 * 60
MAX_LOGIN_FAILURES = 5
OTP_LIFETIME_SECONDS = 10 * 60
OTP_RESEND_SECONDS = 60
OTP_MAX_SENDS_PER_HOUR = 3
OTP_MAX_ATTEMPTS = 5
_GMAIL_RE = re.compile(r"[a-z0-9][a-z0-9.+_-]{0,63}@gmail\.com\Z")
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(24), method=PASSWORD_METHOD)


def auth_db_path() -> Path:
    return Path(os.environ.get("DASHBOARD_AUTH_DB", str(DEFAULT_DB_PATH))).resolve()


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(db_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(descriptor)
    connection = sqlite3.connect(db_path, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_auth_store(db_path: Path) -> None:
    with _connect(db_path) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_accounts (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                auth_version INTEGER NOT NULL DEFAULT 1,
                active INTEGER NOT NULL DEFAULT 1,
                verified_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                approval_status TEXT NOT NULL DEFAULT 'approved',
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_subadmin INTEGER NOT NULL DEFAULT 0,
                approved_by_id INTEGER,
                approved_at INTEGER
            )
        """)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(dashboard_accounts)")}
        for name, definition in (
            ("approval_status", "TEXT NOT NULL DEFAULT 'approved'"),
            ("is_admin", "INTEGER NOT NULL DEFAULT 0"),
            ("is_subadmin", "INTEGER NOT NULL DEFAULT 0"),
            ("approved_by_id", "INTEGER"),
            ("approved_at", "INTEGER"),
        ):
            if name not in columns:
                db.execute(f"ALTER TABLE dashboard_accounts ADD COLUMN {name} {definition}")
        db.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_account_sequence (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                last_id INTEGER NOT NULL
            )
        """)
        db.execute(
            "INSERT OR IGNORE INTO dashboard_account_sequence (singleton, last_id) "
            "SELECT 1, COALESCE(MAX(id), 0) FROM dashboard_accounts"
        )
        db.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_email_challenges (
                email TEXT PRIMARY KEY,
                otp_digest TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_sent_at INTEGER NOT NULL,
                first_sent_at INTEGER NOT NULL,
                send_count INTEGER NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_login_failures (
                email TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                first_attempt INTEGER NOT NULL,
                PRIMARY KEY (email, source_ip)
            )
        """)


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if not _GMAIL_RE.fullmatch(normalized):
        raise ValueError("Enter a valid @gmail.com address")
    return normalized


def validate_password(password: str) -> str:
    if len(password) < 12 or len(password.encode("utf-8")) > 1024:
        raise ValueError("Password must be at least 12 characters and at most 1024 bytes")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password needs an uppercase letter")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password needs a lowercase letter")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password needs a number")
    if not re.search(r"[^A-Za-z0-9\s]", password):
        raise ValueError("Password needs a special symbol")
    return password


def _next_account_id(db: sqlite3.Connection) -> int:
    """Never reuse removed IDs: an old signed cookie must not match a new user."""

    db.execute(
        "UPDATE dashboard_account_sequence "
        "SET last_id = MAX(last_id, COALESCE((SELECT MAX(id) FROM dashboard_accounts), 0)) + 1 "
        "WHERE singleton = 1"
    )
    return db.execute(
        "SELECT last_id FROM dashboard_account_sequence WHERE singleton = 1"
    ).fetchone()["last_id"]


def create_user(db_path: Path, email: str, password: str) -> None:
    """Trusted local recovery/bootstrap only; normal users sign up by email OTP."""

    normalized = normalize_email(email)
    password_hash = generate_password_hash(validate_password(password), method=PASSWORD_METHOD)
    initialize_auth_store(db_path)
    now = int(time.time())
    with _connect(db_path) as db:
        user_id = _next_account_id(db)
        db.execute(
            "INSERT INTO dashboard_accounts (id, email, password_hash, verified_at, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, normalized, password_hash, now, now),
        )


def begin_signup(db_path: Path, email: str, secret: str) -> tuple[str, str]:
    """Store only a keyed OTP digest; return (email, code) to the mailer."""

    normalized = normalize_email(email)
    now = int(time.time())
    initialize_auth_store(db_path)
    with _connect(db_path) as db:
        if db.execute("SELECT 1 FROM dashboard_accounts WHERE email = ?", (normalized,)).fetchone():
            raise ValueError("This Gmail is already registered. Please sign in.")
        old = db.execute(
            "SELECT otp_digest, last_sent_at, first_sent_at, send_count FROM dashboard_email_challenges "
            "WHERE email = ?", (normalized,)
        ).fetchone()
        if old and now - old["last_sent_at"] < OTP_RESEND_SECONDS:
            raise ValueError("Please wait one minute before requesting another code")
        if old and now - old["first_sent_at"] < 3600 and old["send_count"] >= OTP_MAX_SENDS_PER_HOUR:
            raise ValueError("Too many codes requested; try again in one hour")
    while True:
        code = f"{secrets.randbelow(1_000_000):06d}"
        digest = _otp_digest(secret, normalized, code)
        if not old or digest != old["otp_digest"]:
            break
    first_sent = old["first_sent_at"] if old and now - old["first_sent_at"] < 3600 else now
    send_count = old["send_count"] + 1 if old and first_sent != now else 1
    with _connect(db_path) as db:
        db.execute("""
            INSERT INTO dashboard_email_challenges
                (email, otp_digest, expires_at, attempts,
                 last_sent_at, first_sent_at, send_count)
            VALUES (?, ?, ?, 0, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                otp_digest = excluded.otp_digest,
                expires_at = excluded.expires_at,
                attempts = 0,
                last_sent_at = excluded.last_sent_at,
                first_sent_at = excluded.first_sent_at,
                send_count = excluded.send_count
        """, (normalized, digest, now + OTP_LIFETIME_SECONDS,
              now, first_sent, send_count))
    return normalized, code


def cancel_signup(db_path: Path, email: str, code: str, secret: str) -> None:
    """Remove only the challenge whose mail failed; never remove a newer code."""

    with _connect(db_path) as db:
        db.execute(
            "DELETE FROM dashboard_email_challenges WHERE email = ? AND otp_digest = ?",
            (email, _otp_digest(secret, email, code)),
        )


def _otp_digest(secret: str, email: str, code: str) -> str:
    return hmac.new(
        secret.encode("utf-8"), f"signup:{email}:{code}".encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_signup(db_path: Path, email: str, code: str, secret: str) -> bool:
    try:
        normalized = normalize_email(email)
    except ValueError:
        return False
    if not re.fullmatch(r"[0-9]{6}", code.strip()):
        return False
    now = int(time.time())
    with _connect(db_path) as db:
        challenge = db.execute(
            "SELECT * FROM dashboard_email_challenges WHERE email = ?", (normalized,)
        ).fetchone()
        if not challenge or challenge["expires_at"] < now or challenge["attempts"] >= OTP_MAX_ATTEMPTS:
            return False
        submitted = _otp_digest(secret, normalized, code.strip())
        if not hmac.compare_digest(submitted, challenge["otp_digest"]):
            db.execute(
                "UPDATE dashboard_email_challenges SET attempts = attempts + 1 WHERE email = ?",
                (normalized,),
            )
            return False
        db.execute("DELETE FROM dashboard_email_challenges WHERE email = ?", (normalized,))
        return True


def complete_signup(db_path: Path, email: str, password: str) -> str | None:
    """Called only after the Flask session proves this email's OTP was verified."""

    normalized = normalize_email(email)
    password_hash = generate_password_hash(validate_password(password), method=PASSWORD_METHOD)
    config = load_mail_config()
    now = int(time.time())
    try:
        with _connect(db_path) as db:
            user_id = _next_account_id(db)
            first_admin = bool(
                config and normalized == config.sender_gmail
                and not db.execute("SELECT 1 FROM dashboard_accounts WHERE is_admin = 1").fetchone()
            )
            status = "approved" if first_admin else "pending"
            db.execute(
                "INSERT INTO dashboard_accounts "
                "(id, email, password_hash, verified_at, created_at, approval_status, is_admin, approved_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, normalized, password_hash, now, now, status,
                 int(first_admin), now if first_admin else None),
            )
    except sqlite3.IntegrityError:
        return None
    return status


def list_pending_users(db_path: Path) -> list[dict[str, Any]]:
    with _connect(db_path) as db:
        rows = db.execute(
            "SELECT id, email, created_at FROM dashboard_accounts "
            "WHERE approval_status = 'pending' ORDER BY created_at, id"
        ).fetchall()
        return [dict(row) for row in rows]


def list_dashboard_users(db_path: Path) -> list[dict[str, Any]]:
    """Account metadata only; never return password hashes or OTPs to the UI."""

    with _connect(db_path) as db:
        rows = db.execute(
            "SELECT id, email, approval_status, active, is_admin, is_subadmin, created_at "
            "FROM dashboard_accounts ORDER BY created_at, id"
        ).fetchall()
        return [dict(row) for row in rows]


def approve_user(db_path: Path, admin_user_id: int, pending_user_id: int) -> bool:
    """Approval requires an active admin or subadmin, including outside HTTP."""

    now = int(time.time())
    with _connect(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        admin = db.execute(
            "SELECT 1 FROM dashboard_accounts WHERE id = ? AND (is_admin = 1 OR is_subadmin = 1) "
            "AND active = 1 AND approval_status = 'approved'",
            (admin_user_id,),
        ).fetchone()
        if not admin or admin_user_id == pending_user_id:
            return False
        result = db.execute(
            "UPDATE dashboard_accounts SET approval_status = 'approved', "
            "approved_by_id = ?, approved_at = ?, auth_version = auth_version + 1 "
            "WHERE id = ? AND approval_status = 'pending' AND active = 1",
            (admin_user_id, now, pending_user_id),
        )
        return result.rowcount == 1


def set_subadmin(db_path: Path, admin_user_id: int, target_user_id: int, enabled: bool) -> bool:
    """Only a full admin can change another approved user's delegated role."""

    with _connect(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        admin = db.execute(
            "SELECT 1 FROM dashboard_accounts WHERE id = ? AND is_admin = 1 "
            "AND active = 1 AND approval_status = 'approved'", (admin_user_id,),
        ).fetchone()
        if not admin or admin_user_id == target_user_id:
            return False
        result = db.execute(
            "UPDATE dashboard_accounts SET is_subadmin = ?, auth_version = auth_version + 1 "
            "WHERE id = ? AND is_admin = 0 AND active = 1 "
            "AND approval_status = 'approved' AND is_subadmin <> ?",
            (int(enabled), target_user_id, int(enabled)),
        )
        return result.rowcount == 1


def remove_user(db_path: Path, actor_user_id: int, target_user_id: int) -> bool:
    """Delete a non-admin account and invalidate its sessions immediately."""

    with _connect(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        actor = db.execute(
            "SELECT is_admin, is_subadmin FROM dashboard_accounts WHERE id = ? "
            "AND active = 1 AND approval_status = 'approved'", (actor_user_id,),
        ).fetchone()
        target = db.execute(
            "SELECT email, is_admin, is_subadmin FROM dashboard_accounts WHERE id = ?",
            (target_user_id,),
        ).fetchone()
        if (
            not actor or not target or actor_user_id == target_user_id
            or not (actor["is_admin"] or actor["is_subadmin"])
            or target["is_admin"]
            or (target["is_subadmin"] and not actor["is_admin"])
        ):
            return False
        db.execute("DELETE FROM dashboard_login_failures WHERE email = ?", (target["email"],))
        db.execute("DELETE FROM dashboard_email_challenges WHERE email = ?", (target["email"],))
        result = db.execute("DELETE FROM dashboard_accounts WHERE id = ?", (target_user_id,))
        return result.rowcount == 1


def promote_admin(db_path: Path, email: str) -> bool:
    """Trusted local recovery for an existing verified account."""

    normalized = normalize_email(email)
    initialize_auth_store(db_path)
    with _connect(db_path) as db:
        result = db.execute(
            "UPDATE dashboard_accounts SET is_admin = 1, is_subadmin = 0, active = 1, "
            "approval_status = 'approved', auth_version = auth_version + 1 "
            "WHERE email = ?", (normalized,),
        )
        return result.rowcount == 1


def reset_password(db_path: Path, email: str, password: str) -> bool:
    normalized = normalize_email(email)
    password_hash = generate_password_hash(validate_password(password), method=PASSWORD_METHOD)
    initialize_auth_store(db_path)
    with _connect(db_path) as db:
        result = db.execute(
            "UPDATE dashboard_accounts SET password_hash = ?, auth_version = auth_version + 1 "
            "WHERE email = ?", (password_hash, normalized)
        )
        if result.rowcount == 1:
            db.execute("DELETE FROM dashboard_login_failures WHERE email = ?", (normalized,))
        return result.rowcount == 1


def set_user_active(db_path: Path, email: str, active: bool) -> bool:
    normalized = normalize_email(email)
    initialize_auth_store(db_path)
    with _connect(db_path) as db:
        result = db.execute(
            "UPDATE dashboard_accounts SET active = ?, auth_version = auth_version + 1 "
            "WHERE email = ?", (int(active), normalized)
        )
        return result.rowcount == 1


def get_user(db_path: Path, user_id: int) -> dict[str, Any] | None:
    with _connect(db_path) as db:
        row = db.execute(
            "SELECT id, email, auth_version, is_admin, is_subadmin FROM dashboard_accounts "
            "WHERE id = ? AND active = 1 AND approval_status = 'approved'",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def authenticate(
    db_path: Path, email: str, password: str, source_ip: str
) -> tuple[dict[str, Any] | None, bool, bool]:
    """Return (verified user, rate_limited, awaiting_approval)."""

    try:
        normalized = normalize_email(email)
    except ValueError:
        normalized = "<invalid>"
    source_ip = source_ip[:64]
    now = int(time.time())
    with _connect(db_path) as db:
        db.execute(
            "DELETE FROM dashboard_login_failures WHERE first_attempt < ?",
            (now - LOGIN_WINDOW_SECONDS,),
        )
        failure = db.execute(
            "SELECT attempts FROM dashboard_login_failures WHERE email = ? AND source_ip = ?",
            (normalized, source_ip),
        ).fetchone()
        if failure and failure["attempts"] >= MAX_LOGIN_FAILURES:
            return None, True, False
        row = db.execute(
            "SELECT id, email, password_hash, auth_version, approval_status FROM dashboard_accounts "
            "WHERE email = ? AND active = 1", (normalized,)
        ).fetchone()
        valid = check_password_hash(row["password_hash"] if row else _DUMMY_HASH, password)
        if row and valid:
            db.execute(
                "DELETE FROM dashboard_login_failures WHERE email = ? AND source_ip = ?",
                (normalized, source_ip),
            )
            if row["approval_status"] == "pending":
                return None, False, True
            if row["approval_status"] == "approved":
                return {key: row[key] for key in ("id", "email", "auth_version")}, False, False
        db.execute("""
            INSERT INTO dashboard_login_failures (email, source_ip, attempts, first_attempt)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(email, source_ip) DO UPDATE SET attempts = attempts + 1
        """, (normalized, source_ip, now))
        return None, False, False


def revoke_user_sessions(db_path: Path, user_id: int) -> None:
    with _connect(db_path) as db:
        db.execute(
            "UPDATE dashboard_accounts SET auth_version = auth_version + 1 WHERE id = ?",
            (user_id,),
        )


def load_session_secret(secret_path: Path | None = None) -> str:
    configured = os.environ.get("DASHBOARD_SECRET_KEY", "").strip()
    if configured:
        if len(configured) < 32 or configured == "replace_with_your_private_local_value":
            raise RuntimeError("DASHBOARD_SECRET_KEY must be a private random value of at least 32 characters")
        return configured
    path = (secret_path or DEFAULT_SECRET_PATH).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, "w", encoding="utf-8") as secret_file:
            secret_file.write(secrets.token_urlsafe(48))
    secret = path.read_text(encoding="utf-8").strip()
    if len(secret) < 32:
        raise RuntimeError("Dashboard session secret is missing or invalid")
    return secret
