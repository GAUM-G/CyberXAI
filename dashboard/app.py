"""
Dashboard app — serves the multi-section honeypot UI and all API endpoints.
"""

from __future__ import annotations

import json
import math
import os
import platform
import queue
import secrets
import smtplib
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from datetime import timedelta
from pathlib import Path
from typing import Any, Generator
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.logger import get_stream_queue, read_recent_events
from core.time_utils import IST, now_ist, now_ist_iso, to_ist
from dashboard.auth import (
    approve_user,
    auth_db_path,
    authenticate,
    begin_signup,
    cancel_signup,
    complete_signup,
    get_user,
    initialize_auth_store,
    list_dashboard_users,
    load_session_secret,
    remove_user,
    revoke_user_sessions,
    set_subadmin,
    validate_password,
    verify_signup,
)
from dashboard.email_delivery import mail_is_configured, send_signup_code
from dashboard.mail_config import harden_private_file_permissions

try:
    from flask import (
        Flask,
        Response,
        jsonify,
        redirect,
        render_template,
        request,
        session,
        url_for,
    )
    _FLASK_OK = True
except ImportError:
    _FLASK_OK = False

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

TEMPLATE_DIR = Path(__file__).parent / "templates"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
IDS_RESULTS_FILE = PROJECT_ROOT / "data" / "detections" / "hybrid_ids_results.jsonl"
IDS_RESULTS_API_URL = os.environ.get(
    "IDS_RESULTS_API_URL",
    "http://127.0.0.1:5000/api/ids-results",
).strip()
PORTAL_API_URL = os.environ.get(
    "PORTAL_API_URL",
    "http://127.0.0.1:5000",
).strip().rstrip("/")
EVENT_STATS_API_URL = f"{PORTAL_API_URL}/api/events/stats"
DASHBOARD_TOKEN_FILE = Path(
    os.environ.get(
        "DASHBOARD_INTERNAL_TOKEN_FILE",
        str(PROJECT_ROOT / "data" / "runtime" / "dashboard_internal.token"),
    )
).resolve()
IDS_ACTIVE_WINDOW_MINUTES = max(
    1,
    int(os.environ.get("IDS_ACTIVE_WINDOW_MINUTES", "15")),
)
_START_TIME = time.time()


_DASHBOARD_INTERNAL_TOKEN: str | None = None


def _dashboard_internal_token() -> str:
    """Load the credential shared only by the local dashboard and backend."""

    global _DASHBOARD_INTERNAL_TOKEN
    configured = os.environ.get("DASHBOARD_INTERNAL_TOKEN", "").strip()
    if configured:
        if len(configured) < 32:
            raise RuntimeError("DASHBOARD_INTERNAL_TOKEN must be at least 32 characters")
        return configured
    if _DASHBOARD_INTERNAL_TOKEN:
        return _DASHBOARD_INTERNAL_TOKEN

    DASHBOARD_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    generated = secrets.token_urlsafe(32)
    try:
        descriptor = os.open(
            DASHBOARD_TOKEN_FILE,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, "w", encoding="utf-8") as token_file:
            token_file.write(f"{generated}\n")

    if not harden_private_file_permissions(DASHBOARD_TOKEN_FILE):
        raise RuntimeError("Dashboard internal token permissions could not be secured")
    _DASHBOARD_INTERNAL_TOKEN = DASHBOARD_TOKEN_FILE.read_text(encoding="utf-8").strip()
    if len(_DASHBOARD_INTERNAL_TOKEN) < 32:
        raise RuntimeError("Dashboard internal token is missing or invalid")
    return _DASHBOARD_INTERNAL_TOKEN


def _all_events(limit: int = 2000) -> list[dict[str, Any]]:
    return read_recent_events(limit=limit)


def _central_event_stats() -> dict[str, Any] | None:
    """Read uncapped all-time counters from the centralized event store."""

    try:
        headers = {"X-Dashboard-Internal-Token": _dashboard_internal_token()}
        stats_request = urllib.request.Request(EVENT_STATS_API_URL, headers=headers)
        with urllib.request.urlopen(stats_request, timeout=2.0) as response:
            value = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, RuntimeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _read_ids_results_file(limit: int) -> list[dict[str, Any]]:
    if not IDS_RESULTS_FILE.is_file():
        return []
    records: list[dict[str, Any]] = []
    lines = IDS_RESULTS_FILE.read_text(encoding="utf-8").splitlines()
    for line in lines[-limit:]:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return list(reversed(records))


def _all_ids_results(limit: int = 2000) -> list[dict[str, Any]]:
    """Prefer centralized SQLite results and fall back to durable JSONL."""

    if IDS_RESULTS_API_URL:
        separator = "&" if "?" in IDS_RESULTS_API_URL else "?"
        url = f"{IDS_RESULTS_API_URL}{separator}limit={max(1, min(limit, 2000))}"
        try:
            headers = {"X-Dashboard-Internal-Token": _dashboard_internal_token()}
            ids_request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(ids_request, timeout=2.0) as response:
                value = json.loads(response.read().decode("utf-8"))
            results = value.get("results") if isinstance(value, dict) else None
            if isinstance(results, list):
                return [item for item in results if isinstance(item, dict)]
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
            pass

    return _read_ids_results_file(limit)


def _extract_credentials(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    creds: list[dict[str, Any]] = []
    seen: set[str] = set()
    for e in events:
        payload = e.get("payload")
        username = password = None
        if isinstance(payload, dict):
            username = payload.get("username") or payload.get("user")
            password = payload.get("password") or payload.get("pass")
        elif isinstance(payload, str) and "username=" in payload:
            parts = dict(p.split("=", 1) for p in payload.split("&") if "=" in p)
            username = parts.get("username")
            password = parts.get("password")
        if username and password:
            key = f"{e.get('service')}:{username}:{password}"
            if key not in seen:
                seen.add(key)
                creds.append({
                    "timestamp": e.get("timestamp", ""),
                    "source_ip": e.get("source_ip", ""),
                    "service": e.get("service", ""),
                    "username": username,
                    "password": password,
                    "attack_type": e.get("attack_type", ""),
                    "severity": e.get("severity", "info"),
                })
    return creds


def _compute_stats(events: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(events)
    by_service: dict[str, int] = defaultdict(int)
    by_attack: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    unique_ips: set[str] = set()
    for e in events:
        by_service[e.get("service", "unknown")] += 1
        by_attack[e.get("attack_type", "unknown")] += 1
        by_severity[e.get("severity", "info")] += 1
        ip = e.get("source_ip", "")
        if ip:
            unique_ips.add(ip)
    threats = by_severity.get("warning", 0) + by_severity.get("critical", 0)
    return {
        "total_events": total,
        "unique_ips": len(unique_ips),
        "threats_detected": threats,
        "by_service": dict(by_service),
        "by_attack": dict(by_attack),
        "by_severity": dict(by_severity),
    }


def _parse_ids_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ids_result_time(result: dict[str, Any]) -> datetime | None:
    return _parse_ids_datetime(result.get("processed_at")) or _parse_ids_datetime(
        result.get("timestamp")
    )


def _finite_confidences(results: list[dict[str, Any]]) -> list[float]:
    values: list[float] = []
    for result in results:
        value = result.get("confidence")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        confidence = float(value)
        if math.isfinite(confidence):
            values.append(max(0.0, min(confidence, 1.0)))
    return values


def _compute_ids_stats(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_service: dict[str, int] = defaultdict(int)
    by_attack: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    by_threat_level: dict[str, int] = defaultdict(int)
    by_model: dict[str, int] = defaultdict(int)
    unique_ips: set[str] = set()
    severity_names = {
        "Low": "info",
        "Medium": "warning",
        "High": "warning",
        "Critical": "critical",
    }
    current_time = datetime.now(timezone.utc)
    active_cutoff = current_time - timedelta(minutes=IDS_ACTIVE_WINDOW_MINUTES)
    active_threats = 0
    critical_incidents = 0

    for result in results:
        by_service[result.get("service", "unknown")] += 1
        by_attack[result.get("attack_type", "unknown")] += 1
        level = str(result.get("threat_level", "Low"))
        by_severity[severity_names.get(level, "info")] += 1
        by_threat_level[level] += 1
        by_model[str(result.get("model_used", "unknown"))] += 1
        source_ip = str(result.get("source_ip", "")).strip()
        if source_ip:
            unique_ips.add(source_ip)
        if result.get("prediction") == "attack":
            if level == "Critical":
                critical_incidents += 1
            result_time = _ids_result_time(result)
            if result_time is not None and result_time >= active_cutoff:
                active_threats += 1

    confidences = _finite_confidences(results)

    return {
        "total_events": len(results),
        "unique_ips": len(unique_ips),
        "threats_detected": sum(
            1 for result in results if result.get("prediction") == "attack"
        ),
        "active_threats": active_threats,
        "critical_incidents": critical_incidents,
        "average_confidence": (
            round(sum(confidences) / len(confidences), 4)
            if confidences
            else None
        ),
        "active_window_minutes": IDS_ACTIVE_WINDOW_MINUTES,
        "by_service": dict(by_service),
        "by_attack": dict(by_attack),
        "by_severity": dict(by_severity),
        "by_threat_level": dict(by_threat_level),
        "by_model": dict(by_model),
    }


def _ids_service_stats(
    results: list[dict[str, Any]],
    *,
    now: datetime | None = None,
    active_window_minutes: int = IDS_ACTIVE_WINDOW_MINUTES,
) -> list[dict[str, Any]]:
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    else:
        current_time = current_time.astimezone(timezone.utc)
    active_cutoff = current_time - timedelta(minutes=max(1, active_window_minutes))
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        grouped[str(result.get("service", "unknown"))].append(result)

    preferred = ["ssh", "ftp", "http"]
    service_names = [service for service in preferred if service in grouped]
    service_names += sorted(service for service in grouped if service not in preferred)
    rows: list[dict[str, Any]] = []
    for service in service_names:
        service_results = grouped[service]
        attacks = [
            result
            for result in service_results
            if result.get("prediction") == "attack"
        ]
        active = sum(
            1
            for result in attacks
            if (
                (result_time := _ids_result_time(result)) is not None
                and result_time >= active_cutoff
            )
        )
        confidences = _finite_confidences(service_results)
        rows.append(
            {
                "service": service,
                "total_results": len(service_results),
                "attacks": len(attacks),
                "active_threats": active,
                "critical": sum(
                    1
                    for result in attacks
                    if result.get("threat_level") == "Critical"
                ),
                "average_confidence": (
                    round(sum(confidences) / len(confidences), 4)
                    if confidences
                    else None
                ),
            }
        )
    return rows


def _ids_filter_options(results: list[dict[str, Any]]) -> dict[str, list[str]]:
    def _values(field: str) -> list[str]:
        return sorted(
            {
                str(result.get(field, "")).strip()
                for result in results
                if str(result.get(field, "")).strip()
            }
        )

    return {
        "services": _values("service"),
        "attack_types": _values("attack_type"),
        "threat_levels": _values("threat_level"),
        "models": _values("model_used"),
    }


def _port_scan_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Return a stable dashboard summary even when the scan row is buried."""

    scans = [event for event in events if event.get("attack_type") == "port_scanning"]
    if not scans:
        return {"port_scans_detected": 0, "latest_port_scan": None}

    latest = scans[0]
    payload = latest.get("payload") if isinstance(latest.get("payload"), dict) else {}
    metadata = latest.get("metadata") if isinstance(latest.get("metadata"), dict) else {}
    observed_ports = payload.get("observed_ports") or metadata.get("observed_ports") or []

    return {
        "port_scans_detected": len(scans),
        "latest_port_scan": {
            "timestamp": latest.get("timestamp", ""),
            "source_ip": latest.get("source_ip", ""),
            "service": latest.get("service", ""),
            "event": latest.get("event", ""),
            "attack_type": latest.get("attack_type", ""),
            "severity": latest.get("severity", "warning"),
            "status": latest.get("status", "detected"),
            "observed_ports": observed_ports,
        },
    }


def _xai_alerts(events: list[dict[str, Any]], limit: int = 50) -> list[dict[str, Any]]:
    alerts = [e for e in events if e.get("severity") in ("warning", "critical")]
    return alerts[:limit]


def _xai_summary(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    critical = sum(1 for e in alerts if e.get("severity") == "critical")
    warning = sum(1 for e in alerts if e.get("severity") == "warning")
    by_attack: dict[str, int] = defaultdict(int)
    by_service: dict[str, int] = defaultdict(int)
    for e in alerts:
        by_attack[e.get("attack_type", "unknown")] += 1
        by_service[e.get("service", "unknown")] += 1
    return {
        "total_alerts": len(alerts),
        "critical": critical,
        "warning": warning,
        "by_attack": dict(by_attack),
        "by_service": dict(by_service),
    }


def _xai_payload(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "generated_at": now_ist_iso(),
        "summary": _xai_summary(alerts),
        "alerts": [
            {
                "timestamp": e.get("timestamp", ""),
                "source_ip": e.get("source_ip", ""),
                "service": e.get("service", ""),
                "attack_type": e.get("attack_type", ""),
                "severity": e.get("severity", ""),
                "event": e.get("event", ""),
                "payload": e.get("payload", ""),
            }
            for e in alerts
        ],
    }


def _send_webhook_payload(url: str, payload: dict[str, Any]) -> tuple[int, str]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.getcode(), resp.read().decode("utf-8")


def _system_stats() -> dict[str, Any]:
    uptime_s = int(time.time() - _START_TIME)
    h, rem = divmod(uptime_s, 3600)
    m, s = divmod(rem, 60)
    uptime_str = f"{h:02d}:{m:02d}:{s:02d}"
    if _PSUTIL:
        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory()
        net = psutil.net_connections(kind="inet")
        active_conns = len([c for c in net if c.status == "ESTABLISHED"])
        return {
            "uptime": uptime_str,
            "cpu_percent": cpu,
            "ram_percent": ram.percent,
            "ram_used_gb": round(ram.used / 1e9, 2),
            "ram_total_gb": round(ram.total / 1e9, 2),
            "active_connections": active_conns,
            "platform": platform.system(),
            "python": platform.python_version(),
            "psutil_available": True,
        }
    return {
        "uptime": uptime_str, "cpu_percent": 0, "ram_percent": 0,
        "ram_used_gb": 0, "ram_total_gb": 0, "active_connections": 0,
        "platform": platform.system(), "python": platform.python_version(),
        "psutil_available": False,
    }


def _timeline(events: list[dict[str, Any]], buckets: int = 24) -> list[dict[str, Any]]:
    if not events:
        return []
    chron = list(reversed(events))
    try:
        t_start = datetime.fromisoformat(chron[0]["timestamp"].replace("Z", "+00:00")).timestamp()
        t_end   = datetime.fromisoformat(chron[-1]["timestamp"].replace("Z", "+00:00")).timestamp()
    except Exception:
        return []
    span = max(t_end - t_start, 1)
    bucket_size = span / buckets
    result = []
    for i in range(buckets):
        t0, t1 = t_start + i * bucket_size, t_start + (i + 1) * bucket_size
        bucket_events = []
        for e in chron:
            try:
                et = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp()
                if t0 <= et < t1:
                    bucket_events.append(e)
            except Exception:
                continue
        threats = sum(
            1
            for e in bucket_events
            if (
                e.get("prediction") == "attack"
                if "prediction" in e
                else e.get("severity") in ("warning", "critical")
            )
        )
        result.append({
            "label": datetime.fromtimestamp(t0, tz=IST).strftime("%H:%M:%S"),
            "total": len(bucket_events),
            "threats": threats,
        })
    return result


def _ordered_services(events: list[dict[str, Any]]) -> list[str]:
    preferred = ["ssh", "ftp", "http", "website"]
    seen = {e.get("service", "") for e in events if e.get("service")}
    ordered = [svc for svc in preferred if svc in seen]
    ordered += sorted(svc for svc in seen if svc not in preferred)
    return ordered or preferred[:3]


def create_dashboard_app(
    *, auth_path: Path | None = None, session_secret: str | None = None
) -> "Flask":
    if not _FLASK_OK:
        raise RuntimeError("Flask required.")
    app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
    account_db = (auth_path or auth_db_path()).resolve()
    initialize_auth_store(account_db)
    app.config.update(
        SECRET_KEY=session_secret or load_session_secret(),
        SESSION_COOKIE_NAME="dashboard_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("DASHBOARD_COOKIE_SECURE", "").lower()
        in {"1", "true", "yes"},
        SESSION_REFRESH_EACH_REQUEST=False,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=1024 * 1024,
    )

    @app.before_request
    def require_analyst_login() -> Any:
        if request.endpoint in {
            "login", "signup", "verify_signup_route", "resend_signup_code", "set_signup_password"
        }:
            return None
        user_id = session.get("analyst_user_id")
        version = session.get("auth_version")
        user = get_user(account_db, user_id) if type(user_id) is int else None
        if not user or user["auth_version"] != version:
            if user_id is not None or version is not None:
                session.clear()
            if request.path.startswith("/api/") or request.path == "/stream":
                return jsonify({"error": "Dashboard login required"}), 401
            if request.endpoint == "index" and request.method == "GET":
                token = session.setdefault("login_csrf", secrets.token_urlsafe(32))
                return render_template("login.html", csrf_token=token)
            return redirect(url_for("login"))
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            submitted = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not expected or not secrets.compare_digest(submitted, expected):
                return jsonify({"error": "Invalid CSRF token"}), 403
        return None

    @app.after_request
    def secure_response(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        if request.method == "GET":
            token = session.setdefault("login_csrf", secrets.token_urlsafe(32))
            return render_template(
                "login.html", csrf_token=token,
                registered=request.args.get("registered", ""),
            )
        submitted = request.form.get("csrf_token", "")
        expected = session.get("login_csrf", "")
        if not expected or not secrets.compare_digest(submitted, expected):
            fresh_token = secrets.token_urlsafe(32)
            session["login_csrf"] = fresh_token
            return render_template(
                "login.html", csrf_token=fresh_token, stale_form=True,
            ), 403
        email = request.form.get("email", "")[:128]
        password = request.form.get("password", "")
        if len(password.encode("utf-8")) > 1024:
            return render_template(
                "login.html", csrf_token=expected, error="Invalid Gmail or password."
            ), 401
        user, limited, pending = authenticate(
            account_db, email, password, request.remote_addr or "unknown"
        )
        if not user:
            return render_template(
                "login.html",
                csrf_token=expected,
                pending=pending,
                error="Too many attempts. Try again in 15 minutes."
                if limited else None if pending else "Invalid Gmail or password.",
            ), 429 if limited else 401
        session.clear()
        session["analyst_user_id"] = user["id"]
        session["auth_version"] = user["auth_version"]
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True
        return redirect(url_for("index"))

    @app.route("/signup", methods=["GET", "POST"])
    def signup() -> Any:
        token = session.setdefault("login_csrf", secrets.token_urlsafe(32))
        if request.method == "GET":
            return render_template("signup.html", csrf_token=token)
        submitted = request.form.get("csrf_token", "")
        if not secrets.compare_digest(submitted, token):
            return jsonify({"error": "Invalid CSRF token"}), 403
        if not mail_is_configured():
            return render_template(
                "signup.html", csrf_token=token,
                error="OTP sender is not ready. Configure both Gmail sender values "
                      "in the protected mail file or environment. "
                      "This is one-time administrator setup.",
            ), 503
        try:
            email, code = begin_signup(
                account_db,
                request.form.get("email", "")[:128],
                app.config["SECRET_KEY"],
                request.remote_addr or "unknown",
            )
        except ValueError as exc:
            return render_template("signup.html", csrf_token=token, error=str(exc)), 400
        try:
            send_signup_code(email, code)
        except smtplib.SMTPAuthenticationError:
            cancel_signup(account_db, email, code, app.config["SECRET_KEY"])
            app.logger.warning("Dashboard signup email delivery failed: SMTPAuthenticationError")
            return render_template(
                "signup.html", csrf_token=token,
                error="Gmail rejected the sender credential. Check the protected Gmail app password.",
            ), 502
        except (OSError, RuntimeError) as exc:
            cancel_signup(account_db, email, code, app.config["SECRET_KEY"])
            app.logger.warning("Dashboard signup email delivery failed: %s", type(exc).__name__)
            return render_template(
                "signup.html", csrf_token=token,
                error="Could not send the code. Check the protected Gmail sender configuration and try again.",
            ), 502
        session.pop("verified_signup_email", None)
        session.pop("verified_signup_at", None)
        session["pending_signup_email"] = email
        return redirect(url_for("verify_signup_route"))

    @app.route("/resend-otp", methods=["POST"])
    def resend_signup_code() -> Any:
        email = session.get("pending_signup_email")
        if not email:
            return redirect(url_for("signup"))
        token = session.get("login_csrf", "")
        if not token or not secrets.compare_digest(request.form.get("csrf_token", ""), token):
            return jsonify({"error": "Invalid CSRF token"}), 403
        try:
            email, code = begin_signup(
                account_db, email, app.config["SECRET_KEY"], request.remote_addr or "unknown"
            )
        except ValueError as exc:
            return render_template(
                "verify_signup.html", csrf_token=token, email=email, error=str(exc)
            ), 429
        try:
            send_signup_code(email, code)
        except (OSError, RuntimeError) as exc:
            cancel_signup(account_db, email, code, app.config["SECRET_KEY"])
            app.logger.warning("Dashboard OTP resend failed: %s", type(exc).__name__)
            return render_template(
                "verify_signup.html", csrf_token=token, email=email,
                error="Could not resend the code. Check Gmail sender configuration.",
            ), 502
        return render_template(
            "verify_signup.html", csrf_token=token, email=email,
            message="A new code was emailed. The previous code is no longer valid.",
        )

    @app.route("/verify-signup", methods=["GET", "POST"])
    def verify_signup_route() -> Any:
        email = session.get("pending_signup_email")
        if not email:
            return redirect(url_for("signup"))
        token = session.setdefault("login_csrf", secrets.token_urlsafe(32))
        if request.method == "GET":
            return render_template("verify_signup.html", csrf_token=token, email=email)
        submitted = request.form.get("csrf_token", "")
        if not secrets.compare_digest(submitted, token):
            return jsonify({"error": "Invalid CSRF token"}), 403
        valid = verify_signup(
            account_db, email, request.form.get("otp", ""), app.config["SECRET_KEY"]
        )
        if not valid:
            return render_template(
                "verify_signup.html", csrf_token=token, email=email,
                error="Invalid or expired code. Check your email or request a new code.",
            ), 400
        session.pop("pending_signup_email", None)
        session["verified_signup_email"] = email
        session["verified_signup_at"] = int(time.time())
        return redirect(url_for("set_signup_password"))

    @app.route("/set-password", methods=["GET", "POST"])
    def set_signup_password() -> Any:
        email = session.get("verified_signup_email")
        verified_at = session.get("verified_signup_at")
        if not email or type(verified_at) is not int or time.time() - verified_at > 600:
            session.pop("verified_signup_email", None)
            session.pop("verified_signup_at", None)
            return redirect(url_for("signup"))
        token = session.setdefault("login_csrf", secrets.token_urlsafe(32))
        if request.method == "GET":
            return render_template("set_password.html", csrf_token=token, email=email)
        if not secrets.compare_digest(request.form.get("csrf_token", ""), token):
            return jsonify({"error": "Invalid CSRF token"}), 403
        password = request.form.get("password", "")
        if password != request.form.get("confirm_password", ""):
            return render_template(
                "set_password.html", csrf_token=token, email=email,
                error="Passwords do not match.",
            ), 400
        try:
            validate_password(password)
            created = complete_signup(account_db, email, password)
        except ValueError as exc:
            return render_template(
                "set_password.html", csrf_token=token, email=email, error=str(exc)
            ), 400
        if not created:
            return render_template(
                "set_password.html", csrf_token=token, email=email,
                error="Account could not be created. Please sign in if already registered.",
            ), 400
        session.pop("verified_signup_email", None)
        session.pop("verified_signup_at", None)
        return redirect(url_for("login", registered=created))

    @app.route("/admin/users", methods=["GET"])
    def admin_users() -> Any:
        manager = get_user(account_db, session["analyst_user_id"])
        if not (manager["is_admin"] or manager["is_subadmin"]):
            return jsonify({"error": "Manager access required"}), 403
        return render_template(
            "admin_users.html", csrf_token=session["csrf_token"],
            users=list_dashboard_users(account_db), manager=manager,
        )

    @app.route("/admin/users/<int:user_id>/approve", methods=["POST"])
    def admin_approve_user(user_id: int) -> Any:
        manager = get_user(account_db, session["analyst_user_id"])
        if not (manager["is_admin"] or manager["is_subadmin"]):
            return jsonify({"error": "Manager access required"}), 403
        if not approve_user(account_db, manager["id"], user_id):
            return jsonify({"error": "Pending user not found"}), 404
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/subadmin", methods=["POST"])
    def admin_set_subadmin(user_id: int) -> Any:
        manager = get_user(account_db, session["analyst_user_id"])
        if not manager["is_admin"]:
            return jsonify({"error": "Administrator access required"}), 403
        action = request.form.get("action", "")
        if action not in {"grant", "revoke"}:
            return jsonify({"error": "Invalid role action"}), 400
        if not set_subadmin(account_db, manager["id"], user_id, action == "grant"):
            return jsonify({"error": "User cannot be changed"}), 403
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/remove", methods=["POST"])
    def admin_remove_user(user_id: int) -> Any:
        manager = get_user(account_db, session["analyst_user_id"])
        if not (manager["is_admin"] or manager["is_subadmin"]):
            return jsonify({"error": "Manager access required"}), 403
        if not remove_user(account_db, manager["id"], user_id):
            return jsonify({"error": "User cannot be removed"}), 403
        return redirect(url_for("admin_users"))

    @app.route("/logout", methods=["POST"])
    def logout() -> Any:
        revoke_user_sessions(account_db, session["analyst_user_id"])
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    def index() -> Any:
        user = get_user(account_db, session["analyst_user_id"])
        return render_template(
            "index.html",
            csrf_token=session["csrf_token"],
            dashboard_username=user["email"],
            dashboard_can_manage=bool(user["is_admin"] or user["is_subadmin"]),
        )

    def proxy_backend(path: str) -> Response:
        """Relay allow-listed analyst calls through the localhost dashboard."""

        query = request.query_string.decode("ascii", errors="ignore")
        target = f"{PORTAL_API_URL}{path}"
        if query:
            target = f"{target}?{query}"
        headers = {
            "Accept": "application/json",
            "X-Dashboard-Internal-Token": _dashboard_internal_token(),
        }
        analyst = get_user(account_db, session["analyst_user_id"])
        if not analyst or analyst["auth_version"] != session.get("auth_version"):
            return jsonify({"error": "Dashboard login required"}), 401
        headers["X-Dashboard-Analyst-Id"] = str(analyst["id"])
        headers["X-Dashboard-Analyst-Email"] = analyst["email"]
        body = None
        if request.method == "POST":
            headers["Content-Type"] = "application/json"
            body = json.dumps(request.get_json(silent=True) or {}).encode("utf-8")
        backend_request = urllib.request.Request(
            target,
            data=body,
            headers=headers,
            method=request.method,
        )
        try:
            with urllib.request.urlopen(backend_request, timeout=3.0) as response:
                response_body = response.read()
                status = response.status
                content_type = response.headers.get("Content-Type", "application/json")
        except HTTPError as exc:
            response_body = exc.read()
            status = exc.code
            content_type = exc.headers.get("Content-Type", "application/json")
        except (URLError, TimeoutError, OSError):
            return Response(
                json.dumps({"error": "Defender data service is unavailable"}),
                status=502,
                content_type="application/json",
            )
        return Response(response_body, status=status, content_type=content_type)

    @app.route("/api/analyst-feedback")
    @app.route("/api/analyst-feedback/latest")
    @app.route("/api/analyst-feedback/stats")
    def proxy_analyst_feedback() -> Response:
        return proxy_backend(request.path)

    @app.route("/api/analyst-feedback/<event_id>", methods=["GET", "POST"])
    def proxy_analyst_event(event_id: str) -> Response:
        safe_event_id = urllib.parse.quote(event_id, safe="")
        return proxy_backend(f"/api/analyst-feedback/{safe_event_id}")

    @app.route("/api/ips/safety")
    @app.route("/api/ips/status")
    @app.route("/api/ips/recommendations")
    @app.route("/api/ips/actions", methods=["GET", "POST"])
    def proxy_ips() -> Response:
        return proxy_backend(request.path)

    @app.route("/api/monitor")
    def api_monitor() -> Any:
        events = _all_events(2000)
        stats = _compute_stats(events)
        central_stats = _central_event_stats()
        if central_stats is not None:
            by_severity = central_stats.get("by_severity")
            if isinstance(by_severity, dict):
                stats["by_severity"] = by_severity
                stats["threats_detected"] = int(by_severity.get("warning", 0)) + int(
                    by_severity.get("critical", 0)
                )
            for local_name, central_name in (
                ("total_events", "total_events"),
                ("unique_ips", "unique_ips"),
                ("by_service", "by_service"),
                ("by_attack", "by_attack_type"),
            ):
                value = central_stats.get(central_name)
                if isinstance(value, (int, dict)) and not isinstance(value, bool):
                    stats[local_name] = value
        sys_stats = _system_stats()
        port_scan_stats = _port_scan_summary(events)
        return jsonify({
            **stats,
            **sys_stats,
            **port_scan_stats,
            "recent_events": events[:100],
        })

    @app.route("/api/honeypot")
    def api_honeypot() -> Any:
        events = _all_events(2000)
        services: dict[str, dict] = {}
        for svc in _ordered_services(events):
            svc_events = [e for e in events if e.get("service") == svc]
            services[svc] = {
                "total": len(svc_events),
                "threats": sum(1 for e in svc_events if e.get("severity") in ("warning", "critical")),
                "recent": svc_events[:100],
            }
        credentials = _extract_credentials(events)
        return jsonify({"services": services, "credentials": credentials[:100]})

    @app.route("/api/credentials")
    def api_credentials() -> Any:
        events = _all_events(2000)
        return jsonify(_extract_credentials(events))

    @app.route("/api/ids")
    def api_ids() -> Any:
        results = _all_ids_results(2000)
        stats = _compute_ids_stats(results)
        service_stats = _ids_service_stats(results)
        timeline = _timeline(results, buckets=24)
        ip_counts: dict[str, int] = defaultdict(int)
        threat_results = [
            result for result in results if result.get("prediction") == "attack"
        ]
        for e in threat_results or results:
            ip = str(e.get("source_ip", "")).strip()
            if ip:
                ip_counts[ip] += 1
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        return jsonify({
            "source": "hybrid_ids_results",
            "stats": stats,
            "timeline": timeline,
            "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
            "recent_results": results[:100],
            "service_stats": service_stats,
            "critical_incidents": [
                result
                for result in threat_results
                if result.get("threat_level") == "Critical"
            ][:20],
            "filter_options": _ids_filter_options(results),
        })

    @app.route("/api/agents")
    def api_agents() -> Any:
        results = _all_ids_results(2000)
        analyzed = [
            result
            for result in results
            if isinstance(result.get("agents"), dict)
        ]
        latest = analyzed[0].get("agents") if analyzed else None
        actions: dict[str, int] = defaultdict(int)
        correlated_campaigns: set[str] = set()
        escalations = 0
        for result in analyzed:
            agents = result["agents"]
            response_agent = agents.get("response")
            correlation_agent = agents.get("correlation")
            severity_agent = agents.get("severity")
            if isinstance(response_agent, dict):
                actions[str(response_agent.get("recommended_action") or "unknown")] += 1
            if isinstance(correlation_agent, dict) and correlation_agent.get("correlated"):
                correlation_id = str(correlation_agent.get("correlation_id") or "")
                if correlation_id:
                    correlated_campaigns.add(correlation_id)
            if isinstance(severity_agent, dict) and severity_agent.get("escalated"):
                escalations += 1
        return jsonify(
            {
                "source": "step22_intelligent_agents",
                "agent_pipeline_version": (
                    latest.get("agent_pipeline_version")
                    if isinstance(latest, dict)
                    else None
                ),
                "analyzed_results": len(analyzed),
                "correlated_campaigns": len(correlated_campaigns),
                "severity_escalations": escalations,
                "response_recommendations": dict(sorted(actions.items())),
                "latest": latest,
                "generated_at": now_ist_iso(),
            }
        )

    @app.route("/api/xai/alerts")
    def api_xai_alerts() -> Any:
        events = _all_events(2000)
        return jsonify({"alerts": _xai_alerts(events, limit=50)})

    @app.route("/api/xai/report", methods=["POST"])
    def api_xai_report() -> Any:
        events = _all_events(2000)
        alerts = _xai_alerts(events, limit=30)
        if not alerts:
            return jsonify({"status": "empty", "message": "No warning or critical alerts found."}), 400
        payload = _xai_payload(alerts)
        webhook_url = "http://localhost:5678/webhook/xai-honeypot"
        try:
            status_code, response_body = _send_webhook_payload(webhook_url, payload)
            return jsonify({
                "status": "sent",
                "message": f"Delivered {len(alerts)} XAI alerts to n8n.",
                "webhook_status": status_code,
                "webhook_response": response_body,
            })
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            return jsonify({"status": "error", "message": "Webhook returned an HTTP error.", "code": exc.code, "detail": detail}), 502
        except URLError as exc:
            return jsonify({"status": "error", "message": "Unable to connect to webhook.", "detail": str(exc.reason)}), 502
        except Exception as exc:
            return jsonify({"status": "error", "message": "Unexpected error sending XAI report.", "detail": str(exc)}), 500

    @app.route("/api/report")
    def api_report() -> Any:
        events = _all_events(2000)
        stats = _compute_stats(events)
        credentials = _extract_credentials(events)
        return jsonify({
            "generated_at": now_ist_iso(),
            "summary": stats,
            "credentials_captured": credentials,
            "recent_threats": [e for e in events if e.get("severity") in ("warning", "critical")][:50],
        })

    @app.route("/api/report/download")
    def api_report_download() -> Any:
        events = _all_events(2000)
        stats = _compute_stats(events)
        credentials = _extract_credentials(events)
        current_ist = now_ist()
        now = current_ist.strftime("%Y-%m-%d %H:%M:%S IST")
        lines = [
            "=" * 62,
            "  HONEYPOT SECURITY FRAMEWORK — THREAT REPORT",
            f"  Generated : {now}",
            "=" * 62,
            "",
            f"  Total Events        : {stats['total_events']}",
            f"  Threats Detected    : {stats['threats_detected']}",
            f"  Unique Attacker IPs : {stats['unique_ips']}",
            "",
            "── EVENTS BY SERVICE ────────────────────────────────────",
        ]
        for svc, cnt in stats.get("by_service", {}).items():
            lines.append(f"  {svc.upper():8s}: {cnt}")
        lines += ["", "── ATTACK TYPES ─────────────────────────────────────────"]
        for atk, cnt in sorted(stats.get("by_attack", {}).items(), key=lambda x: -x[1]):
            if atk not in ("web_activity", "connection_probe", "command_activity"):
                lines.append(f"  {atk:35s}: {cnt}")
        lines += ["", "── CAPTURED CREDENTIALS ─────────────────────────────────"]
        if credentials:
            lines.append(f"  {'Timestamp':20s} {'IP':15s} {'Svc':5s} {'Username':20s} {'Password'}")
            lines.append("  " + "─" * 75)
            for c in credentials:
                try:
                    ts = to_ist(c["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                except (TypeError, ValueError):
                    ts = str(c.get("timestamp", ""))[:19].replace("T", " ")
                lines.append(f"  {ts:20s} {c['source_ip']:15s} {c['service']:5s} {c['username']:20s} {c['password']}")
        else:
            lines.append("  No credentials captured yet.")
        lines += ["", "── RECENT THREATS ───────────────────────────────────────"]
        for e in [x for x in events if x.get("severity") in ("warning", "critical")][:30]:
            try:
                ts = to_ist(e.get("timestamp")).strftime("%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError):
                ts = str(e.get("timestamp", ""))[:19].replace("T", " ")
            lines.append(f"  [{ts}] [{e.get('service','?'):4s}] {e.get('attack_type','?')}")
        lines += ["", "=" * 62, "  END OF REPORT", "=" * 62]
        fname = f"honeypot_report_{current_ist.strftime('%Y%m%d_%H%M%S')}.txt"
        return Response("\n".join(lines), mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})

    @app.route("/stream")
    def stream() -> Any:
        user_id = session["analyst_user_id"]
        auth_version = session["auth_version"]

        def _gen() -> Generator[str, None, None]:
            q = get_stream_queue()
            last_hb = time.time()
            while True:
                user = get_user(account_db, user_id)
                if not user or user["auth_version"] != auth_version:
                    return
                try:
                    ev = q.get(timeout=1.0)
                    user = get_user(account_db, user_id)
                    if not user or user["auth_version"] != auth_version:
                        return
                    yield f"data: {json.dumps(ev)}\n\n"
                except queue.Empty:
                    pass
                if time.time() - last_hb > 15:
                    yield ": heartbeat\n\n"
                    last_hb = time.time()
        return Response(_gen(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return app


def start_dashboard(host: str = "127.0.0.1", port: int = 5050) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("The defender dashboard must remain loopback-only")
    app = create_dashboard_app()
    print(f"[Dashboard] http://{host}:{port}")
    if not mail_is_configured():
        print("[Dashboard] Signup email is not configured: edit data/runtime/dashboard_mail.json")
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    start_dashboard()
