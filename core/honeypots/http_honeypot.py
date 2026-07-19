"""
HTTP Honeypot
=============
A Flask app that pretends to be a corporate login portal.
Detects and logs:
  - SQL injection attempts  (login form, search)
  - XSS attempts            (search, upload)
  - Directory traversal     (any path)
  - Brute-force login       (rate of login attempts)
  - General web activity

Port: 8080 (configurable)
"""

from __future__ import annotations

import re
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any
from uuid import uuid4

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.logger import log_event

try:
    from flask import Flask, g, jsonify, render_template_string, request
    _FLASK_OK = True
except ImportError:
    _FLASK_OK = False
    print("[HTTP] Flask not installed. Run: pip install flask")


# --------------------------------------------------------------------------- #
#  Attack pattern regexes                                                       #
# --------------------------------------------------------------------------- #

_SQLI = [re.compile(p, re.IGNORECASE) for p in (
    r"(union\s+select)",
    r"(or\s+1\s*=\s*1)",
    r"(drop\s+table)",
    r"(--|#|/\*)",
    r"(information_schema)",
    r"(sleep\s*\()",
    r"(benchmark\s*\()",
    r"('\s*or\s*')",
)]

_XSS = [re.compile(p, re.IGNORECASE) for p in (
    r"<script",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"<img[^>]+src",
    r"document\.cookie",
)]

_DIRSCAN = [re.compile(p, re.IGNORECASE) for p in (
    r"\.\./",
    r"etc/passwd",
    r"wp-admin",
    r"\.git",
    r"phpmyadmin",
    r"\.env",
    r"config\.php",
    r"web\.config",
)]


def _detect_attacks(text: str) -> list[str]:
    found = []
    if any(p.search(text) for p in _SQLI):
        found.append("sql_injection")
    if any(p.search(text) for p in _XSS):
        found.append("xss")
    if any(p.search(text) for p in _DIRSCAN):
        found.append("directory_scanning")
    return found


# --------------------------------------------------------------------------- #
#  Login brute-force tracker                                                    #
# --------------------------------------------------------------------------- #

_login_history: dict[str, deque[float]] = defaultdict(deque)
_LOGIN_WINDOW = 60      # seconds
_LOGIN_THRESHOLD = 10   # attempts per window = brute force


# --------------------------------------------------------------------------- #
#  HTML templates (inline so the project stays self-contained)                 #
# --------------------------------------------------------------------------- #

_LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Company Portal - Login</title>
<style>
  body { font-family: Arial, sans-serif; background: #f0f2f5; display: flex;
         justify-content: center; align-items: center; height: 100vh; margin: 0; }
  .card { background: white; padding: 2rem; border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,.15); width: 320px; }
  h2 { margin: 0 0 1.5rem; color: #1a1a2e; text-align: center; }
  input { width: 100%; padding: .6rem; margin: .4rem 0 1rem;
          border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
  button { width: 100%; padding: .7rem; background: #2563eb;
           color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
  button:hover { background: #1d4ed8; }
  .error { color: #dc2626; font-size: .85rem; margin-top: .5rem; text-align: center; }
  a { color: #2563eb; text-decoration: none; font-size: .85rem; }
</style>
</head>
<body>
<div class="card">
  <h2>🏢 Company Portal</h2>
  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" placeholder="Enter username" autocomplete="off">
    <label>Password</label>
    <input type="password" name="password" placeholder="Enter password">
    <button type="submit">Sign In</button>
  </form>
  {% if error %}<p class="error">{{ error }}</p>{% endif %}
  <p style="text-align:center;margin-top:1rem"><a href="/forgot">Forgot password?</a></p>
</div>
</body>
</html>
"""

_PORTAL_HTML = """
<!DOCTYPE html>
<html>
<head><title>Company Portal</title></head>
<body>
<h1>Welcome to the Company Portal</h1>
<p>Internal systems — authorized access only.</p>
<ul>
  <li><a href="/login">Login</a></li>
  <li><a href="/search?q=">Search</a></li>
</ul>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
#  Flask app factory                                                            #
# --------------------------------------------------------------------------- #

def create_http_honeypot() -> "Flask":
    if not _FLASK_OK:
        raise RuntimeError("Flask is required.")

    app = Flask(__name__)

    @app.before_request
    def _assign_event_session() -> None:
        # One ID links all records generated while handling the same HTTP request.
        g.honeypot_session_id = str(uuid4())

    def _ip() -> str:
        return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")

    def _source_port() -> int | str | None:
        return request.environ.get("REMOTE_PORT")

    def _destination_port() -> int | str:
        return request.environ.get("SERVER_PORT", 8080)

    def _common_context(
        *,
        event_type: str,
        status: str,
        username: str | None = None,
    ) -> dict[str, Any]:
        return {
            "event_type": event_type,
            "protocol": "http",
            "source_port": _source_port(),
            "destination_port": _destination_port(),
            "username": username,
            "session_id": g.honeypot_session_id,
            "request_method": request.method,
            "request_path": request.path,
            "status": status,
        }


    def _headers() -> dict[str, str]:
        wanted = [
            "User-Agent",
            "Referer",
            "Origin",
            "Host",
            "X-Forwarded-For",
            "X-Real-Ip",
            "Accept",
            "Accept-Language",
            "Content-Type",
            "Content-Length",
            "Cookie",
            "Authorization",
        ]
        headers: dict[str, str] = {}
        for key in wanted:
            value = request.headers.get(key)
            if value:
                headers[key.lower()] = value
        return headers

    def _log_with_detection(route: str, payload: str, extra_meta: dict | None = None) -> None:
        ip = _ip()
        attacks = _detect_attacks(payload)

        # Generic activity log
        log_event(
            source_ip=ip,
            service="http",
            event=f"http_{route}_request",
            attack_type="web_activity",
            payload=payload[:500],
            metadata={**(extra_meta or {}), "route": route, "method": request.method, "path": request.path, "headers": _headers(), "query_string": request.query_string.decode("utf-8", errors="ignore")},
            severity="info",
            **_common_context(event_type="request", status="observed"),
        )

        # Specific attack logs
        for attack in attacks:
            log_event(
                source_ip=ip,
                service="http",
                event=f"http_{route}_{attack}",
                attack_type=attack,
                payload=payload[:500],
                metadata={**(extra_meta or {}), "route": route, "method": request.method, "path": request.path, "headers": _headers(), "query_string": request.query_string.decode("utf-8", errors="ignore")},
                severity="warning",
                **_common_context(event_type="attack", status="detected"),
            )

    # -------- routes --------------------------------------------------------

    @app.route("/", methods=["GET"])
    def index() -> Any:
        _log_with_detection("index", request.full_path)
        return render_template_string(_PORTAL_HTML)

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        ip = _ip()
        error = None

        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            payload = f"username={username}&password={password}"

            # Brute-force detection
            now = time.time()
            hist = _login_history[ip]
            hist.append(now)
            while hist and now - hist[0] > _LOGIN_WINDOW:
                hist.popleft()

            is_brute = len(hist) >= _LOGIN_THRESHOLD
            attacks = _detect_attacks(payload)

            log_event(
                source_ip=ip,
                service="http",
                event="http_login_bruteforce" if is_brute else "http_login_attempt",
                attack_type="http_bruteforce" if is_brute else "authentication_probe",
                payload=payload,
                metadata={
                    "username": username,
                    "password_length": len(password),
                    "attempt_count": len(hist),
                    "attacks_detected": attacks,
                    "headers": _headers(),
                    "method": request.method,
                    "path": request.path,
                },
                severity="warning" if (is_brute or attacks) else "info",
                **_common_context(
                    event_type="authentication",
                    status="failed",
                    username=username,
                ),
            )

            for attack in attacks:
                log_event(
                    source_ip=ip,
                    service="http",
                    event=f"http_login_{attack}",
                    attack_type=attack,
                    payload=payload,
                    metadata={"username": username, "headers": _headers(), "path": request.path},
                    severity="warning",
                    **_common_context(
                        event_type="attack",
                        status="detected",
                        username=username,
                    ),
                )

            error = "Invalid username or password."

        return render_template_string(_LOGIN_HTML, error=error)

    @app.route("/search", methods=["GET"])
    def search() -> Any:
        q = request.args.get("q", "")
        _log_with_detection("search", q, {"query_length": len(q)})
        return jsonify({"results": [], "query": q, "status": "ok"})

    @app.route("/admin", methods=["GET"])
    def admin() -> Any:
        _log_with_detection("admin", request.full_path, {"endpoint": "/admin"})
        return jsonify({"error": "Forbidden", "code": 403}), 403

    @app.route("/upload", methods=["GET", "POST"])
    def upload() -> Any:
        if request.method == "POST":
            f = request.files.get("file")
            fname = f.filename if f else "unknown"
            body = request.get_data(as_text=True)
            _log_with_detection("upload", f"filename={fname};body={body[:512]}", {"filename": fname, "body_preview": body[:512], "content_type": request.content_type})
            return jsonify({"status": "uploaded", "filename": fname})
        return jsonify({"status": "ready", "endpoint": "/upload"})

    @app.route("/forgot", methods=["GET"])
    def forgot() -> Any:
        _log_with_detection("forgot", request.full_path)
        return jsonify({"message": "Password reset email sent (not really)."})

    # Catch-all: log every other path (directory scanning)
    @app.route("/<path:path>", methods=["GET", "POST"])
    def catch_all(path: str) -> Any:
        full = "/" + path + "?" + request.query_string.decode()
        attacks = _detect_attacks(full)
        log_event(
            source_ip=_ip(),
            service="http",
            event="http_unknown_path",
            attack_type="directory_scanning" if attacks else "web_activity",
            payload=full[:300],
            metadata={"path": path},
            severity="warning" if attacks else "info",
            **_common_context(
                event_type="attack" if attacks else "request",
                status="detected" if attacks else "failed",
            ),
        )
        return jsonify({"error": "Not found"}), 404

    return app


# --------------------------------------------------------------------------- #
#  Public start function                                                        #
# --------------------------------------------------------------------------- #

def start_http_honeypot(host: str = "0.0.0.0", port: int = 8080) -> None:
    app = create_http_honeypot()
    print(f"[HTTP] Honeypot listening on {host}:{port}")
    # use_reloader=False is CRITICAL — reloader spawns a subprocess that breaks threading
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    start_http_honeypot()
