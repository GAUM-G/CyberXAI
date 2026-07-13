from __future__ import annotations

import re
import socket
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flask import Flask, abort, render_template, request, send_from_directory

from core.logger import log_event

BASE_DIR = Path(__file__).resolve().parent
DECOY_DIR = BASE_DIR / "decoy_files"

_SQLI = [re.compile(p, re.IGNORECASE) for p in (
    r"(union\s+select)",
    r"(or\s+1\s*=\s*1)",
    r"(drop\s+table)",
    r"(--|#|/\*)",
    r"(information_schema)",
)]
_XSS = [re.compile(p, re.IGNORECASE) for p in (
    r"<script",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
)]
_DIRSCAN = [re.compile(p, re.IGNORECASE) for p in (
    r"\.\./",
    r"etc/passwd",
    r"\.git",
    r"phpmyadmin",
    r"\.env",
    r"wp-admin",
)]


def _detect_attack(payload: str) -> list[str]:
    findings: list[str] = []
    if any(p.search(payload) for p in _SQLI):
        findings.append("sql_injection")
    if any(p.search(payload) for p in _XSS):
        findings.append("xss")
    if any(p.search(payload) for p in _DIRSCAN):
        findings.append("directory_scanning")
    return findings


def _ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")


def _request_headers() -> dict[str, str]:
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


def _log(event: str, attack_type: str, payload: Any, severity: str = "info", metadata: dict[str, Any] | None = None) -> None:
    log_event(
        source_ip=_ip(),
        service="website",
        event=event,
        attack_type=attack_type,
        payload=payload,
        severity=severity,
        metadata={**(metadata or {}), "headers": _request_headers(), "method": request.method, "path": request.path, "query_string": request.query_string.decode("utf-8", errors="ignore")},
    )


def create_website_app() -> Flask:
    app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))

    @app.route("/", methods=["GET"])
    def index() -> Any:
        _log("website_index", "web_activity", request.full_path)
        files = sorted(p.name for p in DECOY_DIR.glob("*") if p.is_file())
        return render_template("index.html", files=files)

    @app.route("/login", methods=["POST"])
    def login() -> Any:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        payload = f"username={username}&password={password}"
        findings = _detect_attack(payload)

        _log(
            event="website_login_attempt",
            attack_type="authentication_probe" if not findings else findings[0],
            payload=payload,
            severity="warning" if findings else "info",
            metadata={"username": username, "findings": findings, "password_length": len(password)},
        )

        for attack in findings[1:]:
            _log("website_login_attack", attack, payload, "warning", {"username": username})

        return render_template("index.html", files=sorted(p.name for p in DECOY_DIR.glob("*") if p.is_file()), message="Login failed")

    @app.route("/search", methods=["GET"])
    def search() -> Any:
        query = request.args.get("q", "")
        findings = _detect_attack(query)
        _log(
            event="website_search",
            attack_type="web_activity" if not findings else findings[0],
            payload=query,
            severity="warning" if findings else "info",
            metadata={"query_length": len(query), "findings": findings, "query": query},
        )
        return {"query": query, "results": []}

    @app.route("/files/<path:filename>", methods=["GET"])
    def download_file(filename: str) -> Any:
        safe_path = DECOY_DIR / filename
        if not safe_path.exists() or not safe_path.is_file():
            _log("website_file_not_found", "directory_scanning", filename, "warning")
            abort(404)

        findings = _detect_attack(filename)
        _log(
            event="website_file_access",
            attack_type="file_access" if not findings else findings[0],
            payload=filename,
            severity="warning" if findings else "info",
            metadata={"filename": filename, "path": f"/files/{filename}"},
        )
        return send_from_directory(DECOY_DIR, filename, as_attachment=False)

    @app.route("/<path:path>", methods=["GET", "POST"])
    def catch_all(path: str) -> Any:
        full_path = "/" + path
        findings = _detect_attack(full_path)
        _log(
            event="website_unknown_path",
            attack_type="directory_scanning" if findings else "web_activity",
            payload=full_path,
            severity="warning" if findings else "info",
            metadata={"path": full_path, "findings": findings},
        )
        abort(404)

    return app


def _local_ipv4_candidates() -> list[str]:
    ips: set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                ips.add(ip)
    except OSError:
        pass

    # Fallback: resolve via outbound route without sending traffic.
    if not ips:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127."):
                    ips.add(ip)
        except OSError:
            pass

    return sorted(ips)


def start_website(host: str = "0.0.0.0", port: int = 8090) -> None:
    app = create_website_app()
    print(f"[Website] Decoy website running at http://{host}:{port}")
    if host in {"0.0.0.0", "::"}:
        ips = _local_ipv4_candidates()
        if ips:
            for ip in ips:
                print(f"[Website] Mobile/LAN URL: http://{ip}:{port}")
        else:
            print("[Website] Could not auto-detect LAN IP. Run ipconfig and use your Wi-Fi IPv4 address.")
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    start_website()
