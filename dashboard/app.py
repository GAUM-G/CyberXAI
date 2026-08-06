"""
Dashboard app — serves the multi-section honeypot UI and all API endpoints.
"""

from __future__ import annotations

import json
import math
import os
import platform
import queue
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Generator
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.logger import get_stream_queue, read_recent_events
from core.time_utils import IST, now_ist, now_ist_iso, to_ist

try:
    from flask import (
        Flask,
        Response,
        jsonify,
        render_template,
        request,
        session,
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
DASHBOARD_SECRET_KEY = os.environ.get(
    "DASHBOARD_SECRET_KEY",
    "change-this-local-dashboard-secret",
).strip()
IDS_ACTIVE_WINDOW_MINUTES = max(
    1,
    int(os.environ.get("IDS_ACTIVE_WINDOW_MINUTES", "15")),
)
_START_TIME = time.time()


def _portal_request(
    path: str,
    *,
    method: str = "GET",
    token: str = "",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Call the authenticated portal without exposing credentials in logs."""

    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    portal_request = urllib.request.Request(
        f"{PORTAL_API_URL}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    with urllib.request.urlopen(portal_request, timeout=3.0) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("portal returned an invalid response")
    return value


def _portal_login(username: str, password: str) -> dict[str, Any]:
    return _portal_request(
        "/login",
        method="POST",
        payload={"username": username, "password": password},
    )


def _validate_portal_token(token: str) -> dict[str, Any] | None:
    if not token:
        return None
    try:
        data = _portal_request("/api/auth/session", token=token)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return None
    user = data.get("user")
    return user if isinstance(user, dict) else None


def require_dashboard_auth(view: Callable[..., Any]) -> Callable[..., Any]:
    """Require a currently valid portal JWT stored in the signed session."""

    @wraps(view)
    def protected(*args: Any, **kwargs: Any) -> Any:
        token = str(session.get("portal_token") or "")
        user = _validate_portal_token(token)
        if user is None:
            session.clear()
            return jsonify({"error": "Dashboard login required"}), 401
        session["portal_user"] = user
        return view(*args, **kwargs)

    return protected


def _all_events(limit: int = 2000) -> list[dict[str, Any]]:
    return read_recent_events(limit=limit)


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
            token = str(session.get("portal_token") or "")
            headers = {"Authorization": f"Bearer {token}"} if token else {}
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


def create_dashboard_app() -> "Flask":
    if not _FLASK_OK:
        raise RuntimeError("Flask required.")
    app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
    app.config.update(
        SECRET_KEY=DASHBOARD_SECRET_KEY,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    @app.route("/")
    def index() -> Any:
        return render_template(
            "index.html",
            portal_api_url=PORTAL_API_URL,
        )

    @app.route("/api/auth/login", methods=["POST"])
    def api_auth_login() -> Any:
        body = request.get_json(silent=True)
        username = str((body or {}).get("username") or "").strip()
        password = str((body or {}).get("password") or "")
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        try:
            data = _portal_login(username, password)
        except HTTPError as exc:
            return jsonify({"error": "Login failed"}), exc.code
        except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            return jsonify({"error": "Portal authentication is unavailable"}), 502
        token = str(data.get("token") or "")
        user = data.get("user")
        if not token or not isinstance(user, dict):
            return jsonify({"error": "Portal returned an invalid login"}), 502
        session.clear()
        session["portal_token"] = token
        session["portal_user"] = user
        return jsonify({"authenticated": True, "token": token, "user": user})

    @app.route("/api/auth/session")
    def api_auth_session() -> Any:
        token = str(session.get("portal_token") or "")
        user = _validate_portal_token(token)
        if user is None:
            session.clear()
            return jsonify({"authenticated": False}), 401
        session["portal_user"] = user
        return jsonify(
            {
                "authenticated": True,
                "token": token,
                "user": user,
                "timezone": "Asia/Kolkata",
            }
        )

    @app.route("/api/auth/logout", methods=["POST"])
    def api_auth_logout() -> Any:
        session.clear()
        return jsonify({"authenticated": False})

    @app.route("/api/monitor")
    @require_dashboard_auth
    def api_monitor() -> Any:
        events = _all_events(2000)
        stats = _compute_stats(events)
        sys_stats = _system_stats()
        port_scan_stats = _port_scan_summary(events)
        return jsonify({
            **stats,
            **sys_stats,
            **port_scan_stats,
            "recent_events": events[:100],
        })

    @app.route("/api/honeypot")
    @require_dashboard_auth
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
    @require_dashboard_auth
    def api_credentials() -> Any:
        events = _all_events(2000)
        return jsonify(_extract_credentials(events))

    @app.route("/api/ids")
    @require_dashboard_auth
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
    @require_dashboard_auth
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
    @require_dashboard_auth
    def api_xai_alerts() -> Any:
        events = _all_events(2000)
        return jsonify({"alerts": _xai_alerts(events, limit=50)})

    @app.route("/api/xai/report", methods=["POST"])
    @require_dashboard_auth
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
    @require_dashboard_auth
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
    @require_dashboard_auth
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
    @require_dashboard_auth
    def stream() -> Any:
        def _gen() -> Generator[str, None, None]:
            q = get_stream_queue()
            last_hb = time.time()
            while True:
                try:
                    ev = q.get(timeout=1.0)
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
    app = create_dashboard_app()
    print(f"[Dashboard] http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    start_dashboard()
