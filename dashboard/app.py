"""
Dashboard app — serves the multi-section honeypot UI and all API endpoints.
"""

from __future__ import annotations

import json
import os
import platform
import queue
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.logger import get_stream_queue, read_recent_events

try:
    from flask import Flask, Response, jsonify, render_template
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
_START_TIME = time.time()


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
            with urllib.request.urlopen(url, timeout=2.0) as response:
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


def _compute_ids_stats(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_service: dict[str, int] = defaultdict(int)
    by_attack: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    unique_ips: set[str] = set()
    severity_names = {
        "Low": "info",
        "Medium": "warning",
        "High": "warning",
        "Critical": "critical",
    }

    for result in results:
        by_service[result.get("service", "unknown")] += 1
        by_attack[result.get("attack_type", "unknown")] += 1
        level = str(result.get("threat_level", "Low"))
        by_severity[severity_names.get(level, "info")] += 1
        source_ip = str(result.get("source_ip", "")).strip()
        if source_ip:
            unique_ips.add(source_ip)

    return {
        "total_events": len(results),
        "unique_ips": len(unique_ips),
        "threats_detected": sum(
            1 for result in results if result.get("prediction") == "attack"
        ),
        "by_service": dict(by_service),
        "by_attack": dict(by_attack),
        "by_severity": dict(by_severity),
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
        "generated_at": datetime.now(timezone.utc).isoformat(),
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
            "label": datetime.fromtimestamp(t0, tz=timezone.utc).strftime("%H:%M:%S"),
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

    @app.route("/")
    def index() -> Any:
        return render_template("index.html")

    @app.route("/api/monitor")
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
        })

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
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": stats,
            "credentials_captured": credentials,
            "recent_threats": [e for e in events if e.get("severity") in ("warning", "critical")][:50],
        })

    @app.route("/api/report/download")
    def api_report_download() -> Any:
        events = _all_events(2000)
        stats = _compute_stats(events)
        credentials = _extract_credentials(events)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
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
                ts = c["timestamp"][:19].replace("T", " ")
                lines.append(f"  {ts:20s} {c['source_ip']:15s} {c['service']:5s} {c['username']:20s} {c['password']}")
        else:
            lines.append("  No credentials captured yet.")
        lines += ["", "── RECENT THREATS ───────────────────────────────────────"]
        for e in [x for x in events if x.get("severity") in ("warning", "critical")][:30]:
            ts = e.get("timestamp", "")[:19].replace("T", " ")
            lines.append(f"  [{ts}] [{e.get('service','?'):4s}] {e.get('attack_type','?')}")
        lines += ["", "=" * 62, "  END OF REPORT", "=" * 62]
        fname = f"honeypot_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        return Response("\n".join(lines), mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})

    @app.route("/stream")
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
