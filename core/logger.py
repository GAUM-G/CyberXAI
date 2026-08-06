"""
Centralized structured logger for all honeypot events.
Supports JSONL file logging + in-memory queue for real-time SSE streaming.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from core.attack_detection import PortScanDetector
from core.event_schema import build_common_event
from core.simulated_ips import annotate_event_with_simulated_ips


LOG_FILE = Path(__file__).resolve().parents[1] / "data" / "raw_logs" / "honeypot_events.jsonl"
N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/honeypot-alert").strip()

# In-memory queue for real-time dashboard streaming (SSE)
_event_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=500)
_lock = threading.Lock()


def _to_float(value: str, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def _to_int(value: str, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


N8N_WEBHOOK_TIMEOUT = _to_float(os.getenv("N8N_WEBHOOK_TIMEOUT", "2.0"), 2.0)
EVENT_COLLECTOR_URL = os.getenv(
    "EVENT_COLLECTOR_URL", "http://127.0.0.1:5000/api/events"
).strip()
EVENT_COLLECTOR_TIMEOUT = max(
    0.2, _to_float(os.getenv("EVENT_COLLECTOR_TIMEOUT", "2.0"), 2.0)
)
EVENT_COLLECTOR_RETRY_SECONDS = max(
    0.2, _to_float(os.getenv("EVENT_COLLECTOR_RETRY_SECONDS", "2.0"), 2.0)
)
EVENT_COLLECTOR_QUEUE_SIZE = max(
    100, _to_int(os.getenv("EVENT_COLLECTOR_QUEUE_SIZE", "5000"), 5000)
)
PORT_SCAN_THRESHOLD = max(
    2, _to_int(os.getenv("PORT_SCAN_THRESHOLD", "3"), 3)
)
PORT_SCAN_WINDOW_SECONDS = max(
    1.0, _to_float(os.getenv("PORT_SCAN_WINDOW_SECONDS", "30.0"), 30.0)
)

_collector_queue: queue.Queue[dict[str, Any]] = queue.Queue(
    maxsize=EVENT_COLLECTOR_QUEUE_SIZE
)
_collector_start_lock = threading.Lock()
_collector_worker_started = False
_port_scan_detector = PortScanDetector(
    threshold=PORT_SCAN_THRESHOLD,
    window_seconds=PORT_SCAN_WINDOW_SECONDS,
)


def _post_event_to_collector(record: dict[str, Any]) -> str:
    """Return success, retry or drop without interrupting honeypot logging."""

    body = json.dumps(record, ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(
        EVENT_COLLECTOR_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=EVENT_COLLECTOR_TIMEOUT) as response:
            return "success" if 200 <= response.getcode() < 300 else "retry"
    except urllib.error.HTTPError as exc:
        if 400 <= exc.code < 500 and exc.code not in (408, 429):
            # Retrying a schema/authentication rejection would block later events.
            return "drop"
        return "retry"
    except (urllib.error.URLError, TimeoutError, OSError):
        return "retry"


def _collector_worker() -> None:
    while True:
        record = _collector_queue.get()
        try:
            while EVENT_COLLECTOR_URL:
                outcome = _post_event_to_collector(record)
                if outcome in {"success", "drop"}:
                    break
                time.sleep(EVENT_COLLECTOR_RETRY_SECONDS)
        finally:
            _collector_queue.task_done()


def _ensure_collector_worker() -> None:
    global _collector_worker_started

    if _collector_worker_started:
        return
    with _collector_start_lock:
        if _collector_worker_started:
            return
        threading.Thread(
            target=_collector_worker,
            name="backend-event-collector",
            daemon=True,
        ).start()
        _collector_worker_started = True


def _queue_event_for_collector(record: dict[str, Any]) -> None:
    if not EVENT_COLLECTOR_URL or record.get("service") not in {"ssh", "ftp", "http"}:
        return

    _ensure_collector_worker()
    try:
        _collector_queue.put_nowait(record)
    except queue.Full:
        # JSONL remains the durable fallback if the backend is unavailable.
        pass


def _build_n8n_payload(record: dict[str, Any]) -> dict[str, Any]:
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    payload_value = record.get("payload")
    service = record.get("service") or "unknown"
    normalized_record = {**record, "service": service, "type": service}

    target = metadata.get("path") or metadata.get("route") or metadata.get("target")
    if not target and isinstance(payload_value, str):
        target = payload_value[:200]

    username = None
    password = None
    if isinstance(payload_value, dict):
        username = payload_value.get("username") or payload_value.get("user")
        password = payload_value.get("password") or payload_value.get("pass")
    elif isinstance(payload_value, str) and "username=" in payload_value:
        parts = dict(part.split("=", 1) for part in payload_value.split("&") if "=" in part)
        username = parts.get("username")
        password = parts.get("password")

    request_context = {
        "method": metadata.get("method"),
        "status": metadata.get("status"),
        "durationMs": metadata.get("durationMs"),
        "query": metadata.get("query"),
        "body": metadata.get("body"),
        "userAgent": metadata.get("userAgent"),
        "referer": metadata.get("referer"),
        "origin": metadata.get("origin"),
        "host": metadata.get("host"),
        "remote_port": metadata.get("remote_port"),
        "source_port": metadata.get("source_port"),
        "command": metadata.get("command"),
        "argument": metadata.get("argument"),
        "query_length": metadata.get("query_length"),
        "filename": metadata.get("filename"),
        "attempt_count": metadata.get("attempt_count"),
        "failed_attempts": metadata.get("failed_attempts"),
        "threshold": metadata.get("threshold"),
    }

    indicators = {
        "username": username or metadata.get("username") or metadata.get("user"),
        "password": password or metadata.get("password") or metadata.get("pass"),
        "findings": metadata.get("findings"),
        "attacks_detected": metadata.get("attacks_detected"),
        "event_path": metadata.get("path") or metadata.get("route"),
    }

    return {
        "severity": record.get("severity", "info"),
        "ip": record.get("source_ip", "unknown"),
        # Keep both names because older Telegram templates use `type`.
        "type": service,
        "attack_type": record.get("attack_type", "unknown"),
        "target": target or "n/a",
        "timestamp": record.get("timestamp"),
        "service": service,
        "event": record.get("event"),
        "metadata": metadata,
        "payload": payload_value,
        "record": normalized_record,
        "analysis": {
            "target": target or "n/a",
            "request_context": {k: v for k, v in request_context.items() if v is not None},
            "indicators": {k: v for k, v in indicators.items() if v not in (None, "")},
        },
    }


def _post_critical_alert_to_n8n(record: dict[str, Any]) -> None:
    if not N8N_WEBHOOK_URL:
        return

    body = json.dumps(_build_n8n_payload(record), ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(
        N8N_WEBHOOK_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=N8N_WEBHOOK_TIMEOUT):
            pass
    except (urllib.error.URLError, TimeoutError):
        # Notification delivery failure should not break honeypot logging.
        return


def _publish_record(record: dict[str, Any]) -> None:
    """Publish one already-normalized record through every existing output."""

    # Write to JSONL file (thread-safe)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True) + "\n")

    # Push to SSE queue (non-blocking: drop if full to avoid memory issues)
    try:
        _event_queue.put_nowait(record)
    except queue.Full:
        pass

    # Deliver to the centralized backend without blocking honeypot responses.
    _queue_event_for_collector(record)

    if record.get("severity") == "critical":
        threading.Thread(
            target=_post_critical_alert_to_n8n,
            args=(record,),
            daemon=True,
        ).start()


def _build_port_scan_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Correlate distinct ports while avoiding correlation of synthetic alerts."""

    if record.get("attack_type") == "port_scanning":
        return None

    finding = _port_scan_detector.register(
        str(record.get("source_ip", "")),
        record.get("destination_port"),
    )
    if finding is None:
        return None

    evidence = {
        "observed_ports": list(finding.observed_ports),
        "distinct_port_count": len(finding.observed_ports),
        "threshold": finding.threshold,
        "window_seconds": finding.window_seconds,
        "trigger_event_id": record.get("event_id"),
    }
    return build_common_event(
        source_ip=finding.source_ip,
        source_port=record.get("source_port"),
        destination_port=record.get("destination_port"),
        service=str(record.get("service", "http")),
        protocol=str(record.get("protocol", record.get("service", "http"))),
        event_type="attack",
        event="port_scan_detected",
        attack_type="port_scanning",
        status="detected",
        session_id=record.get("session_id"),
        request_method=record.get("request_method"),
        request_path=record.get("request_path"),
        payload={"observed_ports": list(finding.observed_ports)},
        metadata=evidence,
        severity="warning",
    )


def log_event(
    *,
    source_ip: str,
    service: str,           # "ssh" | "ftp" | "http"
    event: str,             # e.g. "ssh_bruteforce_attempt"
    attack_type: str,       # e.g. "ssh_bruteforce" | "ftp_bruteforce" | "sql_injection" | "xss"
    payload: Any = None,
    metadata: dict[str, Any] | None = None,
    severity: str = "info", # "info" | "warning" | "critical"
    event_type: str | None = None,
    protocol: str | None = None,
    source_port: int | str | None = None,
    destination_port: int | str | None = None,
    username: str | None = None,
    session_id: str | None = None,
    request_method: str | None = None,
    request_path: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Write one event to disk and push it to the live stream queue."""

    record = build_common_event(
        source_ip=source_ip,
        service=service,
        event=event,
        attack_type=attack_type,
        payload=payload,
        metadata=metadata,
        severity=severity,
        event_type=event_type,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        username=username,
        session_id=session_id,
        request_method=request_method,
        request_path=request_path,
        status=status,
    )
    annotate_event_with_simulated_ips(record)

    _publish_record(record)

    port_scan_event = _build_port_scan_event(record)
    if port_scan_event is not None:
        _publish_record(port_scan_event)

    return record


def read_recent_events(limit: int = 100) -> list[dict[str, Any]]:
    """Read the most recent N events from the JSONL log file."""
    if not LOG_FILE.exists():
        return []
    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    events: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(events))


def get_stream_queue() -> "queue.Queue[dict[str, Any]]":
    """Return the shared SSE event queue."""
    return _event_queue
