"""
Centralized structured logger for all honeypot events.
Supports JSONL file logging + in-memory queue for real-time SSE streaming.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


N8N_WEBHOOK_TIMEOUT = _to_float(os.getenv("N8N_WEBHOOK_TIMEOUT", "2.0"), 2.0)


def _build_n8n_payload(record: dict[str, Any]) -> dict[str, Any]:
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    payload_value = record.get("payload")

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
        "attack_type": record.get("attack_type", "unknown"),
        "target": target or "n/a",
        "timestamp": record.get("timestamp"),
        "service": record.get("service"),
        "event": record.get("event"),
        "metadata": metadata,
        "payload": payload_value,
        "record": record,
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


def log_event(
    *,
    source_ip: str,
    service: str,           # "ssh" | "ftp" | "http"
    event: str,             # e.g. "ssh_bruteforce_attempt"
    attack_type: str,       # e.g. "ssh_bruteforce" | "ftp_bruteforce" | "sql_injection" | "xss"
    payload: Any = None,
    metadata: dict[str, Any] | None = None,
    severity: str = "info", # "info" | "warning" | "critical"
) -> dict[str, Any]:
    """Write one event to disk and push it to the live stream queue."""

    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "service": service,
        "event": event,
        "attack_type": attack_type,
        "payload": payload,
        "severity": severity,
        "metadata": metadata or {},
    }

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

    if severity == "critical":
        threading.Thread(target=_post_critical_alert_to_n8n, args=(record,), daemon=True).start()

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
