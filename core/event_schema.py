"""Common event schema shared by all honeypot services.

The builder keeps the original event fields used by the dashboard and n8n while
adding consistent context for later IDS, ML, and XAI processing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


SCHEMA_VERSION = "1.0"

COMMON_EVENT_FIELDS = (
    "schema_version",
    "event_id",
    "timestamp",
    "source_ip",
    "source_port",
    "destination_port",
    "service",
    "protocol",
    "event_type",
    "event",
    "attack_type",
    "severity",
    "status",
    "username",
    "session_id",
    "request_method",
    "request_path",
    "payload",
    "metadata",
)

ALLOWED_SEVERITIES = frozenset({"info", "warning", "critical"})

_DEFAULT_PROTOCOLS = {
    "ssh": "ssh",
    "ftp": "ftp",
    "http": "http",
    "website": "http",
}

_DEFAULT_DESTINATION_PORTS = {
    "ssh": 2222,
    "ftp": 2121,
    "http": 8080,
    "website": 8090,
}


def _clean_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_port(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _payload_username(payload: Any) -> str | None:
    if isinstance(payload, dict):
        return _clean_optional_text(payload.get("username") or payload.get("user"))

    if isinstance(payload, str) and "username=" in payload:
        parts = dict(part.split("=", 1) for part in payload.split("&") if "=" in part)
        return _clean_optional_text(parts.get("username"))

    return None


def _timestamp_value(value: str | datetime | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    text = str(value).strip()
    return text or datetime.now(timezone.utc).isoformat()


def build_common_event(
    *,
    source_ip: str,
    service: str,
    event: str,
    attack_type: str,
    payload: Any = None,
    metadata: dict[str, Any] | None = None,
    severity: str = "info",
    event_type: str | None = None,
    protocol: str | None = None,
    source_port: int | str | None = None,
    destination_port: int | str | None = None,
    username: str | None = None,
    session_id: str | None = None,
    request_method: str | None = None,
    request_path: str | None = None,
    status: str | None = None,
    timestamp: str | datetime | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Build one backward-compatible event using the common schema."""

    normalized_service = str(service).strip().lower()
    normalized_event = str(event).strip()
    normalized_attack = str(attack_type).strip()
    normalized_severity = str(severity).strip().lower()

    if not normalized_service:
        raise ValueError("service must not be empty")
    if not normalized_event:
        raise ValueError("event must not be empty")
    if not normalized_attack:
        raise ValueError("attack_type must not be empty")
    if normalized_severity not in ALLOWED_SEVERITIES:
        raise ValueError(f"unsupported severity: {severity}")

    context = dict(metadata or {})
    resolved_source_port = _coerce_port(
        source_port if source_port is not None else context.get("source_port", context.get("remote_port"))
    )
    resolved_destination_port = _coerce_port(
        destination_port
        if destination_port is not None
        else context.get("destination_port", _DEFAULT_DESTINATION_PORTS.get(normalized_service))
    )
    resolved_username = (
        _clean_optional_text(username)
        or _payload_username(payload)
        or _clean_optional_text(context.get("username") or context.get("user"))
    )
    resolved_method = _clean_optional_text(request_method or context.get("method"))
    if resolved_method:
        resolved_method = resolved_method.upper()
    resolved_path = _clean_optional_text(
        request_path or context.get("path") or context.get("route") or context.get("target")
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": _clean_optional_text(event_id) or str(uuid4()),
        "timestamp": _timestamp_value(timestamp),
        "source_ip": _clean_optional_text(source_ip) or "unknown",
        "source_port": resolved_source_port,
        "destination_port": resolved_destination_port,
        "service": normalized_service,
        "protocol": (_clean_optional_text(protocol) or _DEFAULT_PROTOCOLS.get(normalized_service) or normalized_service).lower(),
        "event_type": (_clean_optional_text(event_type) or normalized_event).lower(),
        # Legacy fields below remain unchanged for the dashboard and n8n workflow.
        "event": normalized_event,
        "attack_type": normalized_attack,
        "severity": normalized_severity,
        "status": (_clean_optional_text(status) or _clean_optional_text(context.get("event_status")) or "observed").lower(),
        "username": resolved_username,
        "session_id": _clean_optional_text(session_id or context.get("session_id")),
        "request_method": resolved_method,
        "request_path": resolved_path,
        "payload": payload,
        "metadata": context,
    }


def validate_common_event(record: dict[str, Any]) -> list[str]:
    """Return validation errors; an empty list means the event is valid."""

    errors: list[str] = []
    missing = [field for field in COMMON_EVENT_FIELDS if field not in record]
    if missing:
        errors.append(f"missing fields: {', '.join(missing)}")

    if record.get("schema_version") != SCHEMA_VERSION:
        errors.append("unsupported schema_version")
    if record.get("severity") not in ALLOWED_SEVERITIES:
        errors.append("invalid severity")
    if not isinstance(record.get("metadata"), dict):
        errors.append("metadata must be an object")

    timestamp = record.get("timestamp")
    try:
        datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        errors.append("timestamp must be ISO-8601")

    for field in ("event_id", "source_ip", "service", "protocol", "event_type", "event", "attack_type", "status"):
        if not isinstance(record.get(field), str) or not record[field].strip():
            errors.append(f"{field} must be a non-empty string")

    for field in ("source_port", "destination_port"):
        value = record.get(field)
        if value is not None and (not isinstance(value, int) or not 0 <= value <= 65535):
            errors.append(f"{field} must be a valid port or null")

    return errors
