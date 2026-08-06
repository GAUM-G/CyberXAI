"""Simulation-only IPS state consumed by the honeypot applications.

This module can delay or end only application-managed honeypot interactions.
It never imports subprocess tooling and never changes a host firewall, route,
network interface, or operating-system security setting.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE_FILE = Path(
    os.environ.get(
        "IPS_STATE_FILE",
        str(PROJECT_ROOT / "data" / "ips" / "simulated_ips_state.json"),
    )
)
IPS_MODE = "simulation"
AUTOMATIC_HOST_BLOCKING = False
HOST_FIREWALL_CHANGED = False
MAX_RATE_LIMIT_DELAY_SECONDS = 1.0

_cache_lock = threading.Lock()
_cache_path: Path | None = None
_cache_mtime_ns: int | None = None
_cache_value: dict[str, Any] | None = None


def _empty_state() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "mode": IPS_MODE,
        "automatic_host_blocking": AUTOMATIC_HOST_BLOCKING,
        "host_firewall_changed": HOST_FIREWALL_CHANGED,
        "simulated_blocks": [],
        "rate_limits": [],
        "terminated_sessions": [],
    }


def _is_active(entry: dict[str, Any], now: datetime) -> bool:
    expires_at = entry.get("expires_at")
    if not expires_at:
        return True
    try:
        expires = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
    except ValueError:
        return False
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > now


def load_simulated_ips_state(
    state_file: Path | str = DEFAULT_STATE_FILE,
) -> dict[str, Any]:
    """Read the safe runtime state and reject any non-simulation contract."""

    global _cache_mtime_ns, _cache_path, _cache_value
    path = Path(state_file)
    try:
        mtime_ns = path.stat().st_mtime_ns
    except OSError:
        return _empty_state()

    with _cache_lock:
        if _cache_path == path and _cache_mtime_ns == mtime_ns and _cache_value is not None:
            return dict(_cache_value)

        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return _empty_state()

        if (
            not isinstance(value, dict)
            or value.get("mode") != IPS_MODE
            or value.get("automatic_host_blocking") is not False
            or value.get("host_firewall_changed") is not False
        ):
            return _empty_state()

        safe = _empty_state()
        for key in ("simulated_blocks", "rate_limits", "terminated_sessions"):
            entries = value.get(key)
            safe[key] = [item for item in entries if isinstance(item, dict)] if isinstance(entries, list) else []
        safe["generated_at"] = value.get("generated_at")
        _cache_path = path
        _cache_mtime_ns = mtime_ns
        _cache_value = safe
        return dict(safe)


def _matches(entry: dict[str, Any], source_ip: str, service: str) -> bool:
    return (
        str(entry.get("source_ip", "")).strip() == str(source_ip).strip()
        and str(entry.get("service", "")).strip().lower() == str(service).strip().lower()
    )


def get_simulated_response(
    source_ip: str,
    service: str,
    session_id: str | None = None,
    *,
    state_file: Path | str = DEFAULT_STATE_FILE,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return only application-level simulated controls for one interaction."""

    observed_at = now or datetime.now(timezone.utc)
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    state = load_simulated_ips_state(state_file)

    blocks = [
        item
        for item in state["simulated_blocks"]
        if _matches(item, source_ip, service) and _is_active(item, observed_at)
    ]
    limits = [
        item
        for item in state["rate_limits"]
        if _matches(item, source_ip, service) and _is_active(item, observed_at)
    ]
    terminations = [
        item
        for item in state["terminated_sessions"]
        if session_id
        and str(item.get("session_id", "")).strip() == str(session_id).strip()
        and str(item.get("service", "")).strip().lower() == str(service).strip().lower()
        and _is_active(item, observed_at)
    ]

    delay_ms = 0
    if limits:
        try:
            delay_ms = max(0, min(int(limits[-1].get("rate_limit_delay_ms") or 0), 1000))
        except (TypeError, ValueError):
            delay_ms = 0

    action_ids = [
        int(item["action_id"])
        for item in [*blocks, *limits, *terminations]
        if isinstance(item.get("action_id"), int)
    ]
    return {
        "mode": IPS_MODE,
        "automatic_host_blocking": AUTOMATIC_HOST_BLOCKING,
        "host_firewall_changed": HOST_FIREWALL_CHANGED,
        "would_have_been_blocked": bool(blocks),
        "rate_limited": bool(limits),
        "session_terminated": bool(terminations),
        "rate_limit_delay_ms": delay_ms,
        "action_ids": action_ids,
    }


def apply_simulated_rate_limit(
    response: dict[str, Any],
    *,
    sleeper: Callable[[float], None] = time.sleep,
) -> float:
    """Apply a bounded honeypot-only delay and return the delay in seconds."""

    if not response.get("rate_limited"):
        return 0.0
    try:
        seconds = float(response.get("rate_limit_delay_ms", 0)) / 1000.0
    except (TypeError, ValueError):
        seconds = 0.0
    seconds = max(0.0, min(seconds, MAX_RATE_LIMIT_DELAY_SECONDS))
    if seconds:
        sleeper(seconds)
    return seconds


def annotate_event_with_simulated_ips(
    record: dict[str, Any],
    *,
    state_file: Path | str = DEFAULT_STATE_FILE,
) -> dict[str, Any]:
    """Attach auditable IPS state without changing the common-event schema."""

    response = get_simulated_response(
        str(record.get("source_ip", "unknown")),
        str(record.get("service", "unknown")),
        record.get("session_id"),
        state_file=state_file,
    )
    if not (
        response["would_have_been_blocked"]
        or response["rate_limited"]
        or response["session_terminated"]
    ):
        return record

    metadata = record.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        record["metadata"] = metadata
    metadata["ips"] = response
    return record
