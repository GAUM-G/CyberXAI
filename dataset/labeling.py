"""Deterministic label rules for centralized honeypot events."""

from __future__ import annotations

from typing import Any, Mapping


APPROVED_LABELS = (
    "normal",
    "ssh_bruteforce",
    "ftp_bruteforce",
    "sql_injection",
    "xss",
    "directory_scanning",
    "port_scanning",
    "other_anomaly",
)

_EXPLICIT_ATTACK_LABELS = frozenset(
    {
        "ssh_bruteforce",
        "ftp_bruteforce",
        "sql_injection",
        "xss",
        "directory_scanning",
        "port_scanning",
    }
)

_NORMAL_ACTIVITY_TYPES = frozenset({"web_activity", "normal", "benign"})


def _normalized(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def assign_label(event: Mapping[str, Any]) -> str:
    """Assign exactly one approved label without modifying the event.

    Only informational activity explicitly marked as normal/web activity is
    considered normal. Honeypot probes and unknown activity remain anomalous.
    """

    attack_type = _normalized(event.get("attack_type"))
    severity = _normalized(event.get("severity"))

    if attack_type in _EXPLICIT_ATTACK_LABELS:
        return attack_type

    if attack_type in _NORMAL_ACTIVITY_TYPES and severity == "info":
        return "normal"

    return "other_anomaly"
