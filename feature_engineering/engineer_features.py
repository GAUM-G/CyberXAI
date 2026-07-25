"""Derive causal behavioural and security features from sanitized Step 6 rows."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Mapping, MutableMapping, Sequence


FEATURE_ENGINEERING_VERSION = "1.0"
RATE_WINDOW_SECONDS = 60.0
SESSION_TIMEOUT_SECONDS = 300.0
USERNAME_WINDOW_SECONDS = 300.0

ENGINEERED_NUMERICAL_FEATURES = (
    "failed_attempts",
    "requests_per_minute",
    "payload_length",
    "session_duration",
    "suspicious_keyword_count",
    "username_repetition",
    "time_between_requests",
    "sqli_xss_pattern_count",
)

FEATURE_DEFINITIONS = {
    "failed_attempts": (
        "Failed events from the same pseudonymous source/service in the "
        "current and previous 60 seconds."
    ),
    "requests_per_minute": (
        "Events from the same pseudonymous source/service in the current "
        "and previous 60 seconds."
    ),
    "payload_length": (
        "Sanitized Step 6 payload length, with a safe text-length fallback."
    ),
    "session_duration": (
        "Seconds since the start of the current source/service activity "
        "session; a gap over 300 seconds starts a new session."
    ),
    "suspicious_keyword_count": (
        "General reconnaissance, sensitive-file and command-tool indicators "
        "found in sanitized request, payload and metadata text."
    ),
    "username_repetition": (
        "Earlier submissions of the same in-memory pseudonymized username "
        "by the source/service during the previous 300 seconds."
    ),
    "time_between_requests": (
        "Seconds since the previous event from the same source/service; "
        "zero for the first event."
    ),
    "sqli_xss_pattern_count": (
        "SQL-injection and cross-site-scripting pattern matches found in "
        "sanitized request, payload and metadata text."
    ),
}

_FAILED_STATUSES = frozenset(
    {
        "denied",
        "failed",
        "failure",
        "forbidden",
        "invalid",
        "rejected",
        "unauthorized",
        "unsuccessful",
    }
)
_USERNAME_KEYS = frozenset(
    {
        "login",
        "user",
        "user_id",
        "userid",
        "user_name",
        "username",
    }
)
_REDACTED_VALUES = frozenset({"", "[redacted]", "redacted", "none", "null"})

_SUSPICIOUS_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(?:\.\./|\.\.\\|%2e%2e(?:%2f|/|%5c))",
        r"(?:/etc/(?:passwd|shadow)|boot\.ini|win\.ini)",
        r"(?:^|[/\\])(?:\.env|id_rsa|web\.config|wp-config\.php)(?:$|[/?&\"'])",
        r"(?:/admin(?:[/?.]|$)|/wp-admin(?:[/?.]|$)|/phpmyadmin(?:[/?.]|$))",
        r"\b(?:cmd\.exe|powershell|certutil|curl|wget|netcat)\b",
        r"(?:^|[\s;&|])nc\s+(?:-[a-z]*\s+)*[a-z0-9]",
    )
)

_SQLI_XSS_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bunion\s+(?:all\s+)?select\b",
        r"\bselect\b[\s\S]{0,120}\bfrom\b",
        r"\b(?:insert\s+into|delete\s+from|drop\s+(?:table|database))\b",
        r"\bupdate\s+[a-z0-9_.$`\"']+\s+set\b",
        r"\b(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"\b(?:sleep|benchmark)\s*\(",
        r"(?:--(?:\s|$)|/\*|\*/)",
        r"<\s*/?\s*script\b",
        r"\bjavascript\s*:",
        r"\bon(?:error|load|click|mouseover|focus)\s*=",
        r"<\s*(?:img|svg|iframe|object)\b",
        r"\b(?:alert|prompt|confirm)\s*\(",
        r"\bdocument\s*\.\s*cookie\b",
    )
)


def _parse_timestamp(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("timestamp_utc must be a non-empty ISO-8601 value")
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def _safe_json(value: Any) -> Any:
    if isinstance(value, (Mapping, list, tuple)):
        return value
    text = str(value or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


def _find_username(value: Any) -> str | None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _normalized_key(key) in _USERNAME_KEYS:
                candidate = str(item or "").strip().lower()
                if candidate not in _REDACTED_VALUES:
                    return candidate
        for item in value.values():
            candidate = _find_username(item)
            if candidate:
                return candidate
    elif isinstance(value, (list, tuple)):
        for item in value:
            candidate = _find_username(item)
            if candidate:
                return candidate
    return None


def _username_token(row: Mapping[str, Any]) -> str | None:
    for field_name in ("payload_json", "metadata_json"):
        candidate = _find_username(_safe_json(row.get(field_name)))
        if candidate:
            return hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    return None


def _evidence_text(row: Mapping[str, Any]) -> str:
    return "\n".join(
        str(row.get(field_name) or "")
        for field_name in ("request_path", "payload_json", "metadata_json")
    )


def _count_patterns(text: str, patterns: Sequence[re.Pattern[str]]) -> int:
    return sum(len(tuple(pattern.finditer(text))) for pattern in patterns)


def _payload_length(row: Mapping[str, Any]) -> float:
    value = row.get("payload_length")
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        number = math.nan
    if math.isfinite(number) and number >= 0:
        return number
    return float(len(str(row.get("payload_json") or "")))


def _is_failed(row: Mapping[str, Any]) -> bool:
    status = str(row.get("status") or "").strip().lower().replace("-", "_")
    return status in _FAILED_STATUSES


def _prune(queue: Deque[float], cutoff: float) -> None:
    while queue and queue[0] < cutoff:
        queue.popleft()


@dataclass
class FeatureEngineeringState:
    """Mutable history used to transform chronologically later rows."""

    request_times: MutableMapping[tuple[str, str], Deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    failed_times: MutableMapping[tuple[str, str], Deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    username_times: MutableMapping[
        tuple[str, str, str], Deque[float]
    ] = field(default_factory=lambda: defaultdict(deque))
    previous_time: dict[tuple[str, str], float] = field(default_factory=dict)
    session_start: dict[tuple[str, str], float] = field(default_factory=dict)


def engineer_rows(
    rows: Sequence[Mapping[str, Any]],
    *,
    state: FeatureEngineeringState | None = None,
) -> list[dict[str, Any]]:
    """Add all Step 8 features using only current and chronologically past rows.

    The input order is preserved. A shared state may be passed from the
    training portion to the chronologically later test portion so test rows
    receive realistic past context without allowing test data to affect any
    training feature.
    """

    history = state if state is not None else FeatureEngineeringState()
    featured_rows: list[dict[str, Any]] = []

    for row in rows:
        timestamp = _parse_timestamp(row.get("_timestamp") or row.get("timestamp_utc"))
        current_time = timestamp.timestamp()
        source = str(row.get("source_ip_hash") or "missing-source").strip()
        service = str(row.get("service") or "missing-service").strip().lower()
        group = (source, service)

        previous = history.previous_time.get(group)
        if previous is not None and current_time < previous:
            raise ValueError(
                "rows must be chronological within each source/service group"
            )

        delta = 0.0 if previous is None else current_time - previous
        if previous is None or delta > SESSION_TIMEOUT_SECONDS:
            history.session_start[group] = current_time
        session_duration = current_time - history.session_start[group]

        requests = history.request_times[group]
        _prune(requests, current_time - RATE_WINDOW_SECONDS)
        requests.append(current_time)

        failed = history.failed_times[group]
        _prune(failed, current_time - RATE_WINDOW_SECONDS)
        if _is_failed(row):
            failed.append(current_time)

        username_repetition = 0
        username = _username_token(row)
        if username:
            username_key = (source, service, username)
            username_history = history.username_times[username_key]
            _prune(username_history, current_time - USERNAME_WINDOW_SECONDS)
            username_repetition = len(username_history)
            username_history.append(current_time)

        evidence = _evidence_text(row)
        featured = dict(row)
        featured.update(
            {
                "failed_attempts": len(failed),
                "requests_per_minute": len(requests),
                "payload_length": _payload_length(row),
                "session_duration": session_duration,
                "suspicious_keyword_count": _count_patterns(
                    evidence, _SUSPICIOUS_PATTERNS
                ),
                "username_repetition": username_repetition,
                "time_between_requests": delta,
                "sqli_xss_pattern_count": _count_patterns(
                    evidence, _SQLI_XSS_PATTERNS
                ),
            }
        )
        featured_rows.append(featured)
        history.previous_time[group] = current_time

    return featured_rows
