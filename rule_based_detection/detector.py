"""Causal, explainable rules for recognizable honeypot attacks.

The Step 9 detector is intentionally independent of target labels and ML
models.  It consumes either sanitized Step 6 dataset rows or Step 3 common
events, evaluates only the current event and earlier in-memory state, and emits
evidence without copying raw request or credential text into findings.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import threading
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import unquote_plus


RULE_ENGINE_VERSION = "1.0"
DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_FAILURE_WINDOW_SECONDS = 60.0

_AUTH_SERVICES = frozenset({"ssh", "ftp", "http"})
_FAILURE_STATUSES = frozenset(
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
_SUCCESS_STATUSES = frozenset(
    {"accepted", "authenticated", "opened", "success", "successful"}
)
_AUTH_TERMS = re.compile(
    r"\b(auth(?:entication)?|credential|login|logon|password|signin|sign_in)\b",
    re.IGNORECASE,
)

# Each expression is deliberately paired with a stable evidence identifier.
# Findings expose identifiers and counts, never the matching attacker text.
_SQLI_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "sqli_boolean_tautology",
        re.compile(
            r"(?:['\"`]\s*)?\b(?:or|and)\b\s+"
            r"['\"`]?(?P<tautology_value>[a-z0-9_.-]+)['\"`]?\s*=\s*"
            r"['\"`]?(?P=tautology_value)['\"`]?",
            re.IGNORECASE,
        ),
    ),
    (
        "sqli_union_select",
        re.compile(r"\bunion(?:\s+all)?\s+select\b", re.IGNORECASE),
    ),
    (
        "sqli_stacked_statement",
        re.compile(
            r";\s*(?:alter|create|delete|drop|exec(?:ute)?|insert|truncate|update)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "sqli_database_enumeration",
        re.compile(
            r"\b(?:information_schema|pg_catalog|sqlite_master|sysobjects)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "sqli_time_delay",
        re.compile(
            r"\b(?:benchmark|pg_sleep|sleep)\s*\(|\bwaitfor\s+delay\b",
            re.IGNORECASE,
        ),
    ),
)

_XSS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "xss_script_tag",
        re.compile(r"<\s*/?\s*script\b", re.IGNORECASE),
    ),
    (
        "xss_javascript_uri",
        re.compile(r"\bjavascript\s*:", re.IGNORECASE),
    ),
    (
        "xss_event_handler",
        re.compile(
            r"\bon(?:error|focus|load|mouseover|pointerover|submit)\s*=",
            re.IGNORECASE,
        ),
    ),
    (
        "xss_dangerous_tag",
        re.compile(
            r"<\s*(?:iframe|object|embed|svg)\b[^>]*>",
            re.IGNORECASE,
        ),
    ),
)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (Mapping, list, tuple)):
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def _normalized(value: Any) -> str:
    return _text(value).strip().lower().replace("-", "_").replace(" ", "_")


def _parse_timestamp(value: Any) -> datetime | None:
    text = _text(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _timestamp_text(event: Mapping[str, Any]) -> str | None:
    parsed = _parse_timestamp(
        event.get("timestamp_utc")
        if event.get("timestamp_utc") not in (None, "")
        else event.get("timestamp")
    )
    return parsed.isoformat().replace("+00:00", "Z") if parsed else None


def _source_reference(event: Mapping[str, Any]) -> str:
    pseudonym = _text(event.get("source_ip_hash")).strip()
    if pseudonym:
        return pseudonym

    raw_source = _text(event.get("source_ip")).strip()
    if not raw_source:
        return "unknown"
    return hashlib.sha256(
        f"step9-rule-source:{raw_source}".encode("utf-8")
    ).hexdigest()[:16]


def _decoded_security_text(event: Mapping[str, Any]) -> str:
    """Return bounded, decoded text used only inside the detector."""

    selected = (
        event.get("request_path"),
        event.get("payload_json"),
        event.get("metadata_json"),
        event.get("payload"),
        event.get("metadata"),
    )
    combined = "\n".join(_text(value) for value in selected if value not in (None, ""))
    # Bound pathological records and decode common browser encodings twice.
    decoded = combined[:100_000]
    for _ in range(2):
        candidate = html.unescape(unquote_plus(decoded))
        if candidate == decoded:
            break
        decoded = candidate
    return decoded


def _matching_ids(
    text: str,
    patterns: tuple[tuple[str, re.Pattern[str]], ...],
) -> tuple[str, ...]:
    return tuple(rule_id for rule_id, pattern in patterns if pattern.search(text))


def _is_authentication_event(event: Mapping[str, Any], service: str) -> bool:
    if service not in _AUTH_SERVICES:
        return False
    context = " ".join(
        (
            _text(event.get("event_type")),
            _text(event.get("event")),
            _text(event.get("request_path")),
        )
    )
    context = re.sub(r"[_-]+", " ", context)
    if _AUTH_TERMS.search(context):
        return True
    # SSH/FTP status failures originate from authentication-focused honeypots.
    return service in {"ssh", "ftp"} and _normalized(event.get("status")) in _FAILURE_STATUSES


def _is_failed_authentication(event: Mapping[str, Any], service: str) -> bool:
    return (
        _normalized(event.get("status")) in _FAILURE_STATUSES
        and _is_authentication_event(event, service)
    )


def _is_successful_authentication(event: Mapping[str, Any], service: str) -> bool:
    return (
        _normalized(event.get("status")) in _SUCCESS_STATUSES
        and _is_authentication_event(event, service)
    )


@dataclass(frozen=True)
class RuleFinding:
    """One explainable Step 9 detection without raw attacker text."""

    schema_version: str
    rule_engine_version: str
    decision_source: str
    event_id: str | None
    timestamp_utc: str | None
    source_ref: str
    service: str
    attack_type: str
    severity: str
    confidence: float
    matched_rules: tuple[str, ...]
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        record = asdict(self)
        record["matched_rules"] = list(self.matched_rules)
        return record


class RuleBasedDetector:
    """Detect repeated failures, SQL injection and XSS causally."""

    def __init__(
        self,
        *,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        failure_window_seconds: float = DEFAULT_FAILURE_WINDOW_SECONDS,
    ) -> None:
        if failure_threshold < 2:
            raise ValueError("failure_threshold must be at least 2")
        if failure_window_seconds <= 0:
            raise ValueError("failure_window_seconds must be positive")

        self.failure_threshold = int(failure_threshold)
        self.failure_window_seconds = float(failure_window_seconds)
        self._failures: dict[
            tuple[str, str], deque[tuple[float, str | None]]
        ] = defaultdict(deque)
        self._failure_alert_active: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    @staticmethod
    def _finding(
        event: Mapping[str, Any],
        *,
        attack_type: str,
        severity: str,
        confidence: float,
        matched_rules: tuple[str, ...],
        evidence: dict[str, Any],
    ) -> RuleFinding:
        return RuleFinding(
            schema_version="1.0",
            rule_engine_version=RULE_ENGINE_VERSION,
            decision_source="rule_based",
            event_id=_text(event.get("event_id")).strip() or None,
            timestamp_utc=_timestamp_text(event),
            source_ref=_source_reference(event),
            service=_normalized(event.get("service")) or "unknown",
            attack_type=attack_type,
            severity=severity,
            confidence=round(float(confidence), 4),
            matched_rules=matched_rules,
            evidence=evidence,
        )

    def _repeated_failure_finding(
        self,
        event: Mapping[str, Any],
        *,
        service: str,
        source_ref: str,
    ) -> RuleFinding | None:
        timestamp = _parse_timestamp(
            event.get("timestamp_utc")
            if event.get("timestamp_utc") not in (None, "")
            else event.get("timestamp")
        )
        if timestamp is None:
            return None

        key = (source_ref, service)
        observed_at = timestamp.timestamp()
        cutoff = observed_at - self.failure_window_seconds

        with self._lock:
            history = self._failures[key]
            while history and history[0][0] < cutoff:
                history.popleft()

            if _is_successful_authentication(event, service):
                history.clear()
                self._failure_alert_active.discard(key)
                return None

            if not _is_failed_authentication(event, service):
                if len(history) < self.failure_threshold:
                    self._failure_alert_active.discard(key)
                return None

            event_id = _text(event.get("event_id")).strip() or None
            history.append((observed_at, event_id))
            if len(history) < self.failure_threshold:
                self._failure_alert_active.discard(key)
                return None
            if key in self._failure_alert_active:
                return None

            self._failure_alert_active.add(key)
            attack_type = (
                f"{service}_bruteforce"
                if service in {"ssh", "ftp"}
                else "http_bruteforce"
            )
            return self._finding(
                event,
                attack_type=attack_type,
                severity="critical",
                confidence=min(0.99, 0.80 + 0.03 * len(history)),
                matched_rules=("repeated_login_failures",),
                evidence={
                    "failure_count": len(history),
                    "threshold": self.failure_threshold,
                    "window_seconds": self.failure_window_seconds,
                    "grouping": "source_ref+service",
                },
            )

    def inspect(self, event: Mapping[str, Any]) -> list[RuleFinding]:
        """Inspect one event and return zero or more independent findings."""

        if not isinstance(event, Mapping):
            return []

        findings: list[RuleFinding] = []
        service = _normalized(event.get("service")) or "unknown"
        source_ref = _source_reference(event)

        failure_finding = self._repeated_failure_finding(
            event,
            service=service,
            source_ref=source_ref,
        )
        if failure_finding is not None:
            findings.append(failure_finding)

        security_text = _decoded_security_text(event)
        sqli_matches = _matching_ids(security_text, _SQLI_PATTERNS)
        if sqli_matches:
            findings.append(
                self._finding(
                    event,
                    attack_type="sql_injection",
                    severity="critical",
                    confidence=min(0.99, 0.91 + 0.02 * len(sqli_matches)),
                    matched_rules=sqli_matches,
                    evidence={
                        "pattern_match_count": len(sqli_matches),
                        "inspected_fields": [
                            "request_path",
                            "payload",
                            "metadata",
                        ],
                        "raw_text_included": False,
                    },
                )
            )

        xss_matches = _matching_ids(security_text, _XSS_PATTERNS)
        if xss_matches:
            findings.append(
                self._finding(
                    event,
                    attack_type="xss",
                    severity="critical",
                    confidence=min(0.99, 0.91 + 0.02 * len(xss_matches)),
                    matched_rules=xss_matches,
                    evidence={
                        "pattern_match_count": len(xss_matches),
                        "inspected_fields": [
                            "request_path",
                            "payload",
                            "metadata",
                        ],
                        "raw_text_included": False,
                    },
                )
            )

        return findings

    def reset(self) -> None:
        """Clear state for an isolated run or test."""

        with self._lock:
            self._failures.clear()
            self._failure_alert_active.clear()
