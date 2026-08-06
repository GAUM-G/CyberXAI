"""Assign deterministic Step 14 threat levels to hybrid IDS results.

The reporter consumes inference results produced by ``hybrid_ids.py``.  It
does not inspect model artifacts, retrain a model, or change the attack
prediction.  Scores use only the agreed Step 14 inputs: attack type,
confidence, repetition, affected service, and anomaly score.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Mapping


THREAT_REPORTING_VERSION = "1.0"
DEFAULT_REPETITION_WINDOW_SECONDS = 60

THREAT_LEVEL_RANGES = (
    ("Low", 0, 24),
    ("Medium", 25, 49),
    ("High", 50, 74),
    ("Critical", 75, 100),
)

ATTACK_TYPE_POINTS = {
    "normal": 0,
    "other_anomaly": 20,
    "port_scanning": 22,
    "directory_scanning": 25,
    "ftp_bruteforce": 32,
    "ssh_bruteforce": 35,
    "xss": 38,
    "sql_injection": 45,
}

SERVICE_POINTS = {
    "http": 7,
    "website": 7,
    "ftp": 8,
    "ssh": 10,
}


def _normalized_text(value: Any, *, field: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        raise ValueError(f"{field} must be a non-empty value")
    return text


def _finite_number(
    value: Any,
    *,
    field: str,
    allow_none: bool = False,
) -> float | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite number")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a finite number") from exc
    if not math.isfinite(number):
        raise ValueError(f"{field} must be a finite number")
    return number


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            raise ValueError("timestamp must be present for threat reporting")
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(
                "timestamp must be a valid ISO-8601 value"
            ) from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def threat_level_for_score(score: int) -> str:
    """Map a validated integer score to the agreed four threat levels."""

    if isinstance(score, bool) or not isinstance(score, int):
        raise ValueError("threat score must be an integer")
    if not 0 <= score <= 100:
        raise ValueError("threat score must be between 0 and 100")
    for level, minimum, maximum in THREAT_LEVEL_RANGES:
        if minimum <= score <= maximum:
            return level
    raise RuntimeError("threat score did not match a configured range")


def _confidence_points(confidence: float | None) -> int:
    if confidence is None:
        return 0
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1 or null")
    return min(20, int(round(confidence * 20.0)))


def _repetition_points(count: int) -> int:
    if count >= 5:
        return 25
    if count >= 3:
        return 15
    if count == 2:
        return 8
    return 0


def _anomaly_points(score: float) -> int:
    if score >= 0.15:
        return 15
    if score >= 0.10:
        return 12
    if score >= 0.05:
        return 8
    if score > 0.0:
        return 4
    return 0


class ThreatReporter:
    """Stateful, causal scorer for chronologically processed IDS incidents."""

    def __init__(
        self,
        *,
        repetition_window_seconds: int = DEFAULT_REPETITION_WINDOW_SECONDS,
    ) -> None:
        if (
            isinstance(repetition_window_seconds, bool)
            or not isinstance(repetition_window_seconds, int)
            or repetition_window_seconds <= 0
        ):
            raise ValueError(
                "repetition window seconds must be a positive integer"
            )
        self.repetition_window_seconds = repetition_window_seconds
        self._incident_times: dict[
            tuple[str, str, str], deque[datetime]
        ] = defaultdict(deque)
        self._lock = RLock()

    def _record_incident(
        self,
        *,
        source_ip: str,
        service: str,
        attack_type: str,
        timestamp: datetime,
    ) -> int:
        key = (source_ip, service, attack_type)
        cutoff = timestamp - timedelta(
            seconds=self.repetition_window_seconds
        )
        with self._lock:
            history = self._incident_times[key]
            causal_times = sorted(
                item for item in history if cutoff <= item <= timestamp
            )
            causal_times.append(timestamp)
            self._incident_times[key] = deque(causal_times)
            return len(causal_times)

    def assess(
        self,
        event: Mapping[str, Any],
        ids_result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Return threat fields for one event/result pair."""

        if not isinstance(event, Mapping):
            raise ValueError("event must be a mapping")
        if not isinstance(ids_result, Mapping):
            raise ValueError("IDS result must be a mapping")

        source_ip = _normalized_text(
            event.get("source_ip"),
            field="source_ip",
        )
        service = _normalized_text(
            ids_result.get("service", event.get("service")),
            field="service",
        )
        attack_type = _normalized_text(
            ids_result.get("attack_type"),
            field="attack_type",
        )
        prediction = _normalized_text(
            ids_result.get("prediction"),
            field="prediction",
        )
        if prediction not in {"normal", "attack"}:
            raise ValueError("prediction must be normal or attack")

        confidence = _finite_number(
            ids_result.get("confidence"),
            field="confidence",
            allow_none=True,
        )
        if confidence is not None and not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1 or null")
        anomaly_value = _finite_number(
            ids_result.get("anomaly_score"),
            field="anomaly_score",
        )
        if anomaly_value is None:
            raise ValueError("anomaly_score must be a finite number")
        anomaly_score = anomaly_value
        timestamp = _parse_timestamp(event.get("timestamp"))

        if prediction == "normal":
            incident_count = 0
            points = {
                "attack_type": 0,
                "confidence": 0,
                "repetition": 0,
                "service": 0,
                "anomaly_score": 0,
            }
        else:
            incident_count = self._record_incident(
                source_ip=source_ip,
                service=service,
                attack_type=attack_type,
                timestamp=timestamp,
            )
            points = {
                "attack_type": ATTACK_TYPE_POINTS.get(attack_type, 25),
                "confidence": _confidence_points(confidence),
                "repetition": _repetition_points(incident_count),
                "service": SERVICE_POINTS.get(service, 5),
                "anomaly_score": _anomaly_points(anomaly_score),
            }

        threat_score = min(100, sum(points.values()))
        threat_level = threat_level_for_score(threat_score)
        factors = [
            {
                "factor": "attack_type",
                "value": attack_type,
                "points": points["attack_type"],
            },
            {
                "factor": "confidence",
                "value": (
                    None if confidence is None else round(confidence, 6)
                ),
                "points": points["confidence"],
            },
            {
                "factor": "repetition",
                "value": incident_count,
                "window_seconds": self.repetition_window_seconds,
                "points": points["repetition"],
            },
            {
                "factor": "service",
                "value": service,
                "points": points["service"],
            },
            {
                "factor": "anomaly_score",
                "value": round(anomaly_score, 6),
                "points": points["anomaly_score"],
            },
        ]

        return {
            "threat_reporting_version": THREAT_REPORTING_VERSION,
            "threat_level": threat_level,
            "threat_score": threat_score,
            "threat_factors": factors,
        }
