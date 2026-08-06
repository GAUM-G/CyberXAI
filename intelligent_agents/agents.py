"""Small, deterministic agents that collaborate after hybrid IDS inference.

The agents never train models, rewrite the protected IDS prediction, execute
host commands, or expose captured credentials.  They organize existing
evidence into operational decisions that remain reviewable by an analyst.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import RLock
from typing import Any, Mapping

from core.time_utils import IST, now_ist_iso, parse_datetime, to_ist_iso


AGENT_VERSION = "1.0"
THREAT_LEVELS = ("Low", "Medium", "High", "Critical")


def _text(value: Any, fallback: str = "unknown") -> str:
    text = str(value or "").strip()
    return text or fallback


def _confidence(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return round(max(0.0, min(float(value), 1.0)), 6)


def _agent_result(name: str, **payload: Any) -> dict[str, Any]:
    return {
        "agent": name,
        "version": AGENT_VERSION,
        "status": "completed",
        "completed_at": now_ist_iso(),
        **payload,
    }


class DetectionAgent:
    """Translate the immutable hybrid IDS decision into an agent finding."""

    name = "detection_agent"

    def analyze(self, result: Mapping[str, Any]) -> dict[str, Any]:
        prediction = _text(result.get("prediction"), "normal").lower()
        attack_type = _text(result.get("attack_type"), "normal").lower()
        components = (
            result.get("components")
            if isinstance(result.get("components"), Mapping)
            else {}
        )
        rules = (
            components.get("rules")
            if isinstance(components.get("rules"), Mapping)
            else {}
        )
        evidence_count = int(rules.get("finding_count") or 0)
        if prediction == "attack" and evidence_count == 0:
            evidence_count = sum(
                1
                for key in ("tabular", "sequence", "anomaly")
                if isinstance(components.get(key), Mapping)
            )

        return _agent_result(
            self.name,
            decision=prediction,
            attack_type=attack_type,
            confidence=_confidence(result.get("confidence")),
            model_used=_text(result.get("model_used")),
            evidence_count=evidence_count,
            reason=_text(result.get("fusion_reason"), "IDS decision recorded"),
            original_prediction_unchanged=True,
        )


@dataclass
class _Campaign:
    correlation_id: str
    first_seen: datetime
    last_seen: datetime
    event_ids: deque[str] = field(default_factory=lambda: deque(maxlen=50))
    services: Counter[str] = field(default_factory=Counter)
    attack_types: Counter[str] = field(default_factory=Counter)


class EventCorrelationAgent:
    """Correlate recent causal activity from the same source address."""

    name = "event_correlation_agent"

    def __init__(self, *, window_seconds: int = 300) -> None:
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = int(window_seconds)
        self._campaigns: dict[str, _Campaign] = {}
        self._lock = RLock()

    @staticmethod
    def _correlation_id(source_ip: str, event_id: str) -> str:
        digest = hashlib.sha256(
            f"{source_ip}|{event_id}".encode("utf-8")
        ).hexdigest()[:16]
        return f"campaign-{digest}"

    def analyze(
        self,
        event: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        source_ip = _text(event.get("source_ip"))
        event_id = _text(result.get("event_id"), _text(event.get("event_id")))
        observed_at = parse_datetime(
            event.get("timestamp") or result.get("timestamp")
        )
        service = _text(result.get("service"), _text(event.get("service")))
        attack_type = _text(result.get("attack_type"), "normal")

        with self._lock:
            campaign = self._campaigns.get(source_ip)
            expired = (
                campaign is None
                or observed_at - campaign.last_seen
                > timedelta(seconds=self.window_seconds)
                or observed_at < campaign.first_seen
            )
            if expired:
                campaign = _Campaign(
                    correlation_id=self._correlation_id(source_ip, event_id),
                    first_seen=observed_at,
                    last_seen=observed_at,
                )
                self._campaigns[source_ip] = campaign

            if event_id not in campaign.event_ids:
                campaign.event_ids.append(event_id)
                campaign.services[service] += 1
                campaign.attack_types[attack_type] += 1
            campaign.last_seen = max(campaign.last_seen, observed_at)

            count = len(campaign.event_ids)
            multi_service = len(campaign.services) > 1
            multi_attack = len(campaign.attack_types) > 1
            correlated = count >= 2
            reason = (
                f"{count} related event(s) from the same source were observed "
                f"within {self.window_seconds} seconds across "
                f"{len(campaign.services)} service(s)."
            )
            return _agent_result(
                self.name,
                correlation_id=campaign.correlation_id,
                correlated=correlated,
                related_event_count=count,
                window_seconds=self.window_seconds,
                first_seen=to_ist_iso(campaign.first_seen),
                last_seen=to_ist_iso(campaign.last_seen),
                services=sorted(campaign.services),
                attack_types=sorted(campaign.attack_types),
                multi_service=multi_service,
                multi_attack_type=multi_attack,
                recent_event_ids=list(campaign.event_ids)[-20:],
                reason=reason,
                raw_source_ip_exposed=False,
            )


class SeverityAgent:
    """Review threat level using correlation without overwriting Step 14."""

    name = "severity_agent"

    def analyze(
        self,
        result: Mapping[str, Any],
        correlation: Mapping[str, Any],
    ) -> dict[str, Any]:
        prediction = _text(result.get("prediction"), "normal").lower()
        base = _text(result.get("threat_level"), "Low").title()
        if base not in THREAT_LEVELS:
            base = "Low"

        related = int(correlation.get("related_event_count") or 1)
        multi_service = bool(correlation.get("multi_service"))
        should_escalate = (
            prediction == "attack"
            and base != "Critical"
            and (related >= 5 or (multi_service and related >= 3))
        )
        recommended = base
        if should_escalate:
            recommended = THREAT_LEVELS[
                min(THREAT_LEVELS.index(base) + 1, len(THREAT_LEVELS) - 1)
            ]

        base_score = int(result.get("threat_score") or 0)
        reviewed_score = min(100, base_score + (10 if should_escalate else 0))
        reason = (
            f"Escalated from {base} to {recommended} because {related} "
            "correlated events indicate repeated or multi-service activity."
            if should_escalate
            else f"Retained {base}; correlation did not meet escalation policy."
        )
        return _agent_result(
            self.name,
            base_level=base,
            recommended_level=recommended,
            base_score=base_score,
            reviewed_score=reviewed_score,
            escalated=should_escalate,
            reason=reason,
            original_threat_level_unchanged=True,
        )


class ExplanationAgent:
    """Combine model, correlation and severity evidence into safe prose."""

    name = "explanation_agent"

    def analyze(
        self,
        result: Mapping[str, Any],
        detection: Mapping[str, Any],
        correlation: Mapping[str, Any],
        severity: Mapping[str, Any],
    ) -> dict[str, Any]:
        xai = result.get("xai") if isinstance(result.get("xai"), Mapping) else {}
        human = (
            xai.get("human_reason")
            if isinstance(xai.get("human_reason"), Mapping)
            else {}
        )
        model_reason = _text(
            human.get("summary"),
            _text(result.get("fusion_reason"), "No model explanation available"),
        )
        related = int(correlation.get("related_event_count") or 1)
        summary = (
            f"{detection.get('decision', 'unknown').title()} decision for "
            f"{_text(detection.get('attack_type')).replace('_', ' ')}. "
            f"{model_reason} Correlation found {related} related event(s). "
            f"Recommended severity: {severity.get('recommended_level', 'Low')}."
        )
        return _agent_result(
            self.name,
            summary=summary,
            evidence=[
                {
                    "type": "model_decision",
                    "value": detection.get("model_used"),
                    "reason": detection.get("reason"),
                },
                {
                    "type": "correlation",
                    "value": correlation.get("correlation_id"),
                    "reason": correlation.get("reason"),
                },
                {
                    "type": "severity_review",
                    "value": severity.get("recommended_level"),
                    "reason": severity.get("reason"),
                },
            ],
            privacy={
                "raw_payload_included": False,
                "source_ip_included": False,
                "credentials_included": False,
            },
            original_xai_unchanged=True,
        )


class ResponseAgent:
    """Recommend a safe Step 21 simulation-only response."""

    name = "response_agent"
    ACTIONS = {
        "Low": "continue_monitoring",
        "Medium": "rate_limit",
        "High": "recommend_block",
        "Critical": "simulate_block",
    }

    def analyze(
        self,
        result: Mapping[str, Any],
        severity: Mapping[str, Any],
    ) -> dict[str, Any]:
        prediction = _text(result.get("prediction"), "normal").lower()
        level = _text(severity.get("recommended_level"), "Low").title()
        action = (
            self.ACTIONS.get(level, "continue_monitoring")
            if prediction == "attack"
            else "no_response"
        )
        durations = {
            "rate_limit": 300,
            "simulate_block": 900,
        }
        approval_required = action not in {"no_response", "continue_monitoring"}
        return _agent_result(
            self.name,
            recommended_action=action,
            duration_seconds=durations.get(action),
            execution="recommendation_only",
            requires_analyst_approval=approval_required,
            reason=(
                f"{level} activity maps to {action.replace('_', ' ')} under "
                "the simulation-only response policy."
            ),
            safety={
                "mode": "simulation",
                "automatic_host_blocking": False,
                "host_firewall_changed": False,
                "os_command_executed": False,
            },
        )


@dataclass
class _DailyMetrics:
    total_events: int = 0
    attacks_detected: int = 0
    critical_incidents: int = 0
    services: Counter[str] = field(default_factory=Counter)
    attack_types: Counter[str] = field(default_factory=Counter)
    severities: Counter[str] = field(default_factory=Counter)
    responses: Counter[str] = field(default_factory=Counter)
    sources: set[str] = field(default_factory=set)


class DailyReportAgent:
    """Maintain a privacy-safe in-memory report for each IST calendar day."""

    name = "daily_report_agent"

    def __init__(self) -> None:
        self._days: dict[str, _DailyMetrics] = defaultdict(_DailyMetrics)
        self._seen_event_ids: set[str] = set()
        self._lock = RLock()

    def analyze(
        self,
        event: Mapping[str, Any],
        result: Mapping[str, Any],
        severity: Mapping[str, Any],
        response: Mapping[str, Any],
    ) -> dict[str, Any]:
        event_id = _text(result.get("event_id"), _text(event.get("event_id")))
        event_time = parse_datetime(
            event.get("timestamp") or result.get("timestamp")
        ).astimezone(IST)
        day = event_time.date().isoformat()

        with self._lock:
            metrics = self._days[day]
            if event_id not in self._seen_event_ids:
                self._seen_event_ids.add(event_id)
                metrics.total_events += 1
                if _text(result.get("prediction"), "normal") == "attack":
                    metrics.attacks_detected += 1
                level = _text(severity.get("recommended_level"), "Low").title()
                if level == "Critical":
                    metrics.critical_incidents += 1
                metrics.services[_text(result.get("service"))] += 1
                metrics.attack_types[_text(result.get("attack_type"))] += 1
                metrics.severities[level] += 1
                metrics.responses[
                    _text(response.get("recommended_action"), "no_response")
                ] += 1
                metrics.sources.add(_text(event.get("source_ip")))

            return _agent_result(
                self.name,
                report_date_ist=day,
                timezone="Asia/Kolkata",
                generated_at=now_ist_iso(),
                total_events=metrics.total_events,
                attacks_detected=metrics.attacks_detected,
                critical_incidents=metrics.critical_incidents,
                unique_source_count=len(metrics.sources),
                by_service=dict(sorted(metrics.services.items())),
                by_attack_type=dict(sorted(metrics.attack_types.items())),
                by_recommended_severity=dict(sorted(metrics.severities.items())),
                by_response=dict(sorted(metrics.responses.items())),
                raw_source_ips_included=False,
                credentials_included=False,
            )
