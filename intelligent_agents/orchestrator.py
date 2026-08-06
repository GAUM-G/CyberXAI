"""Ordered Step 22 agent pipeline and daily-report persistence."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path
from threading import RLock
from typing import Any, Mapping

from core.time_utils import now_ist_iso
from intelligent_agents.agents import (
    DailyReportAgent,
    DetectionAgent,
    EventCorrelationAgent,
    ExplanationAgent,
    ResponseAgent,
    SeverityAgent,
)


AGENT_PIPELINE_VERSION = "1.0"
AGENT_RUN_ORDER = (
    "detection",
    "correlation",
    "severity",
    "explanation",
    "response",
    "daily_report",
)


class IntelligentAgentOrchestrator:
    """Run six bounded agents after the protected IDS has made its decision."""

    def __init__(
        self,
        *,
        correlation_window_seconds: int = 300,
        daily_report_directory: Path | None = None,
    ) -> None:
        self.detection = DetectionAgent()
        self.correlation = EventCorrelationAgent(
            window_seconds=correlation_window_seconds
        )
        self.severity = SeverityAgent()
        self.explanation = ExplanationAgent()
        self.response = ResponseAgent()
        self.daily_report = DailyReportAgent()
        self.daily_report_directory = (
            Path(daily_report_directory).resolve()
            if daily_report_directory is not None
            else None
        )
        self._lock = RLock()

    def _persist_daily_report(self, report: Mapping[str, Any]) -> None:
        if self.daily_report_directory is None:
            return
        self.daily_report_directory.mkdir(parents=True, exist_ok=True)
        day = str(report.get("report_date_ist") or "unknown")
        destination = self.daily_report_directory / f"daily_report_{day}.json"
        content = json.dumps(
            dict(report),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=str(self.daily_report_directory),
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            os.replace(temporary_name, destination)
        finally:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass

    def process(
        self,
        event: Mapping[str, Any],
        ids_result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Return agent analysis while proving protected IDS fields are unchanged."""

        if not isinstance(event, Mapping) or not isinstance(ids_result, Mapping):
            raise ValueError("event and IDS result must be mappings")

        protected_before = copy.deepcopy(
            {
                "prediction": ids_result.get("prediction"),
                "attack_type": ids_result.get("attack_type"),
                "threat_level": ids_result.get("threat_level"),
                "threat_score": ids_result.get("threat_score"),
                "xai": ids_result.get("xai"),
            }
        )

        with self._lock:
            detection = self.detection.analyze(ids_result)
            correlation = self.correlation.analyze(event, ids_result)
            severity = self.severity.analyze(ids_result, correlation)
            explanation = self.explanation.analyze(
                ids_result,
                detection,
                correlation,
                severity,
            )
            response = self.response.analyze(ids_result, severity)
            daily_report = self.daily_report.analyze(
                event,
                ids_result,
                severity,
                response,
            )
            self._persist_daily_report(daily_report)

        protected_after = {
            "prediction": ids_result.get("prediction"),
            "attack_type": ids_result.get("attack_type"),
            "threat_level": ids_result.get("threat_level"),
            "threat_score": ids_result.get("threat_score"),
            "xai": ids_result.get("xai"),
        }
        if protected_after != protected_before:
            raise RuntimeError("intelligent agents modified protected IDS output")

        return {
            "agent_pipeline_version": AGENT_PIPELINE_VERSION,
            "completed_at": now_ist_iso(),
            "run_order": list(AGENT_RUN_ORDER),
            "detection": detection,
            "correlation": correlation,
            "severity": severity,
            "explanation": explanation,
            "response": response,
            "daily_report": daily_report,
            "safety": {
                "original_prediction_changed": False,
                "original_threat_level_changed": False,
                "original_xai_changed": False,
                "model_fit_called": False,
                "host_firewall_changed": False,
                "raw_payload_included": False,
                "credentials_included": False,
            },
        }
