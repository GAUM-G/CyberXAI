"""Focused tests for Step 22 agent order, safety, IST and persistence."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from core.event_schema import build_common_event
from core.time_utils import IST_OFFSET, now_ist_iso
from intelligent_agents.orchestrator import (
    AGENT_RUN_ORDER,
    IntelligentAgentOrchestrator,
)
from machine_learning.realtime_ids import build_integrated_result


def ids_result(event_id: str, timestamp: str) -> dict[str, object]:
    return {
        "hybrid_ids_version": "1.2",
        "event_id": event_id,
        "timestamp": timestamp,
        "service": "http",
        "attack_type": "sql_injection",
        "prediction": "attack",
        "confidence": 0.96,
        "anomaly_score": 0.02,
        "model_used": "rules",
        "threat_reporting_version": "1.0",
        "threat_level": "High",
        "threat_score": 71,
        "threat_factors": [],
        "components": {
            "rules": {"finding_count": 1, "findings": []},
            "tabular": {},
            "sequence": {},
            "anomaly": {},
        },
        "fusion_reason": "deterministic SQL injection rule matched",
        "xai": {
            "shap": {"status": "ready", "top_features": []},
            "human_reason": {"summary": "A sanitized SQL pattern matched."},
            "privacy": {
                "raw_payload_included": False,
                "source_ip_included": False,
                "credentials_included": False,
            },
        },
        "safety": {
            "model_fit_called": False,
            "protected_artifacts_modified": False,
            "xai_changed_prediction": False,
        },
    }


def event(second: int = 0) -> dict[str, object]:
    return build_common_event(
        event_id=str(uuid4()),
        timestamp=f"2026-08-03T12:00:{second:02d}+00:00",
        source_ip="192.0.2.25",
        destination_port=8080,
        service="http",
        protocol="http",
        event_type="attack",
        event="http_login_sql_injection",
        attack_type="sql_injection",
        severity="critical",
        status="detected",
        request_method="POST",
        request_path="/login",
        payload={"username": "private", "password": "do-not-copy"},
        metadata={"password": "do-not-copy"},
    )


class Step22IntelligentAgentTests(unittest.TestCase):
    def test_runtime_clock_records_explicit_ist_offset(self) -> None:
        self.assertTrue(now_ist_iso().endswith(IST_OFFSET))
        self.assertTrue(str(event()["timestamp"]).endswith(IST_OFFSET))

    def test_six_agents_run_in_order_without_changing_ids_output(self) -> None:
        source = event()
        integrated = build_integrated_result(
            source,
            ids_result(str(source["event_id"]), str(source["timestamp"])),
        )
        protected = {
            key: json.loads(json.dumps(integrated[key]))
            for key in ("prediction", "attack_type", "threat_level", "xai")
        }

        with tempfile.TemporaryDirectory() as directory:
            orchestrator = IntelligentAgentOrchestrator(
                daily_report_directory=Path(directory)
            )
            agents = orchestrator.process(source, integrated)

            self.assertEqual(agents["run_order"], list(AGENT_RUN_ORDER))
            for name in AGENT_RUN_ORDER:
                self.assertEqual(agents[name]["status"], "completed")
                self.assertTrue(agents[name]["completed_at"].endswith("+05:30"))

            self.assertEqual(integrated["prediction"], protected["prediction"])
            self.assertEqual(integrated["attack_type"], protected["attack_type"])
            self.assertEqual(integrated["threat_level"], protected["threat_level"])
            self.assertEqual(integrated["xai"], protected["xai"])
            self.assertFalse(agents["safety"]["original_prediction_changed"])
            self.assertFalse(agents["safety"]["host_firewall_changed"])

            reports = list(Path(directory).glob("daily_report_*.json"))
            self.assertEqual(len(reports), 1)
            report = json.loads(reports[0].read_text(encoding="utf-8"))
            self.assertEqual(report["total_events"], 1)
            self.assertFalse(report["credentials_included"])
            self.assertNotIn("do-not-copy", reports[0].read_text(encoding="utf-8"))

    def test_locked_daily_report_never_stops_ids_processing(self) -> None:
        source = event()
        integrated = build_integrated_result(
            source,
            ids_result(str(source["event_id"]), str(source["timestamp"])),
        )

        with tempfile.TemporaryDirectory() as directory:
            orchestrator = IntelligentAgentOrchestrator(
                daily_report_directory=Path(directory)
            )
            with patch(
                "intelligent_agents.orchestrator.os.replace",
                side_effect=PermissionError("report is temporarily locked"),
            ), patch("intelligent_agents.orchestrator.time.sleep"):
                agents = orchestrator.process(source, integrated)

        self.assertEqual(agents["detection"]["status"], "completed")
        self.assertEqual(agents["daily_report_persistence"]["status"], "deferred")
        self.assertFalse(
            agents["daily_report_persistence"]["required_for_detection"]
        )

    def test_correlation_escalates_repeated_high_activity_to_critical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = IntelligentAgentOrchestrator(
                daily_report_directory=Path(directory),
                correlation_window_seconds=300,
            )
            latest = None
            for index in range(5):
                source = event(index)
                integrated = build_integrated_result(
                    source,
                    ids_result(
                        str(source["event_id"]),
                        str(source["timestamp"]),
                    ),
                )
                latest = orchestrator.process(source, integrated)

            assert latest is not None
            self.assertEqual(
                latest["correlation"]["related_event_count"],
                5,
            )
            self.assertTrue(latest["correlation"]["correlated"])
            self.assertTrue(latest["severity"]["escalated"])
            self.assertEqual(
                latest["severity"]["recommended_level"],
                "Critical",
            )
            self.assertEqual(
                latest["response"]["recommended_action"],
                "simulate_block",
            )
            self.assertEqual(
                latest["response"]["execution"],
                "recommendation_only",
            )
            self.assertFalse(
                latest["response"]["safety"]["automatic_host_blocking"]
            )


if __name__ == "__main__":
    unittest.main()
