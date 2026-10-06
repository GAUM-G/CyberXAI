"""Focused tests for Step 16 real-time IDS/backend adapter integration."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from uuid import uuid4

from core.event_schema import build_common_event
from dashboard import app as dashboard_module
from tests.dashboard_auth_helpers import make_authenticated_dashboard_client
from machine_learning.realtime_ids import (
    RealtimeIDSService,
    build_integrated_result,
)
from simulation.n8n import normalize_record


class FakeArtifacts:
    def __init__(self) -> None:
        self.verify_calls = 0

    def verify_unchanged(self) -> None:
        self.verify_calls += 1


class FakeEngine:
    def __init__(self) -> None:
        self.artifacts = FakeArtifacts()
        self.calls: list[dict[str, object]] = []

    def process_event(self, event: dict[str, object]) -> dict[str, object]:
        self.calls.append(event)
        return sample_ids_result(str(event["event_id"]))


def sample_event() -> dict[str, object]:
    return build_common_event(
        event_id=str(uuid4()),
        timestamp="2026-07-28T08:15:00+00:00",
        source_ip="127.0.0.1",
        source_port=49152,
        destination_port=8080,
        service="http",
        protocol="http",
        event_type="attack",
        event="http_search_sql_injection",
        attack_type="untrusted_producer_value",
        status="detected",
        request_method="GET",
        request_path="/search",
        username="private-user",
        payload={
            "query": "' OR '1'='1",
            "password": "never-copy-this-secret",
        },
        metadata={"password": "never-copy-this-secret"},
        severity="critical",
    )


def sample_ids_result(event_id: str) -> dict[str, object]:
    return {
        "hybrid_ids_version": "1.2",
        "event_id": event_id,
        "timestamp": "2026-07-28T08:15:00+00:00",
        "service": "http",
        "attack_type": "sql_injection",
        "prediction": "attack",
        "confidence": 0.93,
        "anomaly_score": 0.04,
        "model_used": "rules",
        "threat_reporting_version": "1.0",
        "threat_level": "Critical",
        "threat_score": 91,
        "threat_factors": [{"factor": "attack_type", "points": 45}],
        "components": {
            "rules": {"finding_count": 1, "findings": []},
            "tabular": {
                "model": "decision_tree",
                "attack_type": "normal",
                "confidence": 0.8,
            },
            "sequence": {
                "model": "lstm_classifier",
                "attack_type": "normal",
                "confidence": 0.8,
                "context_events": 1,
                "sequence_length": 10,
            },
            "anomaly": {
                "model": "isolation_forest",
                "is_anomaly": False,
                "anomaly_score": 0.04,
            },
        },
        "fusion_reason": "deterministic rule matched",
        "safety": {
            "model_fit_called": False,
            "protected_artifacts_modified": False,
            "producer_attack_type_used_as_model_feature": False,
            "raw_payload_in_result": False,
            "future_events_used": False,
            "xai_changed_prediction": False,
        },
        "xai": {
            "xai_version": "1.0",
            "lime_used": False,
            "shap": {"status": "ready", "top_features": []},
            "human_reason": {
                "summary": "A sanitized SQL security pattern matched."
            },
            "privacy": {
                "raw_payload_included": False,
                "source_ip_included": False,
                "credentials_included": False,
            },
            "safety": {
                "prediction_changed": False,
                "model_fit_called": False,
                "artifact_written": False,
            },
        },
    }


class Step16IntegrationTests(unittest.TestCase):
    def test_integrated_result_uses_safe_context_only(self) -> None:
        event = sample_event()
        result = build_integrated_result(
            event,
            sample_ids_result(str(event["event_id"])),
            processed_at="2026-07-28T08:15:01+00:00",
        )

        self.assertEqual(result["source_ip"], "127.0.0.1")
        self.assertEqual(result["request_path"], "/search")
        self.assertEqual(result["ids_result_schema_version"], "1.0")
        self.assertNotIn("payload", result)
        self.assertNotIn("metadata", result)
        self.assertNotIn("username", result)
        serialized = json.dumps(result)
        self.assertNotIn("never-copy-this-secret", serialized)
        self.assertFalse(result["integration"]["raw_payload_included"])
        self.assertFalse(result["integration"]["credentials_included"])
        self.assertFalse(
            result["integration"]["producer_attack_type_used_as_prediction"]
        )
        self.assertFalse(result["xai"]["privacy"]["source_ip_included"])

    def test_service_persists_first_and_delivers_without_retraining(self) -> None:
        delivered: list[dict[str, object]] = []
        delivered_event = threading.Event()

        def deliver(record: dict[str, object]) -> str:
            delivered.append(record)
            delivered_event.set()
            return "success"

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            engine = FakeEngine()
            service = RealtimeIDSService(
                engine,  # type: ignore[arg-type]
                log_path=root / "not-created-yet.jsonl",
                output_path=root / "ids-results.jsonl",
                backend_url="http://test.invalid/api/ids-results",
                poll_seconds=0.01,
                backend_retry_seconds=0.01,
                delivery_function=deliver,
            )
            service.start()
            integrated = service.process_event(sample_event())

            self.assertTrue(delivered_event.wait(timeout=2.0))
            service.stop()

            records = [
                json.loads(line)
                for line in (root / "ids-results.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line
            ]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["event_id"], integrated["event_id"])
            self.assertEqual(delivered[0]["event_id"], integrated["event_id"])
            self.assertEqual(engine.artifacts.verify_calls, 1)
            self.assertEqual(len(engine.calls), 1)

    def test_dashboard_summary_counts_final_predictions(self) -> None:
        event = sample_event()
        integrated = build_integrated_result(
            event,
            sample_ids_result(str(event["event_id"])),
            processed_at="2026-07-28T08:15:01+00:00",
        )
        stats = dashboard_module._compute_ids_stats([integrated])
        timeline = dashboard_module._timeline([integrated], buckets=4)

        self.assertEqual(stats["total_events"], 1)
        self.assertEqual(stats["threats_detected"], 1)
        self.assertEqual(stats["unique_ips"], 1)
        self.assertEqual(stats["by_attack"]["sql_injection"], 1)
        self.assertEqual(sum(bucket["threats"] for bucket in timeline), 1)

    @unittest.skipUnless(dashboard_module._FLASK_OK, "Flask not installed")
    def test_dashboard_ids_endpoint_uses_final_predictions(self) -> None:
        event = sample_event()
        integrated = build_integrated_result(
            event,
            sample_ids_result(str(event["event_id"])),
            processed_at="2026-07-28T08:15:01+00:00",
        )
        original = dashboard_module._all_ids_results
        dashboard_module._all_ids_results = lambda limit=2000: [integrated][
            :limit
        ]
        try:
            client = make_authenticated_dashboard_client(self)
            response = client.get("/api/ids")
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertEqual(payload["source"], "hybrid_ids_results")
            self.assertEqual(payload["stats"]["total_events"], 1)
            self.assertEqual(payload["stats"]["threats_detected"], 1)
            self.assertEqual(
                payload["stats"]["by_attack"]["sql_injection"],
                1,
            )
            self.assertEqual(payload["top_ips"][0]["ip"], "127.0.0.1")
            self.assertEqual(
                payload["recent_results"][0]["xai"]["shap"]["status"],
                "ready",
            )
        finally:
            dashboard_module._all_ids_results = original

    def test_n8n_ids_adapter_preserves_existing_webhook_fields(self) -> None:
        event = sample_event()
        integrated = build_integrated_result(
            event,
            sample_ids_result(str(event["event_id"])),
            processed_at="2026-07-28T08:15:01+00:00",
        )
        payload = normalize_record(integrated, source="ids")

        self.assertEqual(payload["severity"], "critical")
        self.assertEqual(payload["ip"], "127.0.0.1")
        self.assertEqual(payload["type"], "http")
        self.assertEqual(payload["attack_type"], "sql_injection")
        self.assertEqual(payload["target"], "/search")
        self.assertEqual(payload["threat_level"], "Critical")
        self.assertEqual(payload["threat_score"], 91)
        self.assertEqual(payload["source"], "hybrid_ids_result")
        self.assertIn("sanitized SQL", payload["xai_summary"])


if __name__ == "__main__":
    unittest.main()
