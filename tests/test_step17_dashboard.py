"""Regression tests for the additive Step 17 dashboard update."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dashboard import app as dashboard_module


NOW = datetime.now(timezone.utc).replace(microsecond=0)


def _result(
    event_id: str,
    *,
    minutes_ago: int,
    service: str,
    prediction: str,
    attack_type: str,
    threat_level: str,
    confidence: float,
    model_used: str,
) -> dict[str, object]:
    timestamp = (NOW - timedelta(minutes=minutes_ago)).isoformat()
    return {
        "event_id": event_id,
        "processed_at": timestamp,
        "timestamp": timestamp,
        "source_ip": f"192.0.2.{event_id}",
        "destination_port": {"ssh": 2222, "ftp": 2121, "http": 8080}[service],
        "service": service,
        "event_type": "attack" if prediction == "attack" else "connection",
        "event": f"{service}_{attack_type}",
        "status": "detected" if prediction == "attack" else "observed",
        "request_method": "GET" if service == "http" else None,
        "request_path": "/admin" if service == "http" else None,
        "attack_type": attack_type,
        "prediction": prediction,
        "confidence": confidence,
        "anomaly_score": 0.1,
        "model_used": model_used,
        "threat_level": threat_level,
        "threat_score": {
            "Low": 10,
            "Medium": 40,
            "High": 70,
            "Critical": 95,
        }[threat_level],
        "threat_factors": [],
        "components": {},
        "fusion_reason": "test fusion reason",
        "xai": {
            "shap": {"status": "ready", "top_features": []},
            "human_reason": {"summary": f"Sanitized reason for {attack_type}."},
        },
    }


def _results() -> list[dict[str, object]]:
    return [
        _result(
            "1",
            minutes_ago=5,
            service="http",
            prediction="attack",
            attack_type="sql_injection",
            threat_level="Critical",
            confidence=0.95,
            model_used="rules",
        ),
        _result(
            "2",
            minutes_ago=10,
            service="ssh",
            prediction="attack",
            attack_type="ssh_bruteforce",
            threat_level="High",
            confidence=0.85,
            model_used="lstm_classifier",
        ),
        _result(
            "3",
            minutes_ago=20,
            service="ftp",
            prediction="attack",
            attack_type="ftp_bruteforce",
            threat_level="Medium",
            confidence=0.75,
            model_used="decision_tree",
        ),
        _result(
            "4",
            minutes_ago=2,
            service="http",
            prediction="normal",
            attack_type="normal",
            threat_level="Low",
            confidence=0.65,
            model_used="isolation_forest",
        ),
    ]


class Step17SummaryTests(unittest.TestCase):
    def test_summary_adds_active_severity_model_and_confidence_metrics(self) -> None:
        stats = dashboard_module._compute_ids_stats(_results())

        self.assertEqual(stats["total_events"], 4)
        self.assertEqual(stats["threats_detected"], 3)
        self.assertEqual(stats["active_threats"], 2)
        self.assertEqual(stats["critical_incidents"], 1)
        self.assertEqual(stats["average_confidence"], 0.8)
        self.assertEqual(stats["by_threat_level"]["Critical"], 1)
        self.assertEqual(stats["by_model"]["rules"], 1)

    def test_service_statistics_keep_attack_and_active_counts_separate(self) -> None:
        rows = dashboard_module._ids_service_stats(
            _results(),
            now=NOW,
            active_window_minutes=15,
        )
        by_service = {row["service"]: row for row in rows}

        self.assertEqual(by_service["http"]["total_results"], 2)
        self.assertEqual(by_service["http"]["attacks"], 1)
        self.assertEqual(by_service["http"]["active_threats"], 1)
        self.assertEqual(by_service["http"]["critical"], 1)
        self.assertEqual(by_service["ftp"]["active_threats"], 0)

    def test_filter_options_are_derived_from_final_ids_results(self) -> None:
        options = dashboard_module._ids_filter_options(_results())

        self.assertEqual(options["services"], ["ftp", "http", "ssh"])
        self.assertIn("sql_injection", options["attack_types"])
        self.assertIn("Critical", options["threat_levels"])
        self.assertIn("lstm_classifier", options["models"])


@unittest.skipUnless(dashboard_module._FLASK_OK, "Flask not installed")
class Step17EndpointTests(unittest.TestCase):
    def test_ids_endpoint_preserves_old_fields_and_adds_step17_fields(self) -> None:
        original = dashboard_module._all_ids_results
        original_validator = dashboard_module._validate_portal_token
        dashboard_module._all_ids_results = lambda limit=2000: _results()[:limit]
        dashboard_module._validate_portal_token = (
            lambda token: {"id": 1, "username": "analyst"}
            if token == "test-token"
            else None
        )
        try:
            client = dashboard_module.create_dashboard_app().test_client()
            with client.session_transaction() as dashboard_session:
                dashboard_session["portal_token"] = "test-token"
            response = client.get("/api/ids")
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()

            for protected_field in (
                "source",
                "stats",
                "timeline",
                "top_ips",
                "recent_results",
            ):
                self.assertIn(protected_field, payload)
            for added_field in (
                "service_stats",
                "critical_incidents",
                "filter_options",
            ):
                self.assertIn(added_field, payload)

            self.assertEqual(payload["source"], "hybrid_ids_results")
            self.assertEqual(payload["stats"]["total_events"], 4)
            self.assertEqual(len(payload["critical_incidents"]), 1)
        finally:
            dashboard_module._all_ids_results = original
            dashboard_module._validate_portal_token = original_validator


class Step17TemplateProtectionTests(unittest.TestCase):
    def test_existing_dashboard_sections_and_step17_additions_coexist(self) -> None:
        template = (
            Path(dashboard_module.__file__).parent / "templates" / "index.html"
        ).read_text(encoding="utf-8")

        for protected_marker in (
            'id="sec-monitor"',
            'id="port-scan-panel"',
            'id="live-feed"',
            'id="sec-honeypot"',
            'id="cred-table-wrap"',
            'id="sec-ids"',
            'id="attack-breakdown"',
            'id="top-ips"',
            'id="timeline-canvas"',
            "Phase 2 — ML Detection Engine",
            'id="sec-xai"',
            "XAI Alert Reporter",
            'id="sec-report"',
            'href="/api/report/download"',
        ):
            self.assertIn(protected_marker, template)

        for added_marker in (
            'id="ids-active"',
            'id="ids-confidence"',
            'id="ids-severity-breakdown"',
            'id="ids-service-stats"',
            'id="ids-results-wrap"',
            'id="ids-critical-wrap"',
            'id="ids-detail-modal"',
        ):
            self.assertIn(added_marker, template)


if __name__ == "__main__":
    unittest.main()
