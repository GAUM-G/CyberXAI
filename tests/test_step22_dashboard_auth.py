"""Step 22 authentication gate and intelligent-agent dashboard tests."""

from __future__ import annotations

import unittest
from pathlib import Path

from dashboard import app as dashboard_module


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(dashboard_module._FLASK_OK, "Flask not installed")
class Step22DashboardAuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_login = dashboard_module._portal_login
        self.original_validator = dashboard_module._validate_portal_token
        self.original_results = dashboard_module._all_ids_results
        dashboard_module._portal_login = lambda username, password: {
            "token": "valid-test-token",
            "user": {"id": 1, "username": username, "email": "a@example.test"},
        }
        dashboard_module._validate_portal_token = (
            lambda token: {"id": 1, "username": "analyst"}
            if token == "valid-test-token"
            else None
        )
        dashboard_module._all_ids_results = lambda limit=2000: [
            {
                "event_id": "event-1",
                "timestamp": "2026-08-03T17:30:00+05:30",
                "processed_at": "2026-08-03T17:30:01+05:30",
                "source_ip": "192.0.2.25",
                "service": "http",
                "attack_type": "sql_injection",
                "prediction": "attack",
                "confidence": 0.95,
                "model_used": "rules",
                "threat_level": "Critical",
                "agents": {
                    "agent_pipeline_version": "1.0",
                    "correlation": {
                        "correlated": True,
                        "correlation_id": "campaign-test",
                    },
                    "severity": {"escalated": True},
                    "response": {"recommended_action": "simulate_block"},
                    "daily_report": {
                        "report_date_ist": "2026-08-03",
                        "total_events": 1,
                        "attacks_detected": 1,
                        "critical_incidents": 1,
                    },
                },
            }
        ][:limit]
        self.client = dashboard_module.create_dashboard_app().test_client()

    def tearDown(self) -> None:
        dashboard_module._portal_login = self.original_login
        dashboard_module._validate_portal_token = self.original_validator
        dashboard_module._all_ids_results = self.original_results

    def test_sensitive_dashboard_apis_reject_access_before_login(self) -> None:
        for path in (
            "/api/monitor",
            "/api/honeypot",
            "/api/credentials",
            "/api/ids",
            "/api/agents",
            "/api/xai/alerts",
            "/api/report",
            "/stream",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401)

    def test_valid_login_unlocks_ids_xai_and_agent_data(self) -> None:
        login = self.client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "test"},
        )
        self.assertEqual(login.status_code, 200)
        self.assertTrue(login.get_json()["authenticated"])

        self.assertEqual(self.client.get("/api/ids").status_code, 200)
        agents = self.client.get("/api/agents")
        self.assertEqual(agents.status_code, 200)
        payload = agents.get_json()
        self.assertEqual(payload["analyzed_results"], 1)
        self.assertEqual(payload["correlated_campaigns"], 1)
        self.assertEqual(payload["severity_escalations"], 1)

        logout = self.client.post("/api/auth/logout")
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(self.client.get("/api/ids").status_code, 401)

    def test_page_hides_all_dashboard_content_behind_login_gate(self) -> None:
        body = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="dashboard-auth-gate"', body)
        self.assertIn('id="dashboard-app" hidden', body)
        self.assertIn('id="sec-agents"', body)
        self.assertNotIn(
            "The XAI evidence is available without signing in",
            body,
        )


class Step22SourceSafetyTests(unittest.TestCase):
    def test_decoy_port_8080_remains_public_and_unmodified_by_auth_gate(self) -> None:
        dashboard = (ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
        honeypot = (
            ROOT / "core" / "honeypots" / "http_honeypot.py"
        ).read_text(encoding="utf-8")
        self.assertIn("require_dashboard_auth", dashboard)
        self.assertIn('@app.route("/login", methods=["GET", "POST"])', honeypot)
        self.assertNotIn("require_dashboard_auth", honeypot)


if __name__ == "__main__":
    unittest.main()
