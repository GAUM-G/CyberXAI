"""Login-protected local defender dashboard and intelligent-agent tests."""

from __future__ import annotations

import unittest
from pathlib import Path

from dashboard import app as dashboard_module
from tests.dashboard_auth_helpers import authenticated_dashboard_client


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(dashboard_module._FLASK_OK, "Flask not installed")
class LocalDefenderDashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_events = dashboard_module._all_events
        self.original_results = dashboard_module._all_ids_results
        dashboard_module._all_events = lambda limit=2000: []
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
                },
            }
        ][:limit]
        self.client_context = authenticated_dashboard_client()
        self.client = self.client_context.__enter__()

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)
        dashboard_module._all_events = self.original_events
        dashboard_module._all_ids_results = self.original_results

    def test_defender_apis_require_dashboard_session_not_portal_session(self) -> None:
        self.assertEqual(self.client.application.test_client().get("/api/monitor").status_code, 401)
        for path in (
            "/api/monitor",
            "/api/honeypot",
            "/api/credentials",
            "/api/ids",
            "/api/agents",
            "/api/xai/alerts",
            "/api/report",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

        payload = self.client.get("/api/agents").get_json()
        self.assertEqual(payload["analyzed_results"], 1)
        self.assertEqual(payload["correlated_campaigns"], 1)
        self.assertEqual(payload["severity_escalations"], 1)

    def test_page_has_login_gate_and_keeps_defender_tools(self) -> None:
        anonymous = self.client.application.test_client()
        self.assertEqual(anonymous.get("/").status_code, 200)
        self.assertIn("Sign up with Gmail", anonymous.get("/").get_data(as_text=True))
        self.assertIn("Analyst sign in", anonymous.get("/login").get_data(as_text=True))
        body = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="dashboard-app"', body)
        self.assertNotIn('id="dashboard-app" hidden', body)
        self.assertIn('name="csrf-token"', body)
        self.assertIn("Sign out", body)
        self.assertIn("Local defender console", body)
        self.assertIn('id="sec-agents"', body)
        self.assertIn('id="sec-ips"', body)


class LocalDashboardSourceSafetyTests(unittest.TestCase):
    def test_dashboard_is_local_and_uses_server_side_backend_access(self) -> None:
        dashboard = (ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
        middleware = (
            ROOT / "website" / "backend" / "middleware" / "dashboard_access.js"
        ).read_text(encoding="utf-8")
        honeypot = (
            ROOT / "core" / "honeypots" / "http_honeypot.py"
        ).read_text(encoding="utf-8")

        self.assertIn('start_dashboard(host: str = "127.0.0.1"', dashboard)
        self.assertIn("X-Dashboard-Internal-Token", dashboard)
        self.assertIn("require_analyst_login", dashboard)
        self.assertIn("isLoopbackRequest", middleware)
        self.assertIn("timingSafeEqual", middleware)
        self.assertIn("requireAuth(req, res, next)", middleware)
        self.assertIn('@app.route("/login", methods=["GET", "POST"])', honeypot)

    def test_dashboard_rejects_non_loopback_binding(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback-only"):
            dashboard_module.start_dashboard(host="0.0.0.0", port=5050)


if __name__ == "__main__":
    unittest.main()
