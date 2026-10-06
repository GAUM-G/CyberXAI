"""Focused protections for the Step 20 Honeypot Dashboard correction."""

from __future__ import annotations

import unittest
from pathlib import Path

from dashboard import app as dashboard_module
from tests.dashboard_auth_helpers import make_authenticated_dashboard_client


ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


class HoneypotDashboardXAITests(unittest.TestCase):
    def test_primary_dashboard_replaces_stale_xai_placeholders(self) -> None:
        template = read("dashboard/templates/index.html")

        for marker in (
            "Operational XAI Review",
            "LIVE IDS + XAI",
            "Explainable IDS Review Queue",
            "Model confidence",
            "Threat score",
            "Decision explanation",
            "Threat explanation",
            "Feature explanation",
            "SHAP feature contributions",
            "not the final decision source",
            "Raw payload",
            "Credentials",
        ):
            self.assertIn(marker, template)

        self.assertNotIn("XAI Layer — Coming in Phase 3", template)
        self.assertNotIn("Requires Phase 2 (ML models) to be trained first", template)

    def test_primary_dashboard_contains_local_feedback_workflow(self) -> None:
        template = read("dashboard/templates/index.html")

        for marker in (
            "Local defender console",
            "Defender controls enabled",
            'id="xai-confirmed-count"',
            'id="xai-false-count"',
            'id="xai-awaiting-count"',
            'id="xai-override-count"',
            "Confirm attack",
            "Mark false positive",
            "Severity override",
            "Analyst notes",
            "Save analyst review",
            "Feedback history",
            "original IDS result remains unchanged",
            "append-only audit history",
            "submitAnalystFeedback",
            "/api/analyst-feedback/stats",
            "/api/analyst-feedback/latest",
        ):
            self.assertIn(marker, template)

        self.assertNotIn("analyst_id:", template)
        self.assertNotIn("analyst_username:", template)
        self.assertNotIn('id="analyst-login-form"', template)
        self.assertNotIn("ANALYST_TOKEN_KEY", template)

    def test_existing_dashboard_sections_and_modal_remain_available(self) -> None:
        template = read("dashboard/templates/index.html")
        for marker in (
            'id="sec-monitor"',
            'id="port-scan-panel"',
            'id="sec-honeypot"',
            'id="sec-ids"',
            'id="sec-xai"',
            'id="sec-report"',
            'id="ids-detail-modal"',
            "generateXaiReport",
            'href="/api/report/download"',
        ):
            self.assertIn(marker, template)

    def test_monitor_poll_refreshes_cross_process_activity_feed(self) -> None:
        template = read("dashboard/templates/index.html")
        monitor = template[
            template.index("function loadMonitor(){"):
            template.index("function initFeed(evs){")
        ]

        self.assertIn("initFeed(d.recent_events||[]);", monitor)
        self.assertIn("liveTotal=d.total_events||0;", monitor)
        self.assertIn(
            "document.getElementById('live-counter').textContent=liveTotal;",
            monitor,
        )

    def test_monitor_feed_keeps_newest_event_first(self) -> None:
        template = read("dashboard/templates/index.html")
        init_feed = template[
            template.index("function initFeed(evs){"):
            template.index("function appendRow(e,flash=true){")
        ]

        self.assertIn("[...evs].reverse().forEach(e=>appendRow(e,false));", init_feed)


class HoneypotDashboardIntegrationTests(unittest.TestCase):
    def test_dashboard_keeps_backend_address_and_secret_server_side(self) -> None:
        app_source = read("dashboard/app.py")
        self.assertIn("PORTAL_API_URL", app_source)
        self.assertIn("X-Dashboard-Internal-Token", app_source)
        self.assertNotIn("portal_api_url|tojson", read("dashboard/templates/index.html"))

    def test_backend_uses_server_side_dashboard_access_not_browser_cors(self) -> None:
        server = read("website/backend/server.js")
        self.assertNotIn('"http://localhost:5050"', server)
        self.assertNotIn('"http://127.0.0.1:5050"', server)

        for route in (
            'app.get("/api/analyst-feedback", requireDashboardAccess',
            'app.get("/api/analyst-feedback/latest", requireDashboardAccess',
            'app.get("/api/analyst-feedback/stats", requireDashboardAccess',
            'app.post("/api/analyst-feedback/:eventId", requireDashboardAccess',
        ):
            self.assertIn(route, server)

    @unittest.skipUnless(dashboard_module._FLASK_OK, "Flask not installed")
    def test_rendered_dashboard_does_not_expose_backend_or_internal_token(self) -> None:
        response = make_authenticated_dashboard_client(self).get("/")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertNotIn(dashboard_module.PORTAL_API_URL, body)
        self.assertNotIn("X-Dashboard-Internal-Token", body)
        self.assertIn("Local defender console", body)


if __name__ == "__main__":
    unittest.main()
