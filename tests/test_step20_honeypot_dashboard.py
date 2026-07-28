"""Focused protections for the Step 20 Honeypot Dashboard correction."""

from __future__ import annotations

import unittest
from pathlib import Path

from dashboard import app as dashboard_module


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

    def test_primary_dashboard_contains_authenticated_feedback_workflow(self) -> None:
        template = read("dashboard/templates/index.html")

        for marker in (
            'id="analyst-login-form"',
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
            "ANALYST_TOKEN_KEY",
            "signInAnalyst",
            "submitAnalystFeedback",
            "/api/analyst-feedback/stats",
            "/api/analyst-feedback/latest",
        ):
            self.assertIn(marker, template)

        self.assertNotIn("analyst_id:", template)
        self.assertNotIn("analyst_username:", template)

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


class HoneypotDashboardIntegrationTests(unittest.TestCase):
    def test_dashboard_exposes_configured_portal_api_to_template(self) -> None:
        app_source = read("dashboard/app.py")
        self.assertIn("PORTAL_API_URL", app_source)
        self.assertIn("portal_api_url=PORTAL_API_URL", app_source)
        self.assertIn("portal_api_url|tojson", read("dashboard/templates/index.html"))

    def test_backend_allows_both_local_dashboard_origins(self) -> None:
        server = read("website/backend/server.js")
        self.assertIn('"http://localhost:5050"', server)
        self.assertIn('"http://127.0.0.1:5050"', server)

        for route in (
            'app.get("/api/analyst-feedback", requireAuth',
            'app.get("/api/analyst-feedback/latest", requireAuth',
            'app.get("/api/analyst-feedback/stats", requireAuth',
            'app.post("/api/analyst-feedback/:eventId", requireAuth',
        ):
            self.assertIn(route, server)

    @unittest.skipUnless(dashboard_module._FLASK_OK, "Flask not installed")
    def test_rendered_dashboard_contains_safe_portal_api_value(self) -> None:
        response = dashboard_module.create_dashboard_app().test_client().get("/")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn(
            f"const ANALYST_API_BASE={dashboard_module.PORTAL_API_URL!r}".replace(
                "'", '"'
            ),
            body,
        )


if __name__ == "__main__":
    unittest.main()
