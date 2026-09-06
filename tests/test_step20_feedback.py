"""Focused protections for Step 20 analyst feedback and the XAI review UI."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


class Step20BackendTests(unittest.TestCase):
    def test_feedback_store_is_append_only_and_preserves_original_result(self) -> None:
        store = read("website/backend/analyst_feedback_store.js")
        for marker in (
            "CREATE TABLE IF NOT EXISTS analyst_feedback",
            "original_prediction",
            "original_severity",
            "original_attack_type",
            "INSERT INTO analyst_feedback",
            "MAX(id) AS latest_id",
            "awaiting_review",
            "confirmed_attacks",
            "false_positives",
            "severity_overrides",
        ):
            self.assertIn(marker, store)

        self.assertNotIn("UPDATE analyst_feedback", store)
        self.assertNotIn("DELETE FROM analyst_feedback", store)
        self.assertNotIn(".fit(", store)
        self.assertNotIn("fit_transform", store)

    def test_feedback_validation_has_bounded_labels_severity_and_notes(self) -> None:
        store = read("website/backend/analyst_feedback_store.js")
        for marker in (
            '"confirmed_attack"',
            '"false_positive"',
            '"Low"',
            '"Medium"',
            '"High"',
            '"Critical"',
            "MAX_NOTES_LENGTH = 2000",
            "IDS result was not found",
            "authenticated analyst identity is required",
        ):
            self.assertIn(marker, store)

    def test_database_initializes_feedback_after_ids_results(self) -> None:
        database = read("website/backend/db.js")
        self.assertIn('require("./analyst_feedback_store")', database)
        self.assertIn("initializeAnalystFeedbackStore(db)", database)
        self.assertLess(
            database.index("initializeIDSResultStore(db)"),
            database.index("initializeAnalystFeedbackStore(db)"),
        )

    def test_feedback_endpoints_accept_only_defender_or_legacy_access(self) -> None:
        server = read("website/backend/server.js")
        for route in (
            'app.get("/api/analyst-feedback", requireDashboardAccess',
            'app.get("/api/analyst-feedback/latest", requireDashboardAccess',
            'app.get("/api/analyst-feedback/stats", requireDashboardAccess',
            'app.post("/api/analyst-feedback/:eventId", requireDashboardAccess',
        ):
            self.assertIn(route, server)

        self.assertIn("id: req.user.userId", server)
        self.assertIn("username: req.user.username", server)
        self.assertNotIn("analyst_id: req.body", server)
        self.assertNotIn("analyst_username: req.body", server)


class Step20DashboardTests(unittest.TestCase):
    def test_feedback_and_xai_remain_on_the_flask_analyst_dashboard(self) -> None:
        dashboard = read("dashboard/templates/index.html")

        for marker in (
            "Operational XAI Review",
            "Confirmed attacks",
            "False positives",
            "Severity overrides",
            "Confirm attack",
            "Mark false positive",
            "Analyst notes",
            "Save analyst review",
            "Feedback history",
            "/api/analyst-feedback/stats",
            "/api/analyst-feedback/latest",
        ):
            self.assertIn(marker, dashboard)

    def test_local_dashboard_keeps_feedback_and_simulated_ips_controls(self) -> None:
        dashboard = read("dashboard/templates/index.html")
        application = read("dashboard/app.py")

        for marker in (
            "Local defender console",
            "Defender controls enabled",
            "Generate XAI Report",
            "simulate_block",
            "rate_limit",
            "terminate_session",
        ):
            self.assertIn(marker, dashboard)

        self.assertNotIn("@require_dashboard_auth", application)
        self.assertNotIn('/api/auth/login', application)
        self.assertIn("X-Dashboard-Internal-Token", application)
        self.assertIn('@app.route("/api/analyst-feedback")', application)
        self.assertIn('@app.route("/api/ips/actions", methods=["GET", "POST"])', application)
        self.assertIn('app.get("/api/ips/safety", requireDashboardAccess', read("website/backend/server.js"))

    def test_public_react_portal_has_no_feedback_or_ids_connectivity(self) -> None:
        app = read("website/frontend/src/App.jsx")
        home = read("website/frontend/src/pages/HomePage.jsx")
        combined = app + home

        for forbidden in (
            "/api/ids-results",
            "/api/analyst-feedback",
            "/api/ips",
            "IDSInsights",
            "AnalystFeedbackPanel",
        ):
            self.assertNotIn(forbidden, combined)

if __name__ == "__main__":
    unittest.main()
