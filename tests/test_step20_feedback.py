"""Focused protections for Step 20 analyst feedback and the XAI review UI."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def normalized_sha256(relative_path: str) -> str:
    """Hash content consistently across LF and CRLF working trees."""
    content = (ROOT / relative_path).read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(content).hexdigest().upper()


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

    def test_all_feedback_endpoints_are_authenticated(self) -> None:
        server = read("website/backend/server.js")
        for route in (
            'app.get("/api/analyst-feedback", requireAuth',
            'app.get("/api/analyst-feedback/latest", requireAuth',
            'app.get("/api/analyst-feedback/stats", requireAuth',
            'app.post("/api/analyst-feedback/:eventId", requireAuth',
        ):
            self.assertIn(route, server)

        self.assertIn("id: req.user.userId", server)
        self.assertIn("username: req.user.username", server)
        self.assertNotIn("analyst_id: req.body", server)
        self.assertNotIn("analyst_username: req.body", server)


class Step20FrontendTests(unittest.TestCase):
    def test_ids_dashboard_adds_review_queue_without_removing_final_ids_apis(self) -> None:
        component = read("website/frontend/src/components/IDSInsights.jsx")
        for marker in (
            'apiRequest("/api/ids-results?limit=100")',
            'apiRequest("/api/ids-results/stats")',
            'apiRequest("/api/analyst-feedback/stats")',
            'id="ids-review-filter"',
            "Confirmed attacks",
            "False positives",
            "Awaiting review",
            "Severity overrides",
            "<XAIExplanationPanel",
            "<AnalystFeedbackPanel",
            "Original Threat Score",
        ):
            self.assertIn(marker, component)

    def test_feedback_panel_supports_all_required_actions_and_audit_history(self) -> None:
        component = read(
            "website/frontend/src/components/AnalystFeedbackPanel.jsx"
        )
        for marker in (
            "Confirm attack",
            "Mark false positive",
            "Severity override",
            "Analyst notes",
            "Save analyst review",
            "Feedback history",
            "severity_override",
            "response.feedback",
            "original IDS result remains unchanged",
        ):
            self.assertIn(marker, component)
        self.assertNotIn("analyst_id", component)
        self.assertNotIn("analyst_username", component)

    def test_xai_panel_separates_decision_threat_and_feature_explanations(self) -> None:
        component = read(
            "website/frontend/src/components/XAIExplanationPanel.jsx"
        )
        for marker in (
            "Model confidence",
            "Threat score",
            "Decision explanation",
            "Threat explanation",
            "Feature explanation",
            "SHAP feature contributions",
            "supports_final_decision",
            "not the final",
            "raw_payload_included",
            "credentials_included",
            "xai_changed_prediction",
        ):
            self.assertIn(marker, component)

    def test_feedback_and_xai_styles_are_responsive(self) -> None:
        styles = read("website/frontend/src/styles.css")
        for marker in (
            ".ids-review-summary",
            ".review-state",
            ".xai-score-grid",
            ".xai-reason-grid",
            ".xai-feature-list",
            ".xai-limitation",
            ".xai-safety-grid",
            ".feedback-form",
            ".feedback-history",
            "@media (max-width: 920px)",
            "@media (max-width: 640px)",
        ):
            self.assertIn(marker, styles)

    def test_existing_frontend_dependencies_and_api_helper_are_unchanged(self) -> None:
        expected_hashes = {
            "website/frontend/package.json":
                "E8FEE5C2CFE7E5D692882FA4AAF7FFA9D27C93B823690C931336B5A8203262B2",
            "website/backend/package.json":
                "728E6C2E81278A282F811EBEA4A0DF7ADE3643C450753B554E210387439536C2",
            "website/frontend/src/api.js":
                "AA40ECFF433AEC525C61B1E2E1698E9C3B2574C10613163D3932F67D328CE684",
        }
        for relative_path, expected_hash in expected_hashes.items():
            with self.subTest(relative_path=relative_path):
                self.assertEqual(normalized_sha256(relative_path), expected_hash)

if __name__ == "__main__":
    unittest.main()
