from __future__ import annotations

import sqlite3
import tempfile
import unittest
import hashlib
import json
from pathlib import Path

from continuous_learning.pipeline import (
    EVALUATION_FILES,
    MANIFEST_FILENAME,
    MODEL_FILES,
    MODEL_INPUT_FILES,
    apply_analyst_feedback,
    compare_evaluations,
    load_latest_feedback,
    promote_candidate,
)


def sample_rows():
    return [
        {"event_id": "event-1", "label": "sql_injection"},
        {"event_id": "event-2", "label": "normal"},
        {"event_id": "event-3", "label": "xss"},
    ]


def evaluation_report(*, f1=0.90, recall=0.88, fpr=0.02, rows=20):
    return {
        "selection": {
            "best_tabular_classifier": {"selected_model": "random_forest"}
        },
        "model_results": {
            "random_forest": {
                "metrics": {
                    "f1_macro": f1,
                    "recall_macro": recall,
                    "balanced_accuracy": 0.89,
                    "false_positive_rate": {"normal_as_attack": fpr},
                    "test_rows": rows,
                }
            }
        },
    }


class FeedbackExportTests(unittest.TestCase):
    def test_latest_append_only_feedback_is_selected(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "feedback.db"
            connection = sqlite3.connect(database)
            connection.execute(
                """
                CREATE TABLE analyst_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    original_attack_type TEXT NOT NULL
                )
                """
            )
            connection.executemany(
                "INSERT INTO analyst_feedback (event_id, verdict, original_attack_type) VALUES (?, ?, ?)",
                [
                    ("event-1", "confirmed_attack", "sql_injection"),
                    ("event-1", "false_positive", "sql_injection"),
                    ("event-2", "confirmed_attack", "directory_scanning"),
                ],
            )
            connection.commit()
            connection.close()

            feedback = load_latest_feedback(database)

        self.assertEqual(2, len(feedback))
        self.assertEqual("false_positive", feedback["event-1"]["verdict"])
        self.assertEqual("confirmed_attack", feedback["event-2"]["verdict"])

    def test_feedback_changes_only_training_labels(self):
        corrected, stats = apply_analyst_feedback(
            sample_rows(),
            {
                "event-1": {
                    "verdict": "false_positive",
                    "original_attack_type": "sql_injection",
                    "notes": "must never become a feature",
                },
                "event-2": {
                    "verdict": "confirmed_attack",
                    "original_attack_type": "directory_scanning",
                    "analyst_username": "not-a-feature",
                },
            },
        )

        self.assertEqual("normal", corrected[0]["label"])
        self.assertEqual("directory_scanning", corrected[1]["label"])
        self.assertNotIn("notes", corrected[0])
        self.assertNotIn("analyst_username", corrected[1])
        self.assertEqual(2, stats["reviews_applied"])
        self.assertFalse(stats["analyst_notes_used_as_model_input"])


class PromotionGateTests(unittest.TestCase):
    def test_better_candidate_is_recommended_for_explicit_promotion(self):
        comparison = compare_evaluations(
            evaluation_report(),
            evaluation_report(f1=0.92, recall=0.90, fpr=0.01),
        )
        self.assertEqual("promote", comparison["decision"])
        self.assertTrue(comparison["all_quality_gates_passed"])

    def test_false_positive_regression_retains_active_model(self):
        comparison = compare_evaluations(
            evaluation_report(fpr=0.01),
            evaluation_report(f1=0.93, recall=0.91, fpr=0.08),
        )
        self.assertEqual("retain_active", comparison["decision"])
        failed = [gate["name"] for gate in comparison["gates"] if not gate["passed"]]
        self.assertIn("false_positive_rate_non_regression", failed)

    def test_missing_baseline_requires_manual_review(self):
        comparison = compare_evaluations(None, evaluation_report())
        self.assertEqual("manual_review", comparison["decision"])
        self.assertFalse(comparison["all_quality_gates_passed"])

    def test_promotion_is_explicit_and_retains_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registry = root / "registry"
            active = root / "active"
            active.mkdir()
            (active / "old-model.txt").write_text("old", encoding="utf-8")

            version = registry / "versions" / "v-test"
            candidate = version / "ml_ready"
            (candidate / "models").mkdir(parents=True)
            (candidate / "evaluation").mkdir()
            for name in MODEL_INPUT_FILES:
                (candidate / name).write_text(name, encoding="utf-8")
            for name in MODEL_FILES:
                (candidate / "models" / name).write_text(name, encoding="utf-8")
            for name in EVALUATION_FILES:
                (candidate / "evaluation" / name).write_text(name, encoding="utf-8")

            files = {}
            for path in candidate.rglob("*"):
                if path.is_file():
                    files[path.relative_to(version).as_posix()] = {
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "bytes": path.stat().st_size,
                    }
            (version / MANIFEST_FILENAME).write_text(
                json.dumps(
                    {
                        "version_id": "v-test",
                        "evaluation": {"decision": "promote"},
                        "files": files,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "services-stopped"):
                promote_candidate(
                    "v-test",
                    registry_dir=registry,
                    active_dir=active,
                    services_stopped=False,
                )

            promoted = promote_candidate(
                "v-test",
                registry_dir=registry,
                active_dir=active,
                services_stopped=True,
            )

            self.assertEqual("v-test", promoted["active_version"])
            self.assertTrue((active / "models" / "lstm_classifier.pt").is_file())
            self.assertIsNotNone(promoted["rollback_id"])
            rollback = registry / "rollbacks" / promoted["rollback_id"]
            self.assertEqual("old", (rollback / "old-model.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
