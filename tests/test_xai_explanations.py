"""Focused tests for Step 15 SHAP and human-readable IDS explanations."""

from __future__ import annotations

import unittest

import numpy as np

from XAI.prediction_explainer import PredictionExplainer


LABELS = {
    "normal": 0,
    "ssh_bruteforce": 1,
    "ftp_bruteforce": 2,
    "sql_injection": 3,
    "xss": 4,
    "directory_scanning": 5,
    "port_scanning": 6,
    "other_anomaly": 7,
}
FEATURE_NAMES = tuple(f"feature_{index}" for index in range(23))


class FakeEstimator:
    classes_ = np.arange(len(LABELS), dtype=np.int64)


class FakeTreeExplainer:
    def __init__(self, model: object, **kwargs: object) -> None:
        self.model = model
        self.kwargs = kwargs
        self.expected_value = np.linspace(0.05, 0.40, len(LABELS))

    def shap_values(
        self,
        encoded: np.ndarray,
        *,
        check_additivity: bool,
    ) -> np.ndarray:
        values = np.zeros(
            (len(encoded), encoded.shape[1], len(LABELS)),
            dtype=np.float64,
        )
        values[:, 0, LABELS["sql_injection"]] = 0.30
        values[:, 1, LABELS["sql_injection"]] = -0.20
        values[:, 2, LABELS["sql_injection"]] = 0.10
        values[:, 4, LABELS["normal"]] = 0.25
        return values


class FakeShap:
    TreeExplainer = FakeTreeExplainer


def make_result(
    *,
    attack_type: str = "sql_injection",
    model_used: str = "decision_tree",
    tabular_attack_type: str = "sql_injection",
    confidence: float | None = 0.90,
    threat_level: str = "High",
    threat_score: int = 72,
) -> dict[str, object]:
    return {
        "attack_type": attack_type,
        "prediction": "normal" if attack_type == "normal" else "attack",
        "confidence": confidence,
        "anomaly_score": 0.04,
        "model_used": model_used,
        "threat_level": threat_level,
        "threat_score": threat_score,
        "threat_factors": [
            {"factor": "attack_type", "points": 45},
            {"factor": "confidence", "points": 20},
            {
                "factor": "repetition",
                "points": 0,
                "value": 1,
                "window_seconds": 60,
            },
            {"factor": "service", "points": 7},
            {"factor": "anomaly_score", "points": 0},
        ],
        "components": {
            "tabular": {
                "model": "decision_tree",
                "attack_type": tabular_attack_type,
                "confidence": 0.90,
            },
            "sequence": {
                "model": "lstm_classifier",
                "attack_type": "normal",
                "confidence": 0.90,
                "context_events": 3,
                "sequence_length": 10,
            },
            "anomaly": {
                "model": "isolation_forest",
                "is_anomaly": model_used == "isolation_forest",
                "anomaly_score": 0.04,
            },
        },
        "fusion_reason": "test fusion reason",
    }


def make_explainer(
    *,
    shap_module: object | None = FakeShap,
    max_features: int = 5,
) -> PredictionExplainer:
    return PredictionExplainer(
        feature_names=FEATURE_NAMES,
        label_mapping=LABELS,
        tabular_model_name="decision_tree",
        tabular_estimator=FakeEstimator(),
        max_features=max_features,
        shap_module=shap_module,
    )


class PredictionExplainerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.encoded = np.arange(23, dtype=np.float32).reshape(1, -1)

    def test_tree_shap_selects_predicted_class_and_ranks_absolute_values(
        self,
    ) -> None:
        explanation = make_explainer(max_features=3).explain(
            encoded=self.encoded,
            ids_result=make_result(),
            rule_findings=[],
        )

        shap_result = explanation["shap"]
        self.assertEqual(shap_result["status"], "ready")
        self.assertEqual(shap_result["explained_class_index"], 3)
        self.assertEqual(
            [item["feature"] for item in shap_result["top_features"]],
            ["feature_0", "feature_1", "feature_2"],
        )
        self.assertEqual(
            [item["shap_value"] for item in shap_result["top_features"]],
            [0.3, -0.2, 0.1],
        )

    def test_tabular_shap_is_marked_as_supporting_final_tabular_decision(
        self,
    ) -> None:
        result = make_explainer().explain(
            encoded=self.encoded,
            ids_result=make_result(),
            rule_findings=[],
        )

        self.assertTrue(result["shap"]["supports_final_decision"])
        self.assertIn("Decision Tree classified", result["human_reason"]["decision"])

    def test_rule_decision_does_not_misrepresent_tabular_shap_as_final(
        self,
    ) -> None:
        ids_result = make_result(
            model_used="rules",
            tabular_attack_type="normal",
        )
        result = make_explainer().explain(
            encoded=self.encoded,
            ids_result=ids_result,
            rule_findings=[
                {
                    "attack_type": "sql_injection",
                    "confidence": 0.93,
                    "matched_rules": ["sqli_boolean_tautology"],
                    "evidence": {
                        "pattern_match_count": 1,
                        "raw_text_included": False,
                    },
                }
            ],
        )

        self.assertFalse(result["shap"]["supports_final_decision"])
        self.assertIn("sanitized security pattern", result["human_reason"]["decision"])
        self.assertIn(
            "not the final decision source",
            result["human_reason"]["feature"],
        )

    def test_repeated_login_reason_exposes_count_and_window(self) -> None:
        result = make_explainer().explain(
            encoded=self.encoded,
            ids_result=make_result(
                attack_type="ftp_bruteforce",
                model_used="rules",
                tabular_attack_type="normal",
            ),
            rule_findings=[
                {
                    "attack_type": "ftp_bruteforce",
                    "confidence": 0.89,
                    "matched_rules": ["repeated_login_failures"],
                    "evidence": {
                        "failure_count": 3,
                        "window_seconds": 60.0,
                    },
                }
            ],
        )

        decision = result["human_reason"]["decision"]
        self.assertIn("3 failed login attempts", decision)
        self.assertIn("within 60 seconds", decision)

    def test_threat_reason_exposes_each_nonzero_point_contribution(self) -> None:
        result = make_explainer().explain(
            encoded=self.encoded,
            ids_result=make_result(),
            rule_findings=[],
        )

        threat = result["human_reason"]["threat"]
        self.assertIn("High (72/100)", threat)
        self.assertIn("attack type +45", threat)
        self.assertIn("confidence +20", threat)
        self.assertIn("service +7", threat)

    def test_lstm_reason_reports_only_causal_context(self) -> None:
        result = make_explainer().explain(
            encoded=self.encoded,
            ids_result=make_result(
                attack_type="directory_scanning",
                model_used="lstm_classifier",
                tabular_attack_type="normal",
            ),
            rule_findings=[],
        )

        self.assertIn("using 3 causal events", result["human_reason"]["decision"])

    def test_isolation_forest_reason_calls_score_non_probability(self) -> None:
        result = make_explainer().explain(
            encoded=self.encoded,
            ids_result=make_result(
                attack_type="other_anomaly",
                model_used="isolation_forest",
                tabular_attack_type="normal",
                confidence=None,
            ),
            rule_findings=[],
        )

        decision = result["human_reason"]["decision"]
        self.assertIn("anomaly score 0.0400", decision)
        self.assertIn("not a probability", decision)

    def test_missing_shap_dependency_fails_open_with_human_reason(self) -> None:
        explainer = make_explainer(shap_module=object())
        result = explainer.explain(
            encoded=self.encoded,
            ids_result=make_result(),
            rule_findings=[],
        )

        self.assertEqual(result["shap"]["status"], "unavailable")
        self.assertEqual(
            result["shap"]["reason"],
            "shap_explainer_initialization_failed",
        )
        self.assertIn(
            "SHAP feature contributions are unavailable",
            result["human_reason"]["feature"],
        )

    def test_invalid_feature_shape_and_values_are_rejected(self) -> None:
        explainer = make_explainer()
        with self.assertRaisesRegex(ValueError, "shape"):
            explainer.explain(
                encoded=np.zeros((1, 22)),
                ids_result=make_result(),
                rule_findings=[],
            )
        invalid = self.encoded.copy()
        invalid[0, 0] = np.inf
        with self.assertRaisesRegex(ValueError, "finite"):
            explainer.explain(
                encoded=invalid,
                ids_result=make_result(),
                rule_findings=[],
            )

    def test_explanation_never_contains_raw_event_secrets(self) -> None:
        result = make_explainer().explain(
            encoded=self.encoded,
            ids_result=make_result(),
            rule_findings=[],
        )
        serialized = repr(result)

        self.assertFalse(result["privacy"]["raw_payload_included"])
        self.assertFalse(result["privacy"]["source_ip_included"])
        self.assertFalse(result["privacy"]["credentials_included"])
        self.assertNotIn("password", serialized.lower())
        self.assertFalse(result["safety"]["prediction_changed"])
        self.assertFalse(result["safety"]["model_fit_called"])


if __name__ == "__main__":
    unittest.main()
