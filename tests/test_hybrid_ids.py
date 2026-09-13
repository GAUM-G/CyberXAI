"""Tests for the Step 15 explainable, inference-only hybrid IDS."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import numpy as np
import torch

from core.event_schema import build_common_event
from machine_learning.hybrid_ids import HybridArtifacts, HybridIDSEngine


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


class FakePreprocessor:
    def transform(self, matrix: np.ndarray) -> np.ndarray:
        result = np.zeros((len(matrix), 23), dtype=np.float32)
        result[:, 0] = 1.0
        result[:, 1] = np.arange(1, len(matrix) + 1)
        return result


class FakeClassifier:
    def __init__(self, predicted_index: int, confidence: float = 0.90) -> None:
        self.predicted_index = predicted_index
        self.confidence = confidence
        self.classes_ = np.arange(len(LABELS), dtype=np.int64)

    def predict(self, features: np.ndarray) -> np.ndarray:
        return np.full(len(features), self.predicted_index, dtype=np.int64)

    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        remaining = (1.0 - self.confidence) / (len(LABELS) - 1)
        probabilities = np.full(
            (len(features), len(LABELS)),
            remaining,
            dtype=np.float64,
        )
        probabilities[:, self.predicted_index] = self.confidence
        return probabilities


class FakeIsolationForest:
    def __init__(
        self,
        *,
        anomaly: bool = False,
        score: float | None = None,
    ) -> None:
        self.anomaly = anomaly
        self.score = (-0.2 if anomaly else 0.2) if score is None else score

    def predict(self, features: np.ndarray) -> np.ndarray:
        value = -1 if self.anomaly else 1
        return np.full(len(features), value, dtype=np.int8)

    def decision_function(self, features: np.ndarray) -> np.ndarray:
        return np.full(len(features), self.score, dtype=np.float64)


class FakeLSTM(torch.nn.Module):
    def __init__(self, predicted_index: int, confidence_logit: float = 6.0) -> None:
        super().__init__()
        self.predicted_index = predicted_index
        self.confidence_logit = confidence_logit
        self.last_input: torch.Tensor | None = None

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        self.last_input = inputs.detach().cpu().clone()
        logits = torch.zeros((len(inputs), len(LABELS)), device=inputs.device)
        logits[:, self.predicted_index] = self.confidence_logit
        return logits


class FakeXAIExplainer:
    status = "ready"

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def explain(
        self,
        *,
        encoded: np.ndarray,
        ids_result: dict[str, object],
        rule_findings: list[dict[str, object]],
    ) -> dict[str, object]:
        self.calls.append(
            {
                "encoded": encoded.copy(),
                "attack_type": ids_result["attack_type"],
                "rule_findings": list(rule_findings),
            }
        )
        return {
            "xai_version": "1.0",
            "method": "test_stub",
            "lime_used": False,
            "shap": {
                "status": "ready",
                "top_features": [
                    {
                        "feature": "feature_0",
                        "value": 1.0,
                        "shap_value": 0.25,
                        "direction": "supports_explained_class",
                    }
                ],
            },
            "human_reason": {
                "decision": "Test decision reason.",
                "threat": "Test threat reason.",
                "feature": "Test feature reason.",
                "summary": "Test explanation.",
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
        }


def make_artifacts(
    *,
    tabular_index: int = 0,
    sequence_index: int = 0,
    anomaly: bool = False,
    anomaly_score: float | None = None,
    anomaly_score_threshold: float = 0.0,
) -> HybridArtifacts:
    return HybridArtifacts(
        preprocessor=FakePreprocessor(),
        tabular_model_name="decision_tree",
        tabular_estimator=FakeClassifier(tabular_index),
        isolation_estimator=FakeIsolationForest(
            anomaly=anomaly,
            score=anomaly_score,
        ),
        lstm_model=FakeLSTM(sequence_index),
        feature_names=tuple(f"feature_{index}" for index in range(23)),
        label_mapping=dict(LABELS),
        sequence_length=10,
        device=torch.device("cpu"),
        protected_hashes={},
        anomaly_score_threshold=anomaly_score_threshold,
    )


def make_engine(**artifact_options: object) -> HybridIDSEngine:
    return HybridIDSEngine(
        make_artifacts(**artifact_options),
        xai_explainer=FakeXAIExplainer(),
    )


def make_event(
    *,
    service: str = "http",
    event: str = "request",
    status: str = "observed",
    payload: object = None,
    timestamp: datetime | None = None,
) -> dict[str, object]:
    return build_common_event(
        event_id=str(uuid4()),
        timestamp=timestamp or datetime.now(timezone.utc),
        source_ip="127.0.0.1",
        source_port=43210,
        destination_port={"http": 8080, "ssh": 2222, "ftp": 2121}[service],
        service=service,
        protocol=service,
        event_type="request",
        event=event,
        attack_type="untrusted_producer_label",
        status=status,
        payload=payload,
        metadata={},
        severity="info",
    )


class HybridIDSEngineTests(unittest.TestCase):
    def test_required_result_fields_are_emitted(self) -> None:
        result = make_engine().process_event(make_event())

        for field in (
            "attack_type",
            "prediction",
            "confidence",
            "anomaly_score",
            "model_used",
            "threat_level",
            "threat_score",
            "threat_factors",
            "xai",
        ):
            self.assertIn(field, result)
        self.assertEqual(result["threat_level"], "Low")
        self.assertEqual(result["threat_score"], 0)
        self.assertEqual(
            [factor["factor"] for factor in result["threat_factors"]],
            [
                "attack_type",
                "confidence",
                "repetition",
                "service",
                "anomaly_score",
            ],
        )
        self.assertNotIn("payload", result)
        self.assertNotIn("username", result)
        self.assertFalse(
            result["safety"]["producer_attack_type_used_as_model_feature"]
        )
        self.assertFalse(result["safety"]["xai_changed_prediction"])
        self.assertEqual(result["xai"]["xai_version"], "1.0")
        self.assertFalse(result["xai"]["lime_used"])
        self.assertFalse(result["xai"]["privacy"]["raw_payload_included"])

    def test_sql_injection_rule_has_priority(self) -> None:
        event = make_event(
            payload={"query": "' OR '1'='1"},
        )
        result = make_engine(
            tabular_index=LABELS["normal"],
            sequence_index=LABELS["normal"],
            anomaly=True,
        ).process_event(event)

        self.assertEqual(result["attack_type"], "sql_injection")
        self.assertEqual(result["prediction"], "attack")
        self.assertEqual(result["model_used"], "rules")
        self.assertIn(result["threat_level"], {"High", "Critical"})

    def test_selected_tabular_model_handles_known_attack(self) -> None:
        result = make_engine(
            tabular_index=LABELS["ssh_bruteforce"]
        ).process_event(make_event(service="ssh", event="connection"))

        self.assertEqual(result["attack_type"], "ssh_bruteforce")
        self.assertEqual(result["model_used"], "decision_tree")

    def test_lstm_can_detect_sequence_attack_when_tabular_is_normal(self) -> None:
        result = make_engine(
            sequence_index=LABELS["directory_scanning"]
        ).process_event(make_event())

        self.assertEqual(result["attack_type"], "directory_scanning")
        self.assertEqual(result["model_used"], "lstm_classifier")

    def test_isolation_forest_handles_unknown_anomaly(self) -> None:
        result = make_engine(anomaly=True).process_event(make_event())

        self.assertEqual(result["attack_type"], "other_anomaly")
        self.assertEqual(result["model_used"], "isolation_forest")
        self.assertIsNone(result["confidence"])
        self.assertTrue(result["components"]["anomaly"]["is_anomaly"])

    def test_isolation_forest_uses_calibrated_anomaly_threshold(self) -> None:
        # The estimator's legacy predict() says inlier, but its score crosses
        # the validation-calibrated operating point stored in the bundle.
        result = make_engine(
            anomaly=False,
            anomaly_score=-0.20,
            anomaly_score_threshold=0.10,
        ).process_event(make_event())

        self.assertEqual(result["attack_type"], "other_anomaly")
        self.assertEqual(result["model_used"], "isolation_forest")
        self.assertAlmostEqual(result["anomaly_score"], 0.20)
        self.assertTrue(result["components"]["anomaly"]["is_anomaly"])

    def test_normal_decision_uses_both_supervised_models(self) -> None:
        result = make_engine().process_event(make_event())

        self.assertEqual(result["attack_type"], "normal")
        self.assertEqual(result["prediction"], "normal")
        self.assertEqual(
            result["model_used"],
            "decision_tree+lstm_classifier",
        )

    def test_sequences_are_left_padded_and_causal(self) -> None:
        artifacts = make_artifacts()
        engine = HybridIDSEngine(
            artifacts,
            xai_explainer=FakeXAIExplainer(),
        )
        start = datetime(2026, 7, 27, tzinfo=timezone.utc)
        first = engine.process_event(make_event(timestamp=start))
        second = engine.process_event(
            make_event(timestamp=start + timedelta(seconds=1))
        )

        self.assertEqual(
            first["components"]["sequence"]["context_events"],
            1,
        )
        self.assertEqual(
            second["components"]["sequence"]["context_events"],
            2,
        )
        captured = artifacts.lstm_model.last_input
        self.assertIsNotNone(captured)
        self.assertEqual(tuple(captured.shape), (1, 10, 23))
        self.assertTrue(torch.all(captured[:, :8, :] == 0).item())
        self.assertTrue(torch.any(captured[:, -2:, :] != 0).item())

    def test_duplicate_event_id_is_rejected(self) -> None:
        engine = make_engine()
        event = make_event()
        engine.process_event(event)

        with self.assertRaisesRegex(ValueError, "duplicate event_id"):
            engine.process_event(event)

    def test_repeated_failed_logins_trigger_rule_on_third_event(self) -> None:
        engine = make_engine()
        start = datetime(2026, 7, 27, tzinfo=timezone.utc)
        results = [
            engine.process_event(
                make_event(
                    service="ftp",
                    event="authentication_failed",
                    status="failed",
                    timestamp=start + timedelta(seconds=index),
                )
            )
            for index in range(3)
        ]

        self.assertNotEqual(results[0]["model_used"], "rules")
        self.assertNotEqual(results[1]["model_used"], "rules")
        self.assertEqual(results[2]["attack_type"], "ftp_bruteforce")
        self.assertEqual(results[2]["model_used"], "rules")

    def test_xai_receives_final_result_and_encoded_features(self) -> None:
        explainer = FakeXAIExplainer()
        engine = HybridIDSEngine(
            make_artifacts(tabular_index=LABELS["sql_injection"]),
            xai_explainer=explainer,
        )

        result = engine.process_event(make_event())

        self.assertEqual(len(explainer.calls), 1)
        self.assertEqual(explainer.calls[0]["attack_type"], "sql_injection")
        self.assertEqual(explainer.calls[0]["encoded"].shape, (1, 23))
        self.assertEqual(result["xai"]["human_reason"]["summary"], "Test explanation.")


if __name__ == "__main__":
    unittest.main()
