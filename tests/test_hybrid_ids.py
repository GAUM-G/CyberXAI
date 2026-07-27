"""Tests for the Step 14 threat-aware, inference-only hybrid IDS."""

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


def make_artifacts(
    *,
    tabular_index: int = 0,
    sequence_index: int = 0,
    anomaly: bool = False,
) -> HybridArtifacts:
    return HybridArtifacts(
        preprocessor=FakePreprocessor(),
        tabular_model_name="decision_tree",
        tabular_estimator=FakeClassifier(tabular_index),
        isolation_estimator=FakeIsolationForest(anomaly=anomaly),
        lstm_model=FakeLSTM(sequence_index),
        feature_names=tuple(f"feature_{index}" for index in range(23)),
        label_mapping=dict(LABELS),
        sequence_length=10,
        device=torch.device("cpu"),
        protected_hashes={},
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
        result = HybridIDSEngine(make_artifacts()).process_event(make_event())

        for field in (
            "attack_type",
            "prediction",
            "confidence",
            "anomaly_score",
            "model_used",
            "threat_level",
            "threat_score",
            "threat_factors",
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

    def test_sql_injection_rule_has_priority(self) -> None:
        event = make_event(
            payload={"query": "' OR '1'='1"},
        )
        result = HybridIDSEngine(
            make_artifacts(
                tabular_index=LABELS["normal"],
                sequence_index=LABELS["normal"],
                anomaly=True,
            )
        ).process_event(event)

        self.assertEqual(result["attack_type"], "sql_injection")
        self.assertEqual(result["prediction"], "attack")
        self.assertEqual(result["model_used"], "rules")
        self.assertIn(result["threat_level"], {"High", "Critical"})

    def test_selected_tabular_model_handles_known_attack(self) -> None:
        result = HybridIDSEngine(
            make_artifacts(tabular_index=LABELS["ssh_bruteforce"])
        ).process_event(make_event(service="ssh", event="connection"))

        self.assertEqual(result["attack_type"], "ssh_bruteforce")
        self.assertEqual(result["model_used"], "decision_tree")

    def test_lstm_can_detect_sequence_attack_when_tabular_is_normal(self) -> None:
        result = HybridIDSEngine(
            make_artifacts(sequence_index=LABELS["directory_scanning"])
        ).process_event(make_event())

        self.assertEqual(result["attack_type"], "directory_scanning")
        self.assertEqual(result["model_used"], "lstm_classifier")

    def test_isolation_forest_handles_unknown_anomaly(self) -> None:
        result = HybridIDSEngine(
            make_artifacts(anomaly=True)
        ).process_event(make_event())

        self.assertEqual(result["attack_type"], "other_anomaly")
        self.assertEqual(result["model_used"], "isolation_forest")
        self.assertIsNone(result["confidence"])
        self.assertTrue(result["components"]["anomaly"]["is_anomaly"])

    def test_normal_decision_uses_both_supervised_models(self) -> None:
        result = HybridIDSEngine(make_artifacts()).process_event(make_event())

        self.assertEqual(result["attack_type"], "normal")
        self.assertEqual(result["prediction"], "normal")
        self.assertEqual(
            result["model_used"],
            "decision_tree+lstm_classifier",
        )

    def test_sequences_are_left_padded_and_causal(self) -> None:
        artifacts = make_artifacts()
        engine = HybridIDSEngine(artifacts)
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
        engine = HybridIDSEngine(make_artifacts())
        event = make_event()
        engine.process_event(event)

        with self.assertRaisesRegex(ValueError, "duplicate event_id"):
            engine.process_event(event)

    def test_repeated_failed_logins_trigger_rule_on_third_event(self) -> None:
        engine = HybridIDSEngine(make_artifacts())
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


if __name__ == "__main__":
    unittest.main()
