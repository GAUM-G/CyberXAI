"""Run the Step 13 hybrid IDS on live common-event JSONL records.

The engine combines deterministic rules, the Step 12 selected tabular
classifier, Isolation Forest, and the LSTM sequence classifier. It performs
inference only: no model ``fit`` or artifact-writing operation exists here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import torch

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dataset.prepare_dataset import normalize_event, validate_event
from feature_engineering.engineer_features import (
    FeatureEngineeringState,
    engineer_rows,
)
from machine_learning.lstm_model import LSTMClassifier
from preprocessing.preprocess_dataset import rows_to_matrix
from rule_based_detection.detector import RuleBasedDetector


HYBRID_IDS_VERSION = "1.0"
DEFAULT_INPUT_DIR = Path("data/ml_ready")
DEFAULT_MODEL_DIR = DEFAULT_INPUT_DIR / "models"
DEFAULT_SELECTION_PATH = DEFAULT_INPUT_DIR / "evaluation" / "model_selection.json"
DEFAULT_LOG_PATH = Path("data/raw_logs/honeypot_events.jsonl")
DEFAULT_OUTPUT_PATH = Path("data/detections/hybrid_ids_results.jsonl")


def _read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read valid JSON from {path}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalize_label_mapping(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("label_mapping.json must contain a non-empty object")

    mapping: dict[str, int] = {}
    for raw_name, raw_index in value.items():
        name = str(raw_name).strip().lower()
        if not name:
            raise ValueError("label mapping contains an empty name")
        if isinstance(raw_index, bool) or not isinstance(raw_index, int):
            raise ValueError("label mapping indexes must be integers")
        mapping[name] = raw_index

    if sorted(mapping.values()) != list(range(len(mapping))):
        raise ValueError("label indexes must be contiguous and start at zero")
    if "normal" not in mapping or "other_anomaly" not in mapping:
        raise ValueError("label mapping must include normal and other_anomaly")
    return mapping


def _require_classifier_bundle(
    name: str,
    bundle: Any,
    *,
    feature_names: Sequence[str],
    label_mapping: Mapping[str, int],
) -> Any:
    if not isinstance(bundle, Mapping):
        raise ValueError(f"{name} artifact must contain a bundle")
    required = {
        "model_name": name,
        "purpose": "known_attack_classification",
        "fit_scope": "training_rows_only",
    }
    for key, expected in required.items():
        if bundle.get(key) != expected:
            raise ValueError(f"{name} bundle has invalid {key}")
    if list(bundle.get("feature_names", [])) != list(feature_names):
        raise ValueError(f"{name} feature names do not match")
    if dict(bundle.get("label_mapping", {})) != dict(label_mapping):
        raise ValueError(f"{name} label mapping does not match")

    estimator = bundle.get("estimator")
    if (
        estimator is None
        or not hasattr(estimator, "predict")
        or not hasattr(estimator, "predict_proba")
    ):
        raise ValueError(f"{name} bundle is missing a probabilistic estimator")
    return estimator


def _require_isolation_bundle(
    bundle: Any,
    *,
    feature_names: Sequence[str],
    normal_index: int,
) -> Any:
    if not isinstance(bundle, Mapping):
        raise ValueError("Isolation Forest artifact must contain a bundle")
    required = {
        "model_name": "isolation_forest",
        "purpose": "unknown_anomaly_detection",
        "fit_scope": "normal_training_features_only",
        "normal_label_index": normal_index,
    }
    for key, expected in required.items():
        if bundle.get(key) != expected:
            raise ValueError(f"Isolation Forest bundle has invalid {key}")
    if list(bundle.get("feature_names", [])) != list(feature_names):
        raise ValueError("Isolation Forest feature names do not match")

    estimator = bundle.get("estimator")
    if (
        estimator is None
        or not hasattr(estimator, "predict")
        or not hasattr(estimator, "decision_function")
    ):
        raise ValueError("Isolation Forest bundle is missing a usable estimator")
    return estimator


def _load_lstm(
    path: Path,
    *,
    label_mapping: Mapping[str, int],
    sequence_length: int,
    input_features: int,
    device: torch.device,
) -> LSTMClassifier:
    checkpoint = torch.load(
        path,
        map_location=device,
        weights_only=True,
    )
    if not isinstance(checkpoint, Mapping):
        raise ValueError("LSTM checkpoint must contain a mapping")
    if checkpoint.get("model_name") != "LSTMClassifier":
        raise ValueError("LSTM checkpoint contains the wrong model name")
    if dict(checkpoint.get("label_mapping", {})) != dict(label_mapping):
        raise ValueError("LSTM label mapping does not match")
    if checkpoint.get("sequence_length") != sequence_length:
        raise ValueError("LSTM sequence length does not match preprocessing")

    config = checkpoint.get("model_config")
    if not isinstance(config, Mapping):
        raise ValueError("LSTM checkpoint is missing model_config")
    if config.get("input_size") != input_features:
        raise ValueError("LSTM input size does not match encoded features")
    if config.get("num_classes") != len(label_mapping):
        raise ValueError("LSTM class count does not match label mapping")

    model = LSTMClassifier(
        input_size=int(config["input_size"]),
        num_classes=int(config["num_classes"]),
        hidden_size=int(config["hidden_size"]),
        num_layers=int(config["num_layers"]),
        dropout=float(config["dropout"]),
    )
    state = checkpoint.get("model_state_dict")
    if not isinstance(state, Mapping) or not state:
        raise ValueError("LSTM checkpoint is missing model_state_dict")
    model.load_state_dict(state, strict=True)
    model.to(device)
    model.eval()
    return model


@dataclass(frozen=True)
class HybridArtifacts:
    """Validated, inference-only objects loaded from Steps 7, 10, 11 and 12."""

    preprocessor: Any
    tabular_model_name: str
    tabular_estimator: Any
    isolation_estimator: Any
    lstm_model: torch.nn.Module
    feature_names: tuple[str, ...]
    label_mapping: dict[str, int]
    sequence_length: int
    device: torch.device
    protected_hashes: dict[Path, str]

    def verify_unchanged(self) -> None:
        changed = [
            str(path)
            for path, expected in self.protected_hashes.items()
            if not path.is_file() or _sha256(path) != expected
        ]
        if changed:
            raise RuntimeError(
                "protected Step 12 artifacts changed: " + ", ".join(changed)
            )


def load_hybrid_artifacts(
    input_dir: Path = DEFAULT_INPUT_DIR,
    model_dir: Path = DEFAULT_MODEL_DIR,
    selection_path: Path = DEFAULT_SELECTION_PATH,
    *,
    device_name: str = "cpu",
) -> HybridArtifacts:
    """Load and validate Step 12 selections without modifying any artifact."""

    input_dir = input_dir.resolve()
    model_dir = model_dir.resolve()
    selection_path = selection_path.resolve()
    input_paths = {
        "preprocessor": input_dir / "preprocessor.joblib",
        "feature_names": input_dir / "feature_names.json",
        "label_mapping": input_dir / "label_mapping.json",
        "preprocessing_manifest": input_dir / "preprocessing_manifest.json",
    }
    selection = _read_json(selection_path)
    if not isinstance(selection, Mapping):
        raise ValueError("model_selection.json must contain an object")

    best_tabular = selection.get("best_tabular_classifier", {})
    tabular_name = (
        str(best_tabular.get("selected_model", "")).strip().lower()
        if isinstance(best_tabular, Mapping)
        else ""
    )
    if tabular_name not in {"decision_tree", "random_forest"}:
        raise ValueError("Step 12 did not select a supported tabular classifier")

    roles = selection.get("step13_hybrid_roles", {})
    if not isinstance(roles, Mapping):
        raise ValueError("Step 13 hybrid roles are missing")
    expected_roles = {
        "known_attack_classifier": tabular_name,
        "sequence_attack_classifier": "lstm_classifier",
        "unknown_anomaly_detector": "isolation_forest",
    }
    for role, expected in expected_roles.items():
        if roles.get(role) != expected:
            raise ValueError(f"model selection has invalid {role}")

    model_paths = {
        "tabular": model_dir / f"{tabular_name}.joblib",
        "isolation": model_dir / "isolation_forest.joblib",
        "lstm": model_dir / "lstm_classifier.pt",
    }
    protected_paths = {
        *input_paths.values(),
        *model_paths.values(),
        selection_path,
    }
    missing = [str(path) for path in protected_paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "missing required Step 13 artifacts: " + ", ".join(sorted(missing))
        )

    hashes_before = {path: _sha256(path) for path in protected_paths}
    feature_names_value = _read_json(input_paths["feature_names"])
    if not isinstance(feature_names_value, list) or not feature_names_value:
        raise ValueError("feature_names.json must contain a non-empty list")
    feature_names = tuple(str(item).strip() for item in feature_names_value)
    if any(not item for item in feature_names):
        raise ValueError("feature_names.json contains an empty feature name")
    if len(feature_names) != len(set(feature_names)):
        raise ValueError("feature_names.json contains duplicates")

    label_mapping = _normalize_label_mapping(
        _read_json(input_paths["label_mapping"])
    )
    manifest = _read_json(input_paths["preprocessing_manifest"])
    if not isinstance(manifest, Mapping):
        raise ValueError("preprocessing_manifest.json must contain an object")
    feature_contract = manifest.get("features", {})
    sequence_contract = manifest.get("sequences", {})
    safety = manifest.get("safety", {})
    if (
        not isinstance(feature_contract, Mapping)
        or feature_contract.get("encoded_feature_count") != len(feature_names)
    ):
        raise ValueError("preprocessing feature contract does not match")
    if not isinstance(sequence_contract, Mapping):
        raise ValueError("preprocessing sequence contract is missing")
    sequence_length = sequence_contract.get("length")
    if isinstance(sequence_length, bool) or not isinstance(sequence_length, int):
        raise ValueError("preprocessing sequence length is invalid")
    if sequence_length < 2:
        raise ValueError("preprocessing sequence length must be at least two")
    required_safe_flags = {
        "preprocessor_fitted_on_test_data": False,
        "raw_payload_used_as_direct_model_input": False,
        "direct_identifiers_used_as_model_inputs": False,
        "labels_used_for_feature_engineering": False,
        "future_events_used_for_feature_engineering": False,
    }
    if not isinstance(safety, Mapping) or any(
        safety.get(name) is not expected
        for name, expected in required_safe_flags.items()
    ):
        raise ValueError("preprocessing manifest has an unsafe contract")

    device = torch.device(device_name)
    if device.type == "cuda" and not torch.cuda.is_available():
        raise ValueError("CUDA was requested but is not available")

    preprocessor = joblib.load(input_paths["preprocessor"])
    if not hasattr(preprocessor, "transform"):
        raise ValueError("preprocessor artifact is missing transform")
    tabular_estimator = _require_classifier_bundle(
        tabular_name,
        joblib.load(model_paths["tabular"]),
        feature_names=feature_names,
        label_mapping=label_mapping,
    )
    isolation_estimator = _require_isolation_bundle(
        joblib.load(model_paths["isolation"]),
        feature_names=feature_names,
        normal_index=label_mapping["normal"],
    )
    lstm_model = _load_lstm(
        model_paths["lstm"],
        label_mapping=label_mapping,
        sequence_length=sequence_length,
        input_features=len(feature_names),
        device=device,
    )

    hashes_after = {path: _sha256(path) for path in protected_paths}
    if hashes_after != hashes_before:
        raise RuntimeError("artifact loading modified protected Step 12 files")

    return HybridArtifacts(
        preprocessor=preprocessor,
        tabular_model_name=tabular_name,
        tabular_estimator=tabular_estimator,
        isolation_estimator=isolation_estimator,
        lstm_model=lstm_model,
        feature_names=feature_names,
        label_mapping=label_mapping,
        sequence_length=sequence_length,
        device=device,
        protected_hashes=hashes_before,
    )


class HybridIDSEngine:
    """Stateful causal fusion engine for one chronologically ordered event feed."""

    def __init__(
        self,
        artifacts: HybridArtifacts,
        *,
        hash_salt: str = "honeypot-dataset-v1",
        sequence_attack_threshold: float = 0.60,
        rule_detector: RuleBasedDetector | None = None,
    ) -> None:
        if not 0.0 <= sequence_attack_threshold <= 1.0:
            raise ValueError("sequence attack threshold must be between 0 and 1")
        self.artifacts = artifacts
        self.hash_salt = str(hash_salt)
        self.sequence_attack_threshold = float(sequence_attack_threshold)
        self.rule_detector = rule_detector or RuleBasedDetector()
        self.feature_state = FeatureEngineeringState()
        self.sequence_buffers: dict[
            tuple[str, str], deque[np.ndarray]
        ] = defaultdict(
            lambda: deque(maxlen=self.artifacts.sequence_length)
        )
        self._processed_event_ids: set[str] = set()
        self._names_by_index = {
            index: name
            for name, index in self.artifacts.label_mapping.items()
        }
        self._lock = RLock()

    def _tabular_prediction(
        self,
        encoded: np.ndarray,
    ) -> tuple[str, float]:
        estimator = self.artifacts.tabular_estimator
        index = int(np.asarray(estimator.predict(encoded)).reshape(-1)[0])
        if index not in self._names_by_index:
            raise RuntimeError("tabular classifier returned an unknown class")

        probabilities = np.asarray(estimator.predict_proba(encoded), dtype=float)
        classes = np.asarray(estimator.classes_, dtype=int).reshape(-1)
        if probabilities.shape != (1, len(classes)):
            raise RuntimeError("tabular classifier returned invalid probabilities")
        positions = np.flatnonzero(classes == index)
        if len(positions) != 1:
            raise RuntimeError("tabular class is missing from probability output")
        confidence = float(probabilities[0, int(positions[0])])
        return self._names_by_index[index], confidence

    def _anomaly_prediction(
        self,
        encoded: np.ndarray,
    ) -> tuple[bool, float]:
        estimator = self.artifacts.isolation_estimator
        prediction = int(np.asarray(estimator.predict(encoded)).reshape(-1)[0])
        if prediction not in {-1, 1}:
            raise RuntimeError("Isolation Forest returned an invalid prediction")
        decision_score = float(
            np.asarray(estimator.decision_function(encoded)).reshape(-1)[0]
        )
        if not np.isfinite(decision_score):
            raise RuntimeError("Isolation Forest returned a non-finite score")
        return prediction == -1, -decision_score

    def _sequence_prediction(
        self,
        encoded: np.ndarray,
        *,
        group: tuple[str, str],
    ) -> tuple[str, float, int]:
        history = self.sequence_buffers[group]
        history.append(encoded[0].copy())
        context_events = len(history)
        sequence = np.zeros(
            (
                self.artifacts.sequence_length,
                len(self.artifacts.feature_names),
            ),
            dtype=np.float32,
        )
        sequence[-context_events:] = np.stack(tuple(history))
        tensor = torch.from_numpy(sequence).unsqueeze(0).to(
            self.artifacts.device
        )
        with torch.inference_mode():
            logits = self.artifacts.lstm_model(tensor)
            probabilities = torch.softmax(logits, dim=1)
            index = int(torch.argmax(probabilities, dim=1).item())
            confidence = float(probabilities[0, index].item())
        if index not in self._names_by_index:
            raise RuntimeError("LSTM returned an unknown class")
        return self._names_by_index[index], confidence, context_events

    def _fuse(
        self,
        *,
        rule_findings: Sequence[Mapping[str, Any]],
        tabular_label: str,
        tabular_confidence: float,
        sequence_label: str,
        sequence_confidence: float,
        sequence_events: int,
        is_anomaly: bool,
    ) -> tuple[str, str, float | None, str, str]:
        normal = "normal"
        if rule_findings:
            strongest = max(
                rule_findings,
                key=lambda item: (
                    float(item.get("confidence", 0.0)),
                    str(item.get("attack_type", "")),
                ),
            )
            return (
                str(strongest["attack_type"]),
                "attack",
                float(strongest["confidence"]),
                "rules",
                "deterministic rule matched",
            )

        tabular_attack = tabular_label != normal
        sequence_attack = (
            sequence_label != normal
            and sequence_confidence >= self.sequence_attack_threshold
        )
        if tabular_attack:
            if sequence_attack and sequence_label == tabular_label:
                return (
                    tabular_label,
                    "attack",
                    (tabular_confidence + sequence_confidence) / 2.0,
                    (
                        f"{self.artifacts.tabular_model_name}"
                        "+lstm_classifier"
                    ),
                    "tabular and sequence classifiers agreed",
                )
            return (
                tabular_label,
                "attack",
                tabular_confidence,
                self.artifacts.tabular_model_name,
                "Step 12 selected tabular classifier identified a known attack",
            )

        if sequence_attack:
            return (
                sequence_label,
                "attack",
                sequence_confidence,
                "lstm_classifier",
                (
                    "LSTM identified a sequence attack using "
                    f"{sequence_events} causal event(s)"
                ),
            )

        if is_anomaly:
            return (
                "other_anomaly",
                "attack",
                None,
                "isolation_forest",
                (
                    "Isolation Forest flagged an unknown anomaly; confidence "
                    "is null because its score is not a calibrated probability"
                ),
            )

        normal_confidences = [tabular_confidence]
        if sequence_label == normal:
            normal_confidences.append(sequence_confidence)
        return (
            normal,
            "normal",
            float(sum(normal_confidences) / len(normal_confidences)),
            f"{self.artifacts.tabular_model_name}+lstm_classifier",
            "no rule, known attack, sequence attack or unknown anomaly detected",
        )

    def process_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """Validate, feature-engineer, infer and fuse one common event."""

        errors = validate_event(event)
        if errors:
            raise ValueError("invalid common event: " + "; ".join(errors))

        event_id = str(event["event_id"]).strip().lower()
        with self._lock:
            if event_id in self._processed_event_ids:
                raise ValueError(f"duplicate event_id: {event_id}")

            rule_findings = [
                finding.to_dict()
                for finding in self.rule_detector.inspect(event)
            ]

            # Prevent the producer's attack_type from entering even the
            # temporary target column created by Step 6 normalization.
            neutral_event = dict(event)
            neutral_event["attack_type"] = "normal"
            row = normalize_event(neutral_event, hash_salt=self.hash_salt)
            row["_timestamp"] = row["timestamp_utc"]
            featured = engineer_rows([row], state=self.feature_state)[0]
            matrix = rows_to_matrix([featured])
            encoded = np.asarray(
                self.artifacts.preprocessor.transform(matrix),
                dtype=np.float32,
            )
            expected_shape = (1, len(self.artifacts.feature_names))
            if encoded.shape != expected_shape:
                raise RuntimeError(
                    "preprocessor output shape mismatch: "
                    f"expected {expected_shape}, received {encoded.shape}"
                )
            if not np.isfinite(encoded).all():
                raise RuntimeError("preprocessor produced non-finite features")

            tabular_label, tabular_confidence = self._tabular_prediction(encoded)
            is_anomaly, anomaly_score = self._anomaly_prediction(encoded)
            group = (str(featured["source_ip_hash"]), str(featured["service"]))
            sequence_label, sequence_confidence, sequence_events = (
                self._sequence_prediction(encoded, group=group)
            )
            (
                attack_type,
                prediction,
                confidence,
                model_used,
                fusion_reason,
            ) = self._fuse(
                rule_findings=rule_findings,
                tabular_label=tabular_label,
                tabular_confidence=tabular_confidence,
                sequence_label=sequence_label,
                sequence_confidence=sequence_confidence,
                sequence_events=sequence_events,
                is_anomaly=is_anomaly,
            )
            self._processed_event_ids.add(event_id)

        return {
            "hybrid_ids_version": HYBRID_IDS_VERSION,
            "event_id": event_id,
            "timestamp": event["timestamp"],
            "service": event["service"],
            "attack_type": attack_type,
            "prediction": prediction,
            "confidence": (
                None if confidence is None else round(float(confidence), 6)
            ),
            "anomaly_score": round(float(anomaly_score), 6),
            "model_used": model_used,
            "components": {
                "rules": {
                    "finding_count": len(rule_findings),
                    "findings": [
                        {
                            "attack_type": finding["attack_type"],
                            "confidence": finding["confidence"],
                            "matched_rules": finding["matched_rules"],
                        }
                        for finding in rule_findings
                    ],
                },
                "tabular": {
                    "model": self.artifacts.tabular_model_name,
                    "attack_type": tabular_label,
                    "confidence": round(tabular_confidence, 6),
                },
                "sequence": {
                    "model": "lstm_classifier",
                    "attack_type": sequence_label,
                    "confidence": round(sequence_confidence, 6),
                    "context_events": sequence_events,
                    "sequence_length": self.artifacts.sequence_length,
                },
                "anomaly": {
                    "model": "isolation_forest",
                    "is_anomaly": is_anomaly,
                    "anomaly_score": round(anomaly_score, 6),
                },
            },
            "fusion_reason": fusion_reason,
            "safety": {
                "model_fit_called": False,
                "protected_artifacts_modified": False,
                "producer_attack_type_used_as_model_feature": False,
                "raw_payload_in_result": False,
                "future_events_used": False,
            },
        }


def _append_jsonl(path: Path, record: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
        handle.write("\n")


def _process_line(
    engine: HybridIDSEngine,
    line: str,
    *,
    output_path: Path,
    line_number: int | None = None,
) -> bool:
    try:
        value = json.loads(line)
        if not isinstance(value, Mapping):
            raise ValueError("JSON value is not an object")
        result = engine.process_event(value)
    except (json.JSONDecodeError, ValueError, RuntimeError) as exc:
        location = f" line {line_number}" if line_number is not None else ""
        print(f"[HYBRID IDS] SKIP{location}: {exc}", file=sys.stderr)
        return False

    _append_jsonl(output_path, result)
    confidence = (
        "n/a"
        if result["confidence"] is None
        else f"{result['confidence']:.4f}"
    )
    print(
        "[HYBRID IDS] "
        f"{result['service']} | {result['attack_type']} | "
        f"{result['prediction']} | confidence={confidence} | "
        f"anomaly_score={result['anomaly_score']:.4f} | "
        f"model={result['model_used']}"
    )
    return True


def run_once(
    engine: HybridIDSEngine,
    *,
    log_path: Path,
    output_path: Path,
) -> tuple[int, int]:
    if not log_path.is_file():
        raise FileNotFoundError(f"honeypot log not found: {log_path}")
    processed = 0
    skipped = 0
    with log_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            if _process_line(
                engine,
                line,
                output_path=output_path,
                line_number=line_number,
            ):
                processed += 1
            else:
                skipped += 1
    return processed, skipped


def follow_log(
    engine: HybridIDSEngine,
    *,
    log_path: Path,
    output_path: Path,
    replay_existing: bool,
    poll_seconds: float,
) -> None:
    if poll_seconds <= 0:
        raise ValueError("poll seconds must be positive")
    print(f"[HYBRID IDS] Waiting for events in: {log_path.resolve()}")
    while not log_path.is_file():
        time.sleep(poll_seconds)

    with log_path.open("r", encoding="utf-8") as handle:
        if not replay_existing:
            handle.seek(0, os.SEEK_END)
        line_number = 0
        while True:
            line = handle.readline()
            if not line:
                time.sleep(poll_seconds)
                continue
            line_number += 1
            if line.strip():
                _process_line(
                    engine,
                    line,
                    output_path=output_path,
                    line_number=line_number,
                )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="validate all Step 13 artifacts and exit (default mode)",
    )
    mode.add_argument(
        "--once",
        action="store_true",
        help="process all currently stored JSONL events and exit",
    )
    mode.add_argument(
        "--follow",
        action="store_true",
        help="follow the live JSONL log until Ctrl+C",
    )
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument(
        "--selection-path",
        type=Path,
        default=DEFAULT_SELECTION_PATH,
    )
    parser.add_argument("--log-path", type=Path, default=DEFAULT_LOG_PATH)
    parser.add_argument("--output-path", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument(
        "--hash-salt",
        default=os.environ.get(
            "DATASET_HASH_SALT",
            "honeypot-dataset-v1",
        ),
    )
    parser.add_argument(
        "--sequence-attack-threshold",
        type=float,
        default=0.60,
    )
    parser.add_argument(
        "--replay-existing",
        action="store_true",
        help="with --follow, process existing records before new ones",
    )
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    artifacts = load_hybrid_artifacts(
        args.input_dir,
        args.model_dir,
        args.selection_path,
        device_name=args.device,
    )
    engine = HybridIDSEngine(
        artifacts,
        hash_salt=args.hash_salt,
        sequence_attack_threshold=args.sequence_attack_threshold,
    )
    print("[HYBRID IDS] PASS: Step 12 artifacts loaded without retraining.")
    print(
        "[HYBRID IDS] Models: rules + "
        f"{artifacts.tabular_model_name} + isolation_forest + lstm_classifier"
    )
    print(
        "[HYBRID IDS] Features/sequence:",
        f"{len(artifacts.feature_names)}/{artifacts.sequence_length}",
    )

    if not args.once and not args.follow:
        artifacts.verify_unchanged()
        print("[HYBRID IDS] PASS: Protected artifacts are unchanged.")
        return 0

    try:
        if args.once:
            processed, skipped = run_once(
                engine,
                log_path=args.log_path,
                output_path=args.output_path,
            )
            print(
                f"[HYBRID IDS] Completed: processed={processed}, "
                f"skipped={skipped}"
            )
        else:
            follow_log(
                engine,
                log_path=args.log_path,
                output_path=args.output_path,
                replay_existing=args.replay_existing,
                poll_seconds=args.poll_seconds,
            )
    except KeyboardInterrupt:
        print("\n[HYBRID IDS] Stopped by user.")
    finally:
        artifacts.verify_unchanged()
        print("[HYBRID IDS] PASS: Protected artifacts are unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
