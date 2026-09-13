"""Evaluate and select Step 12 IDS models without retraining them."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import statistics
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import joblib
import numpy as np
import sklearn
import torch
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)

try:
    from machine_learning.lstm_model import LSTMClassifier
except ModuleNotFoundError:
    from lstm_model import LSTMClassifier


EVALUATION_VERSION = "1.0"
SUPERVISED_ARTIFACTS = {
    "decision_tree": "decision_tree.joblib",
    "random_forest": "random_forest.joblib",
}
ISOLATION_ARTIFACT = "isolation_forest.joblib"
LSTM_ARTIFACT = "lstm_classifier.pt"
LSTM_METRICS_ARTIFACT = "lstm_metrics.json"
TRAINING_MANIFEST_ARTIFACT = "training_manifest.json"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read valid JSON from {path}") from exc


def _write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(
            value,
            handle,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")


def _load_array(path: Path) -> np.ndarray:
    try:
        return np.load(path, allow_pickle=False)
    except (OSError, ValueError) as exc:
        raise ValueError(f"could not load safe NumPy array from {path}") from exc


def _normalize_label_mapping(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("label_mapping.json must contain a non-empty object")

    result: dict[str, int] = {}
    for raw_label, raw_index in value.items():
        label = str(raw_label).strip().lower()
        if not label:
            raise ValueError("label mapping contains an empty label")
        if isinstance(raw_index, bool) or not isinstance(raw_index, int):
            raise ValueError("label mapping indexes must be integers")
        if label in result:
            raise ValueError(f"duplicate normalized label: {label}")
        result[label] = raw_index

    expected_indexes = list(range(len(result)))
    if sorted(result.values()) != expected_indexes:
        raise ValueError(
            "label mapping indexes must be contiguous and start at zero"
        )
    if "normal" not in result:
        raise ValueError("label mapping must contain the normal class")
    return result


def _validate_feature_array(
    name: str,
    value: np.ndarray,
    *,
    dimensions: int,
) -> None:
    if value.ndim != dimensions:
        raise ValueError(f"{name} must have {dimensions} dimensions")
    if any(size < 1 for size in value.shape):
        raise ValueError(f"{name} must not contain an empty dimension")
    if not np.issubdtype(value.dtype, np.number):
        raise ValueError(f"{name} must contain numeric values")
    if not np.isfinite(value).all():
        raise ValueError(f"{name} contains non-finite values")


def _validate_labels(
    name: str,
    value: np.ndarray,
    *,
    rows: int,
    allowed_indexes: set[int],
) -> None:
    if value.ndim != 1 or len(value) != rows:
        raise ValueError(f"{name} does not align with its feature array")
    if not np.issubdtype(value.dtype, np.integer):
        raise ValueError(f"{name} must contain integer indexes")
    unknown = sorted(set(map(int, value.tolist())) - allowed_indexes)
    if unknown:
        raise ValueError(f"{name} contains unknown label indexes: {unknown}")


def _safe_rate(numerator: int | float, denominator: int | float) -> float:
    if denominator == 0:
        return 0.0
    return float(numerator / denominator)


def _binary_confusion_counts(
    truth: np.ndarray,
    predictions: np.ndarray,
) -> tuple[int, int, int, int]:
    matrix = confusion_matrix(truth, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (
        int(item) for item in matrix.ravel()
    )
    return true_negative, false_positive, false_negative, true_positive


def _multiclass_metrics(
    truth: np.ndarray,
    predictions: np.ndarray,
    label_mapping: Mapping[str, int],
) -> dict[str, Any]:
    indexes = list(range(len(label_mapping)))
    names_by_index = {
        index: label for label, index in label_mapping.items()
    }
    names = [names_by_index[index] for index in indexes]
    normal_index = label_mapping["normal"]

    matrix = confusion_matrix(truth, predictions, labels=indexes)
    macro_precision, macro_recall, macro_f1, _ = (
        precision_recall_fscore_support(
            truth,
            predictions,
            labels=indexes,
            average="macro",
            zero_division=0,
        )
    )
    weighted_precision, weighted_recall, weighted_f1, _ = (
        precision_recall_fscore_support(
            truth,
            predictions,
            labels=indexes,
            average="weighted",
            zero_division=0,
        )
    )
    class_precision, class_recall, class_f1, class_support = (
        precision_recall_fscore_support(
            truth,
            predictions,
            labels=indexes,
            average=None,
            zero_division=0,
        )
    )

    per_class: dict[str, Any] = {}
    one_vs_rest_fprs: list[float] = []
    total = int(matrix.sum())
    for position, name in enumerate(names):
        true_positive = int(matrix[position, position])
        false_negative = int(matrix[position, :].sum() - true_positive)
        false_positive = int(matrix[:, position].sum() - true_positive)
        true_negative = total - true_positive - false_negative - false_positive
        false_positive_rate = _safe_rate(
            false_positive,
            false_positive + true_negative,
        )
        one_vs_rest_fprs.append(false_positive_rate)
        per_class[name] = {
            "precision": float(class_precision[position]),
            "recall": float(class_recall[position]),
            "f1_score": float(class_f1[position]),
            "support": int(class_support[position]),
            "false_positive_rate_one_vs_rest": false_positive_rate,
        }

    attack_truth = (truth != normal_index).astype(np.int8)
    attack_predictions = (predictions != normal_index).astype(np.int8)
    true_negative, false_positive, false_negative, true_positive = (
        _binary_confusion_counts(attack_truth, attack_predictions)
    )

    return {
        "metric_scope": "multiclass_attack_classification",
        "test_rows": int(len(truth)),
        "accuracy": float(accuracy_score(truth, predictions)),
        "balanced_accuracy": float(
            balanced_accuracy_score(truth, predictions)
        ),
        "precision_macro": float(macro_precision),
        "recall_macro": float(macro_recall),
        "f1_macro": float(macro_f1),
        "precision_weighted": float(weighted_precision),
        "recall_weighted": float(weighted_recall),
        "f1_weighted": float(weighted_f1),
        "false_positive_rate": {
            "normal_as_attack": _safe_rate(
                false_positive,
                false_positive + true_negative,
            ),
            "macro_one_vs_rest": float(np.mean(one_vs_rest_fprs)),
            "definition": (
                "normal_as_attack is the fraction of true normal rows "
                "predicted as any attack"
            ),
        },
        "attack_detection_binary_view": {
            "precision": float(
                precision_score(
                    attack_truth,
                    attack_predictions,
                    zero_division=0,
                )
            ),
            "recall": float(
                recall_score(
                    attack_truth,
                    attack_predictions,
                    zero_division=0,
                )
            ),
            "f1_score": float(
                f1_score(
                    attack_truth,
                    attack_predictions,
                    zero_division=0,
                )
            ),
            "false_positive_rate": _safe_rate(
                false_positive,
                false_positive + true_negative,
            ),
            "false_negative_rate": _safe_rate(
                false_negative,
                false_negative + true_positive,
            ),
            "confusion_matrix": {
                "labels": ["normal", "attack"],
                "values": [
                    [true_negative, false_positive],
                    [false_negative, true_positive],
                ],
            },
        },
        "per_class": per_class,
        "classification_report": classification_report(
            truth,
            predictions,
            labels=indexes,
            target_names=names,
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": {
            "labels": names,
            "values": matrix.astype(int).tolist(),
        },
    }


def _anomaly_metrics(
    original_labels: np.ndarray,
    isolation_predictions: np.ndarray,
    decision_scores: np.ndarray,
    *,
    normal_index: int,
    other_anomaly_index: int | None = None,
    anomaly_score_threshold: float = 0.0,
) -> dict[str, Any]:
    all_truth = (original_labels != normal_index).astype(np.int8)
    all_predictions = (isolation_predictions == -1).astype(np.int8)
    anomaly_scores_all = -np.asarray(decision_scores, dtype=np.float64)

    if other_anomaly_index is None:
        scope_mask = np.ones(len(original_labels), dtype=bool)
        positive_class = "attack_or_anomaly"
    else:
        scope_mask = np.isin(
            original_labels,
            np.asarray([normal_index, other_anomaly_index]),
        )
        positive_class = "other_anomaly"

    truth = (
        original_labels[scope_mask] != normal_index
    ).astype(np.int8)
    predictions = all_predictions[scope_mask]
    anomaly_scores = anomaly_scores_all[scope_mask]
    true_negative, false_positive, false_negative, true_positive = (
        _binary_confusion_counts(truth, predictions)
    )

    if len(np.unique(truth)) == 2:
        roc_auc = float(roc_auc_score(truth, anomaly_scores))
        average_precision = float(
            average_precision_score(truth, anomaly_scores)
        )
    else:
        roc_auc = None
        average_precision = None

    all_tn, all_fp, all_fn, all_tp = _binary_confusion_counts(
        all_truth,
        all_predictions,
    )

    return {
        "metric_scope": (
            "binary_other_anomaly_vs_normal"
            if other_anomaly_index is not None
            else "binary_unknown_anomaly_detection"
        ),
        "test_rows": int(len(truth)),
        "positive_class": positive_class,
        "accuracy": float(accuracy_score(truth, predictions)),
        "balanced_accuracy": float(
            balanced_accuracy_score(truth, predictions)
        ),
        "precision": float(
            precision_score(truth, predictions, zero_division=0)
        ),
        "recall": float(recall_score(truth, predictions, zero_division=0)),
        "f1_score": float(f1_score(truth, predictions, zero_division=0)),
        "false_positive_rate": _safe_rate(
            false_positive,
            false_positive + true_negative,
        ),
        "false_negative_rate": _safe_rate(
            false_negative,
            false_negative + true_positive,
        ),
        "specificity": _safe_rate(
            true_negative,
            true_negative + false_positive,
        ),
        "roc_auc_from_anomaly_score": roc_auc,
        "average_precision_from_anomaly_score": average_precision,
        "decision_score_contract": {
            "estimator_score": "higher values indicate a more normal sample",
            "reported_anomaly_score": (
                "negative decision_function; higher values indicate anomaly"
            ),
            "anomaly_score_threshold": float(anomaly_score_threshold),
            "threshold_selection": (
                "validation-calibrated when recorded in the model bundle; "
                "otherwise sklearn default zero"
            ),
        },
        "anomaly_score_summary": {
            "minimum": float(np.min(anomaly_scores)),
            "maximum": float(np.max(anomaly_scores)),
            "mean": float(np.mean(anomaly_scores)),
            "median": float(np.median(anomaly_scores)),
        },
        "classification_report": classification_report(
            truth,
            predictions,
            labels=[0, 1],
            target_names=["normal", positive_class],
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": {
            "labels": ["normal", positive_class],
            "values": [
                [true_negative, false_positive],
                [false_negative, true_positive],
            ],
        },
        "known_attack_coverage_secondary": {
            "scope": (
                "all non-normal labels; diagnostic only because Isolation "
                "Forest is assigned to unknown-anomaly detection"
            ),
            "rows": int(len(all_truth)),
            "recall": _safe_rate(all_tp, all_tp + all_fn),
            "false_positive_rate": _safe_rate(all_fp, all_fp + all_tn),
            "confusion_matrix": {
                "labels": ["normal", "any_non_normal"],
                "values": [[all_tn, all_fp], [all_fn, all_tp]],
            },
        },
    }


def _synchronize(device: torch.device) -> None:
    if device.type == "cuda":
        torch.cuda.synchronize(device)


def _benchmark(
    operation: Callable[[], np.ndarray],
    *,
    rows: int,
    warmup_runs: int,
    timing_runs: int,
    synchronize: Callable[[], None] | None = None,
) -> tuple[np.ndarray, dict[str, Any]]:
    if warmup_runs < 0 or timing_runs < 1:
        raise ValueError("warmup runs must be non-negative and timing runs positive")

    for _ in range(warmup_runs):
        operation()
    if synchronize is not None:
        synchronize()

    durations_ns: list[int] = []
    predictions: np.ndarray | None = None
    for _ in range(timing_runs):
        if synchronize is not None:
            synchronize()
        start = time.perf_counter_ns()
        predictions = np.asarray(operation())
        if synchronize is not None:
            synchronize()
        durations_ns.append(time.perf_counter_ns() - start)

    if predictions is None or len(predictions) != rows:
        raise RuntimeError("inference output did not align with test rows")

    median_ns = statistics.median(durations_ns)
    return predictions, {
        "warmup_runs": warmup_runs,
        "timing_runs": timing_runs,
        "test_rows_per_run": rows,
        "measurement_scope": (
            "model prediction only; artifact and array loading excluded"
        ),
        "minimum_total_ms": float(min(durations_ns) / 1_000_000),
        "median_total_ms": float(median_ns / 1_000_000),
        "mean_total_ms": float(statistics.mean(durations_ns) / 1_000_000),
        "p95_total_ms": float(
            np.percentile(np.asarray(durations_ns), 95) / 1_000_000
        ),
        "median_per_row_microseconds": float(median_ns / rows / 1_000),
    }


def _require_classifier_bundle(
    name: str,
    bundle: Any,
    *,
    feature_names: Sequence[str],
    label_mapping: Mapping[str, int],
) -> Any:
    if not isinstance(bundle, Mapping):
        raise ValueError(f"{name} artifact must contain a bundle")
    if bundle.get("model_name") != name:
        raise ValueError(f"{name} bundle contains the wrong model name")
    if bundle.get("purpose") != "known_attack_classification":
        raise ValueError(f"{name} bundle contains the wrong purpose")
    if bundle.get("fit_scope") != "training_rows_only":
        raise ValueError(f"{name} bundle contains an unsafe fit scope")
    if list(bundle.get("feature_names", [])) != list(feature_names):
        raise ValueError(f"{name} feature names do not match")
    if dict(bundle.get("label_mapping", {})) != dict(label_mapping):
        raise ValueError(f"{name} label mapping does not match")
    estimator = bundle.get("estimator")
    if estimator is None or not hasattr(estimator, "predict"):
        raise ValueError(f"{name} bundle is missing a usable estimator")
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
            raise ValueError(
                f"Isolation Forest bundle has invalid {key}: "
                f"{bundle.get(key)!r}"
            )
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
        raise ValueError("LSTM sequence length does not match test arrays")

    config = checkpoint.get("model_config")
    if not isinstance(config, Mapping):
        raise ValueError("LSTM checkpoint is missing model_config")
    if config.get("input_size") != input_features:
        raise ValueError("LSTM input size does not match test arrays")
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


def _select_tabular_classifier(
    results: Mapping[str, Mapping[str, Any]],
    *,
    tolerance: float,
) -> dict[str, Any]:
    remaining = sorted(results)
    criteria = (
        ("f1_macro", "higher"),
        ("balanced_accuracy", "higher"),
        ("recall_macro", "higher"),
        ("accuracy", "higher"),
        ("false_positive_rate.normal_as_attack", "lower"),
    )
    decisive_criterion = "all predictive criteria tied"

    def value_for(name: str, path: str) -> float:
        value: Any = results[name]
        for component in path.split("."):
            value = value[component]
        return float(value)

    for path, direction in criteria:
        values = {name: value_for(name, path) for name in remaining}
        best = (
            max(values.values())
            if direction == "higher"
            else min(values.values())
        )
        finalists = [
            name
            for name, value in values.items()
            if abs(value - best) <= tolerance
        ]
        if len(finalists) == 1:
            remaining = finalists
            decisive_criterion = f"{direction} {path}"
            break
        remaining = finalists

    if len(remaining) == 1:
        selected = remaining[0]
        tie_breaker = None
    elif "random_forest" in remaining:
        selected = "random_forest"
        tie_breaker = (
            "Predictive criteria tied within tolerance; Random Forest retained "
            "as the predeclared Step 13 ensemble classifier and Decision Tree "
            "remains the interpretable baseline."
        )
    else:
        selected = sorted(remaining)[0]
        tie_breaker = "Predictive criteria tied; deterministic name ordering used."

    return {
        "selected_model": selected,
        "candidate_models": sorted(results),
        "decisive_criterion": decisive_criterion,
        "tie_tolerance": tolerance,
        "tie_breaker": tie_breaker,
        "selection_order": [
            "higher macro F1",
            "higher balanced accuracy",
            "higher macro recall",
            "higher accuracy",
            "lower normal-as-attack false-positive rate",
            "Random Forest architecture tie-breaker",
        ],
        "latency_policy": (
            "Inference latency is reported separately and does not override "
            "predictive quality."
        ),
    }


def _select_supervised_metric_leader(
    results: Mapping[str, Mapping[str, Any]],
) -> str:
    return max(
        sorted(results),
        key=lambda name: (
            float(results[name]["f1_macro"]),
            float(results[name]["balanced_accuracy"]),
            float(results[name]["recall_macro"]),
            float(results[name]["accuracy"]),
        ),
    )


def _write_summary_csv(
    path: Path,
    model_results: Mapping[str, Mapping[str, Any]],
) -> None:
    fields = [
        "model",
        "role",
        "metric_scope",
        "test_rows",
        "accuracy",
        "balanced_accuracy",
        "precision",
        "recall",
        "f1_score",
        "false_positive_rate",
        "median_total_ms",
        "median_per_row_microseconds",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for name in (
            "decision_tree",
            "random_forest",
            "lstm_classifier",
            "isolation_forest",
        ):
            result = model_results[name]
            metrics = result["metrics"]
            if name == "isolation_forest":
                precision = metrics["precision"]
                recall = metrics["recall"]
                f1_value = metrics["f1_score"]
                false_positive_rate = metrics["false_positive_rate"]
            else:
                precision = metrics["precision_macro"]
                recall = metrics["recall_macro"]
                f1_value = metrics["f1_macro"]
                false_positive_rate = metrics["false_positive_rate"][
                    "normal_as_attack"
                ]
            writer.writerow(
                {
                    "model": name,
                    "role": result["role"],
                    "metric_scope": metrics["metric_scope"],
                    "test_rows": metrics["test_rows"],
                    "accuracy": metrics["accuracy"],
                    "balanced_accuracy": metrics["balanced_accuracy"],
                    "precision": precision,
                    "recall": recall,
                    "f1_score": f1_value,
                    "false_positive_rate": false_positive_rate,
                    "median_total_ms": result["inference_time"][
                        "median_total_ms"
                    ],
                    "median_per_row_microseconds": result["inference_time"][
                        "median_per_row_microseconds"
                    ],
                }
            )


def evaluate_models(
    input_dir: Path,
    model_dir: Path,
    output_dir: Path,
    *,
    batch_size: int,
    warmup_runs: int,
    timing_runs: int,
    device_name: str,
    selection_tolerance: float,
) -> dict[str, Any]:
    input_dir = input_dir.resolve()
    model_dir = model_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir in {input_dir, model_dir}:
        raise ValueError("output directory must not replace input or model directory")
    if batch_size < 1:
        raise ValueError("batch size must be positive")
    if selection_tolerance < 0:
        raise ValueError("selection tolerance must be non-negative")

    input_paths = {
        name: input_dir / name
        for name in (
            "X_test.npy",
            "y_test.npy",
            "X_test_sequences.npy",
            "y_test_sequences.npy",
            "feature_names.json",
            "label_mapping.json",
            "preprocessing_manifest.json",
        )
    }
    model_paths = {
        **{
            name: model_dir / filename
            for name, filename in SUPERVISED_ARTIFACTS.items()
        },
        "isolation_forest": model_dir / ISOLATION_ARTIFACT,
        "lstm_classifier": model_dir / LSTM_ARTIFACT,
        "lstm_metrics": model_dir / LSTM_METRICS_ARTIFACT,
        "training_manifest": model_dir / TRAINING_MANIFEST_ARTIFACT,
    }
    missing = [
        str(path)
        for path in [*input_paths.values(), *model_paths.values()]
        if not path.is_file()
    ]
    if missing:
        raise FileNotFoundError("missing required artifacts: " + ", ".join(missing))

    protected_paths = {**input_paths, **model_paths}
    hashes_before = {
        name: _sha256_file(path) for name, path in protected_paths.items()
    }

    X_test = np.asarray(
        _load_array(input_paths["X_test.npy"]),
        dtype=np.float32,
    )
    y_test = np.asarray(
        _load_array(input_paths["y_test.npy"]),
        dtype=np.int64,
    )
    X_test_sequences = np.asarray(
        _load_array(input_paths["X_test_sequences.npy"]),
        dtype=np.float32,
    )
    y_test_sequences = np.asarray(
        _load_array(input_paths["y_test_sequences.npy"]),
        dtype=np.int64,
    )
    _validate_feature_array("X_test.npy", X_test, dimensions=2)
    _validate_feature_array(
        "X_test_sequences.npy",
        X_test_sequences,
        dimensions=3,
    )
    if X_test.shape[1] != X_test_sequences.shape[2]:
        raise ValueError("tabular and sequence feature counts differ")

    feature_names_value = _read_json(input_paths["feature_names.json"])
    if (
        not isinstance(feature_names_value, list)
        or len(feature_names_value) != X_test.shape[1]
    ):
        raise ValueError("feature_names.json does not match test arrays")
    feature_names = tuple(str(item) for item in feature_names_value)
    if any(not item for item in feature_names):
        raise ValueError("feature_names.json contains an empty feature name")

    label_mapping = _normalize_label_mapping(
        _read_json(input_paths["label_mapping.json"])
    )
    allowed_indexes = set(label_mapping.values())
    _validate_labels(
        "y_test.npy",
        y_test,
        rows=len(X_test),
        allowed_indexes=allowed_indexes,
    )
    _validate_labels(
        "y_test_sequences.npy",
        y_test_sequences,
        rows=len(X_test_sequences),
        allowed_indexes=allowed_indexes,
    )
    if Counter(map(int, y_test)) != Counter(map(int, y_test_sequences)):
        raise ValueError(
            "tabular and sequence test label counts must match; "
            "positional ordering is intentionally not required"
        )

    preprocessing_manifest = _read_json(
        input_paths["preprocessing_manifest.json"]
    )
    split = (
        preprocessing_manifest.get("split", {})
        if isinstance(preprocessing_manifest, Mapping)
        else {}
    )
    supported_split_strategies = {
        "chronological",
        "stratified_group_holdout",
    }
    if (
        split.get("strategy") not in supported_split_strategies
        or split.get("transform_fit_scope") != "training_rows_only"
        or split.get("test_rows") != len(X_test)
        or (
            split.get("strategy") == "stratified_group_holdout"
            and split.get("group_overlap") != 0
        )
    ):
        raise ValueError("preprocessing manifest has an unsafe test contract")

    training_manifest = _read_json(model_paths["training_manifest"])
    if not isinstance(training_manifest, Mapping):
        raise ValueError("training manifest must contain an object")
    training_safety = training_manifest.get("safety", {})
    if (
        training_safety.get("supervised_models_fitted_on_test_rows") is not False
        or training_safety.get("test_labels_used_for_model_fit") is not False
        or training_safety.get("isolation_forest_used_labels_as_features")
        is not False
    ):
        raise ValueError("training manifest does not satisfy evaluation safety")

    device = torch.device(device_name)
    if device.type == "cuda" and not torch.cuda.is_available():
        raise ValueError("CUDA was requested but is not available")

    supervised_estimators: dict[str, Any] = {}
    for name in SUPERVISED_ARTIFACTS:
        bundle = joblib.load(model_paths[name])
        supervised_estimators[name] = _require_classifier_bundle(
            name,
            bundle,
            feature_names=feature_names,
            label_mapping=label_mapping,
        )

    isolation_bundle = joblib.load(model_paths["isolation_forest"])
    isolation_estimator = _require_isolation_bundle(
        isolation_bundle,
        feature_names=feature_names,
        normal_index=label_mapping["normal"],
    )
    threshold_value = isolation_bundle.get("anomaly_score_threshold", 0.0)
    if isinstance(threshold_value, bool):
        raise ValueError("Isolation Forest anomaly threshold must be numeric")
    try:
        anomaly_score_threshold = float(threshold_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Isolation Forest anomaly threshold must be numeric"
        ) from exc
    if not np.isfinite(anomaly_score_threshold):
        raise ValueError("Isolation Forest anomaly threshold must be finite")

    lstm_model = _load_lstm(
        model_paths["lstm_classifier"],
        label_mapping=label_mapping,
        sequence_length=X_test_sequences.shape[1],
        input_features=X_test_sequences.shape[2],
        device=device,
    )
    lstm_metrics_saved = _read_json(model_paths["lstm_metrics"])
    if (
        not isinstance(lstm_metrics_saved, Mapping)
        or dict(lstm_metrics_saved.get("label_mapping", {}))
        != dict(label_mapping)
    ):
        raise ValueError("saved LSTM metrics do not match label mapping")

    model_results: dict[str, dict[str, Any]] = {}
    for name, estimator in supervised_estimators.items():
        predictions, timing = _benchmark(
            lambda estimator=estimator: np.asarray(
                estimator.predict(X_test),
                dtype=np.int64,
            ),
            rows=len(X_test),
            warmup_runs=warmup_runs,
            timing_runs=timing_runs,
        )
        model_results[name] = {
            "role": "known_attack_classification",
            "input_contract": {
                "shape": list(X_test.shape),
                "array": "X_test.npy",
                "labels": "y_test.npy",
            },
            "metrics": _multiclass_metrics(
                y_test,
                predictions.astype(np.int64),
                label_mapping,
            ),
            "inference_time": timing,
        }

    def predict_isolation() -> np.ndarray:
        anomaly_scores = -np.asarray(
            isolation_estimator.decision_function(X_test),
            dtype=np.float64,
        )
        return np.where(
            anomaly_scores >= anomaly_score_threshold,
            -1,
            1,
        ).astype(np.int8)

    isolation_predictions, isolation_timing = _benchmark(
        predict_isolation,
        rows=len(X_test),
        warmup_runs=warmup_runs,
        timing_runs=timing_runs,
    )
    isolation_scores = np.asarray(
        isolation_estimator.decision_function(X_test),
        dtype=np.float64,
    )
    if not np.isfinite(isolation_scores).all():
        raise RuntimeError("Isolation Forest produced non-finite scores")
    model_results["isolation_forest"] = {
        "role": "unknown_anomaly_detection",
        "input_contract": {
            "shape": list(X_test.shape),
            "array": "X_test.npy",
            "labels": (
                "binary evaluation view derived from y_test.npy; labels were "
                "not used to fit Isolation Forest"
            ),
        },
        "metrics": _anomaly_metrics(
            y_test,
            isolation_predictions.astype(np.int8),
            isolation_scores,
            normal_index=label_mapping["normal"],
            other_anomaly_index=label_mapping.get("other_anomaly"),
            anomaly_score_threshold=anomaly_score_threshold,
        ),
        "inference_time": isolation_timing,
    }

    sequence_tensor = torch.from_numpy(X_test_sequences).to(device)

    def predict_lstm() -> np.ndarray:
        batches: list[np.ndarray] = []
        with torch.inference_mode():
            for start in range(0, len(sequence_tensor), batch_size):
                logits = lstm_model(sequence_tensor[start : start + batch_size])
                batches.append(
                    torch.argmax(logits, dim=1)
                    .detach()
                    .cpu()
                    .numpy()
                    .astype(np.int64, copy=False)
                )
        return np.concatenate(batches)

    lstm_predictions, lstm_timing = _benchmark(
        predict_lstm,
        rows=len(X_test_sequences),
        warmup_runs=warmup_runs,
        timing_runs=timing_runs,
        synchronize=lambda: _synchronize(device),
    )
    model_results["lstm_classifier"] = {
        "role": "sequence_attack_classification",
        "input_contract": {
            "shape": list(X_test_sequences.shape),
            "array": "X_test_sequences.npy",
            "labels": "y_test_sequences.npy",
            "ordering": (
                "grouped causal sequence order; evaluated against sequence "
                "labels, not positional y_test.npy order"
            ),
            "batch_size": batch_size,
            "device": str(device),
        },
        "metrics": _multiclass_metrics(
            y_test_sequences,
            lstm_predictions.astype(np.int64),
            label_mapping,
        ),
        "inference_time": lstm_timing,
    }

    tabular_metrics = {
        name: model_results[name]["metrics"]
        for name in SUPERVISED_ARTIFACTS
    }
    tabular_selection = _select_tabular_classifier(
        tabular_metrics,
        tolerance=selection_tolerance,
    )
    validation_selection = training_manifest.get("validation_selection", {})
    if isinstance(validation_selection, Mapping):
        validation_selected_model = validation_selection.get("tabular_model")
        if validation_selected_model in SUPERVISED_ARTIFACTS:
            tabular_selection = {
                **tabular_selection,
                "selected_model": validation_selected_model,
                "decisive_criterion": "validation macro F1",
                "selection_scope": "validation_only",
                "validation_metrics": validation_selection.get(
                    "tabular_metrics",
                    {},
                ),
                "test_metrics_used_for_selection": False,
            }
    all_supervised_metrics = {
        name: model_results[name]["metrics"]
        for name in (
            "decision_tree",
            "random_forest",
            "lstm_classifier",
        )
    }
    supervised_leader = _select_supervised_metric_leader(
        all_supervised_metrics
    )
    selection = {
        "best_tabular_classifier": tabular_selection,
        "sequence_classifier": {
            "selected_model": "lstm_classifier",
            "reason": (
                "only evaluated model with the required causal sequence "
                "input contract"
            ),
        },
        "unknown_anomaly_detector": {
            "selected_model": "isolation_forest",
            "reason": (
                "only evaluated normal-only, label-free anomaly detector"
            ),
        },
        "supervised_metric_leader": {
            "model": supervised_leader,
            "metric": "macro F1 with balanced-accuracy and recall tie-breaks",
            "warning": (
                "The LSTM uses sequence inputs and must not silently replace "
                "the tabular classifier."
            ),
        },
        "step13_hybrid_roles": {
            "rules": "deterministic signatures and thresholds",
            "known_attack_classifier": tabular_selection["selected_model"],
            "unknown_anomaly_detector": "isolation_forest",
            "sequence_attack_classifier": "lstm_classifier",
        },
    }

    hashes_after = {
        name: _sha256_file(path) for name, path in protected_paths.items()
    }
    if hashes_after != hashes_before:
        changed = sorted(
            name
            for name in hashes_before
            if hashes_before[name] != hashes_after[name]
        )
        raise RuntimeError(
            "evaluation modified protected artifacts: " + ", ".join(changed)
        )

    report = {
        "evaluation_version": EVALUATION_VERSION,
        "generated_at_utc": datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "data_contract": {
            "split_strategy": split.get("strategy"),
            "chronological_split": split.get("strategy") == "chronological",
            "group_overlap": split.get("group_overlap"),
            "preprocessor_fit_scope": "training_rows_only",
            "tabular_test_rows": int(len(X_test)),
            "sequence_test_rows": int(len(X_test_sequences)),
            "encoded_features": int(X_test.shape[1]),
            "sequence_length": int(X_test_sequences.shape[1]),
            "classes": len(label_mapping),
            "label_mapping": dict(label_mapping),
            "test_label_counts": {
                label: int(np.count_nonzero(y_test == index))
                for label, index in sorted(
                    label_mapping.items(),
                    key=lambda item: item[1],
                )
            },
            "sequence_label_counts_preserved": True,
        },
        "model_results": model_results,
        "selection": selection,
        "dependencies": {
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
            "torch": str(torch.__version__),
        },
        "safety": {
            "models_retrained": False,
            "model_fit_called": False,
            "test_labels_used_only_for_evaluation": True,
            "protected_artifacts_modified": False,
            "split_contract_preserved": True,
            "chronological_split_preserved": (
                split.get("strategy") == "chronological"
            ),
            "sequence_labels_compared_by_position_to_tabular_labels": False,
            "inference_timing_excludes_artifact_loading": True,
            "single_holdout_results_prove_external_generalization": False,
        },
        "protected_artifact_hashes": hashes_before,
    }

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".step12-",
        dir=output_dir.parent,
    ) as temporary:
        staging = Path(temporary)
        _write_json(staging / "evaluation_report.json", report)
        _write_json(
            staging / "confusion_matrices.json",
            {
                name: result["metrics"]["confusion_matrix"]
                for name, result in model_results.items()
            },
        )
        _write_json(staging / "model_selection.json", selection)
        _write_summary_csv(
            staging / "evaluation_summary.csv",
            model_results,
        )
        output_files = (
            "evaluation_report.json",
            "evaluation_summary.csv",
            "confusion_matrices.json",
            "model_selection.json",
        )
        manifest = {
            "evaluation_version": EVALUATION_VERSION,
            "generated_at_utc": report["generated_at_utc"],
            "files": {
                filename: {
                    "sha256": _sha256_file(staging / filename),
                    "bytes": (staging / filename).stat().st_size,
                }
                for filename in output_files
            },
            "safety": report["safety"],
            "protected_artifacts_modified": False,
        }
        _write_json(staging / "evaluation_manifest.json", manifest)

        output_dir.mkdir(parents=True, exist_ok=True)
        for path in sorted(staging.iterdir()):
            os.replace(path, output_dir / path.name)

    return report


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate Step 12 traditional, anomaly, and LSTM IDS models "
            "without retraining."
        )
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("data/ml_ready"),
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path("data/ml_ready/models"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/ml_ready/evaluation"),
    )
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--warmup-runs", type=int, default=3)
    parser.add_argument("--timing-runs", type=int, default=30)
    parser.add_argument(
        "--device",
        choices=("cpu", "cuda"),
        default="cpu",
    )
    parser.add_argument(
        "--selection-tolerance",
        type=float,
        default=1e-12,
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    report = evaluate_models(
        args.input_dir,
        args.model_dir,
        args.output_dir,
        batch_size=args.batch_size,
        warmup_runs=args.warmup_runs,
        timing_runs=args.timing_runs,
        device_name=args.device,
        selection_tolerance=args.selection_tolerance,
    )

    print("[EVALUATION] Test rows:", report["data_contract"]["tabular_test_rows"])
    print("[EVALUATION] Features:", report["data_contract"]["encoded_features"])
    print("[EVALUATION] Classes:", report["data_contract"]["classes"])
    for name in (
        "decision_tree",
        "random_forest",
        "lstm_classifier",
    ):
        result = report["model_results"][name]
        metrics = result["metrics"]
        timing = result["inference_time"]
        print(
            f"[EVALUATION] {name}: "
            f"accuracy={metrics['accuracy']:.4f} "
            f"macro_f1={metrics['f1_macro']:.4f} "
            "normal_fpr="
            f"{metrics['false_positive_rate']['normal_as_attack']:.4f} "
            f"median_ms={timing['median_total_ms']:.4f}"
        )

    isolation = report["model_results"]["isolation_forest"]
    isolation_metrics = isolation["metrics"]
    print(
        "[EVALUATION] isolation_forest: "
        f"accuracy={isolation_metrics['accuracy']:.4f} "
        f"f1={isolation_metrics['f1_score']:.4f} "
        f"fpr={isolation_metrics['false_positive_rate']:.4f} "
        "median_ms="
        f"{isolation['inference_time']['median_total_ms']:.4f}"
    )
    print(
        "[EVALUATION] Best tabular classifier:",
        report["selection"]["best_tabular_classifier"]["selected_model"],
    )
    print(
        "[EVALUATION] Supervised metric leader:",
        report["selection"]["supervised_metric_leader"]["model"],
    )
    print("[EVALUATION] Output:", str(args.output_dir.resolve()))
    print("[EVALUATION] PASS: Models evaluated without retraining.")


if __name__ == "__main__":
    main()
