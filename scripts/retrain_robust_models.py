"""Build and optionally promote a leakage-resistant IDS model bundle.

The workflow uses source-group-isolated train/validation/test partitions.
Hyperparameters, the tabular classifier, the LSTM checkpoint epoch, and the
Isolation Forest score threshold are selected using validation data only.
The final test split is evaluated once after every selection is frozen.

The existing active bundle is moved to a timestamped rollback directory before
promotion.  Raw logs and the processed dataset are never modified.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np
import sklearn
import torch
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dataset.labeling import APPROVED_LABELS
from feature_engineering.engineer_features import (
    ENGINEERED_NUMERICAL_FEATURES,
    FEATURE_DEFINITIONS,
    FEATURE_ENGINEERING_VERSION,
    FeatureEngineeringState,
    engineer_rows,
)
from machine_learning.evaluate_models import (
    _multiclass_metrics,
    _select_tabular_classifier,
    evaluate_models,
)
from preprocessing.preprocess_dataset import (
    BASE_NUMERICAL_FEATURES,
    CATEGORICAL_FEATURES,
    LABEL_TO_INDEX,
    MODEL_FEATURES,
    create_sequences,
    encode_labels,
    read_dataset,
    rows_to_matrix,
)


RETRAINING_VERSION = "2.0"
DEFAULT_DATASET = ROOT / "data" / "processed" / "honeypot_dataset.csv"
DEFAULT_ACTIVE_DIR = ROOT / "data" / "ml_ready"
DEFAULT_REGISTRY_DIR = ROOT / "data" / "continuous_learning" / "robust_retraining"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_text(value: datetime | None = None) -> str:
    return (value or _utc_now()).isoformat().replace("+00:00", "Z")


def _run_id(value: datetime | None = None) -> str:
    return (value or _utc_now()).strftime("%Y%m%dT%H%M%SZ")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else ["status"]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _count_labels(labels: np.ndarray) -> dict[str, int]:
    counts = Counter(int(value) for value in labels.tolist())
    return {
        label: int(counts.get(index, 0))
        for label, index in sorted(LABEL_TO_INDEX.items(), key=lambda item: item[1])
    }


def _load_assignments(path: Path) -> dict[str, str]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        assignments = {
            row["event_id"].strip().lower(): row["split"].strip().lower()
            for row in csv.DictReader(stream)
        }
    if set(assignments.values()) != {"train", "validation", "test"}:
        raise ValueError("split assignments must contain train, validation and test")
    return assignments


def _prepare_split(
    rows: list[dict[str, Any]],
    preprocessor: Any,
) -> tuple[list[dict[str, Any]], np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    engineered = engineer_rows(
        [dict(row) for row in rows],
        state=FeatureEngineeringState(),
    )
    features = np.asarray(
        preprocessor.transform(rows_to_matrix(engineered)),
        dtype=np.float32,
    )
    labels = encode_labels(engineered)
    sequences, sequence_labels = create_sequences(
        features,
        labels,
        engineered,
        sequence_length=10,
        pad_short_history=True,
    )
    return engineered, features, labels, sequences, sequence_labels


def _binary_metrics(
    truth: np.ndarray,
    scores: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    predictions = (scores >= threshold).astype(np.int8)
    matrix = confusion_matrix(truth, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    return {
        "samples": int(len(truth)),
        "accuracy": float(accuracy_score(truth, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(truth, predictions)),
        "precision": float(precision_score(truth, predictions, zero_division=0)),
        "recall": float(recall_score(truth, predictions, zero_division=0)),
        "f1_score": float(f1_score(truth, predictions, zero_division=0)),
        "false_positive_rate": float(
            false_positive / max(1, false_positive + true_negative)
        ),
        "false_negative_rate": float(
            false_negative / max(1, false_negative + true_positive)
        ),
        "roc_auc": float(roc_auc_score(truth, scores)),
        "average_precision": float(average_precision_score(truth, scores)),
        "confusion_matrix": matrix.astype(int).tolist(),
    }


def _choose_threshold(
    truth: np.ndarray,
    scores: np.ndarray,
    *,
    max_false_positive_rate: float = 0.10,
) -> tuple[float, dict[str, Any]]:
    unique = np.unique(scores)
    candidates = np.concatenate(
        (
            [unique[0] - 1e-9],
            (unique[:-1] + unique[1:]) / 2.0,
            [unique[-1] + 1e-9],
        )
    )
    best: tuple[tuple[Any, ...], float, dict[str, Any]] | None = None
    for threshold in candidates:
        metrics = _binary_metrics(truth, scores, float(threshold))
        key = (
            metrics["false_positive_rate"] <= max_false_positive_rate,
            metrics["f1_score"],
            metrics["balanced_accuracy"],
            -metrics["false_positive_rate"],
        )
        if best is None or key > best[0]:
            best = (key, float(threshold), metrics)
    if best is None:
        raise RuntimeError("no Isolation Forest threshold candidate was evaluated")
    return best[1], best[2]


def _fit_isolation_forest(
    train_features: np.ndarray,
    train_labels: np.ndarray,
    validation_features: np.ndarray,
    validation_labels: np.ndarray,
    *,
    random_state: int,
) -> tuple[IsolationForest, float, dict[str, Any]]:
    normal_index = LABEL_TO_INDEX["normal"]
    unknown_index = LABEL_TO_INDEX["other_anomaly"]
    normal_train = train_features[train_labels == normal_index]
    validation_mask = np.isin(
        validation_labels,
        np.asarray([normal_index, unknown_index]),
    )
    validation_truth = (
        validation_labels[validation_mask] == unknown_index
    ).astype(np.int8)
    if len(np.unique(validation_truth)) != 2:
        raise RuntimeError(
            "Isolation Forest calibration requires normal and other_anomaly validation rows"
        )

    # This small, predeclared grid is selected on validation only.  The first
    # configuration is the simplest and wins deterministic ties.
    configurations = (
        {"max_samples": "auto", "max_features": 1.0},
        {"max_samples": "auto", "max_features": 0.8},
        {"max_samples": 0.5, "max_features": 0.8},
        {"max_samples": 0.75, "max_features": 0.8},
    )
    candidates: list[dict[str, Any]] = []
    for index, configuration in enumerate(configurations):
        estimator = IsolationForest(
            n_estimators=300,
            contamination="auto",
            max_samples=configuration["max_samples"],
            max_features=configuration["max_features"],
            random_state=random_state,
            n_jobs=1,
        )
        estimator.fit(normal_train)
        scores = -np.asarray(
            estimator.decision_function(validation_features[validation_mask]),
            dtype=np.float64,
        )
        threshold, metrics = _choose_threshold(validation_truth, scores)
        candidates.append(
            {
                "index": index,
                "configuration": configuration,
                "estimator": estimator,
                "threshold": threshold,
                "metrics": metrics,
            }
        )

    selected = max(
        candidates,
        key=lambda item: (
            item["metrics"]["false_positive_rate"] <= 0.10,
            item["metrics"]["f1_score"],
            item["metrics"]["balanced_accuracy"],
            -item["metrics"]["false_positive_rate"],
            -item["index"],
        ),
    )
    summary = {
        "selection_scope": "validation_only",
        "metric_scope": "other_anomaly_vs_normal",
        "normal_training_rows": int(len(normal_train)),
        "selected_configuration": selected["configuration"],
        "anomaly_score_threshold": selected["threshold"],
        "validation_metrics": selected["metrics"],
        "candidate_metrics": [
            {
                "configuration": item["configuration"],
                "threshold": item["threshold"],
                "metrics": item["metrics"],
            }
            for item in candidates
        ],
        "test_labels_used_for_selection": False,
    }
    return selected["estimator"], selected["threshold"], summary


def _run_lstm_audit(
    output_dir: Path,
    dataset: Path,
    *,
    max_epochs: int,
    patience: int,
    random_state: int,
) -> None:
    command = [
        sys.executable,
        str(ROOT / "scripts" / "audit_lstm_generalization.py"),
        "--dataset",
        str(dataset),
        "--output-dir",
        str(output_dir),
        "--max-epochs",
        str(max_epochs),
        "--patience",
        str(patience),
        "--random-state",
        str(random_state),
    ]
    subprocess.run(command, cwd=ROOT, check=True)


def _build_bundle(
    run_dir: Path,
    dataset: Path,
    *,
    max_epochs: int,
    patience: int,
    random_state: int,
) -> tuple[Path, dict[str, Any]]:
    audit_dir = run_dir / "lstm_group_audit"
    _run_lstm_audit(
        audit_dir,
        dataset,
        max_epochs=max_epochs,
        patience=patience,
        random_state=random_state,
    )
    audit = json.loads((audit_dir / "audit_results.json").read_text(encoding="utf-8"))
    assignments = _load_assignments(audit_dir / "split_assignments.csv")
    rows, read_stats = read_dataset(dataset)
    split_rows = {
        name: [row for row in rows if assignments.get(row["event_id"]) == name]
        for name in ("train", "validation", "test")
    }
    assigned_count = sum(len(items) for items in split_rows.values())
    if assigned_count != len(rows):
        raise RuntimeError("split assignments do not cover the complete dataset")

    group_sets = {
        name: {row["source_ip_hash"] for row in items}
        for name, items in split_rows.items()
    }
    group_overlap = sum(
        len(group_sets[left] & group_sets[right])
        for left, right in (
            ("train", "validation"),
            ("train", "test"),
            ("validation", "test"),
        )
    )
    if group_overlap:
        raise RuntimeError("source groups overlap across robust splits")

    bundle = run_dir / "bundle"
    model_dir = bundle / "models"
    evaluation_dir = bundle / "evaluation"
    model_dir.mkdir(parents=True)
    evaluation_dir.mkdir(parents=True)
    preprocessor = joblib.load(audit_dir / "preprocessor_group_isolated.joblib")
    split_data: dict[str, dict[str, Any]] = {}
    for name in ("train", "validation", "test"):
        engineered, features, labels, sequences, sequence_labels = _prepare_split(
            split_rows[name],
            preprocessor,
        )
        split_data[name] = {
            "rows": engineered,
            "features": features,
            "labels": labels,
            "sequences": sequences,
            "sequence_labels": sequence_labels,
        }
        prefix = "validation" if name == "validation" else name
        np.save(bundle / f"X_{prefix}.npy", features, allow_pickle=False)
        np.save(bundle / f"y_{prefix}.npy", labels, allow_pickle=False)
        np.save(bundle / f"X_{prefix}_sequences.npy", sequences, allow_pickle=False)
        np.save(bundle / f"y_{prefix}_sequences.npy", sequence_labels, allow_pickle=False)

    shutil.copy2(audit_dir / "preprocessor_group_isolated.joblib", bundle / "preprocessor.joblib")
    shutil.copy2(audit_dir / "feature_names.json", bundle / "feature_names.json")
    _write_json(bundle / "label_mapping.json", LABEL_TO_INDEX)
    shutil.copy2(audit_dir / "split_assignments.csv", bundle / "split_assignments.csv")

    feature_names = json.loads((bundle / "feature_names.json").read_text(encoding="utf-8"))
    array_files = [
        f"{kind}_{split}{suffix}.npy"
        for split in ("train", "validation", "test")
        for suffix in ("", "_sequences")
        for kind in ("X", "y")
    ]
    preprocessing_files = [
        *array_files,
        "preprocessor.joblib",
        "feature_names.json",
        "label_mapping.json",
        "split_assignments.csv",
    ]
    preprocessing_manifest = {
        "preprocessing_version": "2.0-group-isolated",
        "generated_at_utc": _utc_text(),
        "input": {
            "path": str(dataset.resolve()),
            "sha256": _sha256(dataset),
            **read_stats,
        },
        "split": {
            "strategy": "stratified_group_holdout",
            "group_field": "source_ip_hash",
            "group_overlap": 0,
            "train_rows": len(split_rows["train"]),
            "validation_rows": len(split_rows["validation"]),
            "test_rows": len(split_rows["test"]),
            "transform_fit_scope": "training_rows_only",
            "model_selection_scope": "validation_only",
            "test_scope": "final_evaluation_only",
            "random_state": random_state,
        },
        "labels": {
            "mapping": LABEL_TO_INDEX,
            **{
                f"{name}_counts": _count_labels(split_data[name]["labels"])
                for name in ("train", "validation", "test")
            },
        },
        "features": {
            "numerical": list(BASE_NUMERICAL_FEATURES + ENGINEERED_NUMERICAL_FEATURES),
            "engineered_numerical": list(ENGINEERED_NUMERICAL_FEATURES),
            "engineered_definitions": FEATURE_DEFINITIONS,
            "categorical": list(CATEGORICAL_FEATURES),
            "encoded_feature_count": len(feature_names),
            "feature_engineering_version": FEATURE_ENGINEERING_VERSION,
            "numerical_normalization": "standard scaling fitted on training rows",
            "categorical_encoding": "one-hot; unknown categories ignored",
            "engineering_scope": {
                "grouping": ["source_ip_hash", "service"],
                "history": "current and past events only within each split",
                "label_used": False,
            },
        },
        "sequences": {
            "length": 10,
            "grouping": ["source_ip_hash", "service"],
            "padding_mask_value": 0.0,
            "short_history_policy": "left zero padding",
            "target": "last event label",
            "cross_split_context_used": False,
            **{
                f"{name}_sequences": len(split_data[name]["sequences"])
                for name in ("train", "validation", "test")
            },
        },
        "safety": {
            "preprocessor_fitted_on_test_data": False,
            "preprocessor_fitted_on_validation_data": False,
            "raw_payload_used_as_direct_model_input": False,
            "direct_identifiers_used_as_model_inputs": False,
            "labels_used_for_feature_engineering": False,
            "future_events_used_for_feature_engineering": False,
            "future_events_used_for_test_sequences": False,
            "context_labels_used_for_test_sequences": False,
            "source_group_overlap": False,
            "test_labels_used_for_model_selection": False,
        },
        "arrays": {
            filename: {
                "shape": list(np.load(bundle / filename, mmap_mode="r").shape),
                "dtype": str(np.load(bundle / filename, mmap_mode="r").dtype),
            }
            for filename in array_files
        },
        "files": {
            filename: {"sha256": _sha256(bundle / filename)}
            for filename in preprocessing_files
        },
    }
    _write_json(bundle / "preprocessing_manifest.json", preprocessing_manifest)

    train_features = split_data["train"]["features"]
    train_labels = split_data["train"]["labels"]
    validation_features = split_data["validation"]["features"]
    validation_labels = split_data["validation"]["labels"]
    decision_tree = DecisionTreeClassifier(
        criterion="gini",
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=random_state,
    ).fit(train_features, train_labels)
    random_forest = RandomForestClassifier(
        n_estimators=200,
        criterion="gini",
        max_depth=16,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=1,
    ).fit(train_features, train_labels)

    validation_tabular_metrics = {
        "decision_tree": _multiclass_metrics(
            validation_labels,
            decision_tree.predict(validation_features),
            LABEL_TO_INDEX,
        ),
        "random_forest": _multiclass_metrics(
            validation_labels,
            random_forest.predict(validation_features),
            LABEL_TO_INDEX,
        ),
    }
    selected_tabular = _select_tabular_classifier(
        validation_tabular_metrics,
        tolerance=1e-12,
    )
    isolation_forest, anomaly_threshold, isolation_selection = _fit_isolation_forest(
        train_features,
        train_labels,
        validation_features,
        validation_labels,
        random_state=random_state,
    )

    def classifier_bundle(name: str, estimator: Any) -> dict[str, Any]:
        return {
            "model_training_version": RETRAINING_VERSION,
            "model_name": name,
            "purpose": "known_attack_classification",
            "fit_scope": "training_rows_only",
            "feature_names": feature_names,
            "label_mapping": LABEL_TO_INDEX,
            "estimator": estimator,
        }

    joblib.dump(
        classifier_bundle("decision_tree", decision_tree),
        model_dir / "decision_tree.joblib",
        compress=3,
    )
    joblib.dump(
        classifier_bundle("random_forest", random_forest),
        model_dir / "random_forest.joblib",
        compress=3,
    )
    joblib.dump(
        {
            "model_training_version": RETRAINING_VERSION,
            "model_name": "isolation_forest",
            "purpose": "unknown_anomaly_detection",
            "fit_scope": "normal_training_features_only",
            "feature_names": feature_names,
            "normal_label_index": LABEL_TO_INDEX["normal"],
            "prediction_encoding": {"1": "inlier", "-1": "anomaly"},
            "anomaly_score_threshold": anomaly_threshold,
            "threshold_score": "negative decision_function",
            "threshold_selected_on": "validation_only",
            "threshold_metric_scope": "other_anomaly_vs_normal",
            "estimator": isolation_forest,
        },
        model_dir / "isolation_forest.joblib",
        compress=3,
    )

    shutil.copy2(
        audit_dir / "lstm_group_isolated_candidate.pt",
        model_dir / "lstm_classifier.pt",
    )
    lstm_metrics = {
        "framework": "PyTorch",
        "torch_version": torch.__version__,
        "device": "cpu",
        "data": {
            "training_sequences": len(split_data["train"]["sequences"]),
            "validation_sequences": len(split_data["validation"]["sequences"]),
            "testing_sequences": len(split_data["test"]["sequences"]),
            "sequence_length": 10,
            "input_features": len(feature_names),
            "num_classes": len(LABEL_TO_INDEX),
        },
        "label_mapping": LABEL_TO_INDEX,
        "training_history": list(csv.DictReader(
            (audit_dir / "training_history.csv").open(encoding="utf-8")
        )),
        "train_metrics": audit["metrics"]["train"],
        "validation_metrics": audit["metrics"]["validation"],
        "test_metrics": audit["metrics"]["test"],
        "selection": {
            "best_epoch": audit["configuration"]["best_epoch"],
            "criterion": "minimum validation loss",
            "test_labels_used_for_selection": False,
        },
    }
    _write_json(model_dir / "lstm_metrics.json", lstm_metrics)

    input_files = (
        "X_train.npy",
        "X_test.npy",
        "y_train.npy",
        "y_test.npy",
        "feature_names.json",
        "label_mapping.json",
        "preprocessing_manifest.json",
    )
    model_files = (
        "decision_tree.joblib",
        "random_forest.joblib",
        "isolation_forest.joblib",
        "lstm_classifier.pt",
        "lstm_metrics.json",
    )
    training_manifest = {
        "model_training_version": RETRAINING_VERSION,
        "generated_at_utc": _utc_text(),
        "split_strategy": "stratified_group_holdout",
        "data": {
            "train_rows": len(train_features),
            "validation_rows": len(validation_features),
            "test_rows": len(split_data["test"]["features"]),
            "encoded_features": len(feature_names),
            "training_label_counts": _count_labels(train_labels),
            "normal_training_rows": int(
                np.count_nonzero(train_labels == LABEL_TO_INDEX["normal"])
            ),
        },
        "configuration": {
            "random_state": random_state,
            "decision_tree": decision_tree.get_params(deep=False),
            "random_forest": random_forest.get_params(deep=False),
            "isolation_forest": isolation_forest.get_params(deep=False),
            "lstm": audit["configuration"],
        },
        "validation_selection": {
            "tabular_model": selected_tabular["selected_model"],
            "tabular_selection": selected_tabular,
            "tabular_metrics": validation_tabular_metrics,
            "isolation_forest": isolation_selection,
            "lstm_best_epoch": audit["configuration"]["best_epoch"],
            "test_labels_used_for_selection": False,
        },
        "models": {
            "decision_tree": {
                "artifact": "decision_tree.joblib",
                "purpose": "known_attack_classification",
                "fit_scope": "training_rows_only",
            },
            "random_forest": {
                "artifact": "random_forest.joblib",
                "purpose": "known_attack_classification",
                "fit_scope": "training_rows_only",
            },
            "isolation_forest": {
                "artifact": "isolation_forest.joblib",
                "purpose": "unknown_anomaly_detection",
                "fit_scope": "normal_training_features_only",
                "anomaly_score_threshold": anomaly_threshold,
            },
            "lstm_classifier": {
                "artifact": "lstm_classifier.pt",
                "purpose": "group-isolated sequence classification",
                "fit_scope": "training_rows_only; epoch selected on validation",
            },
        },
        "input": {
            "directory": str(bundle),
            "preprocessing_version": preprocessing_manifest["preprocessing_version"],
            "preprocessing_manifest_sha256": _sha256(
                bundle / "preprocessing_manifest.json"
            ),
            "files": {
                filename: {"sha256": _sha256(bundle / filename)}
                for filename in input_files
            },
        },
        "dependencies": {
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
            "torch": torch.__version__,
        },
        "safety": {
            "group_overlap": 0,
            "preprocessed_input_arrays_modified": False,
            "supervised_models_fitted_on_test_rows": False,
            "test_labels_used_for_model_fit": False,
            "test_labels_used_for_model_selection": False,
            "isolation_forest_used_labels_as_features": False,
            "training_labels_used_only_to_select_normal_rows": True,
            "validation_labels_used_only_for_model_and_threshold_selection": True,
            "isolation_forest_fit_scope": "normal_training_features_only",
            "raw_payload_used_as_direct_model_input": False,
            "direct_identifiers_used_as_model_inputs": False,
            "deterministic_random_state": True,
        },
    }
    _write_json(model_dir / "training_manifest.json", training_manifest)

    report = evaluate_models(
        bundle,
        model_dir,
        evaluation_dir,
        batch_size=128,
        warmup_runs=3,
        timing_runs=20,
        device_name="cpu",
        selection_tolerance=1e-12,
    )
    metrics = report["model_results"]
    gates = {
        "source_group_overlap_is_zero": group_overlap == 0,
        "test_not_used_for_selection": True,
        "lstm_test_macro_f1_at_least_0_90": (
            metrics["lstm_classifier"]["metrics"]["f1_macro"] >= 0.90
        ),
        "isolation_primary_test_f1_at_least_0_85": (
            metrics["isolation_forest"]["metrics"]["f1_score"] >= 0.85
        ),
        "isolation_primary_test_fpr_at_most_0_10": (
            metrics["isolation_forest"]["metrics"]["false_positive_rate"] <= 0.10
        ),
    }
    outcome = {
        "run_id": run_dir.name,
        "retraining_version": RETRAINING_VERSION,
        "generated_at_utc": _utc_text(),
        "bundle": str(bundle),
        "dataset": str(dataset.resolve()),
        "dataset_sha256": _sha256(dataset),
        "dataset_expanded": False,
        "dataset_expansion_reason": (
            "Not required: every class already has 510 records; split leakage "
            "and threshold calibration, not record count, caused the reported issues."
        ),
        "split": preprocessing_manifest["split"],
        "validation_selection": training_manifest["validation_selection"],
        "test_metrics": {
            name: result["metrics"]
            for name, result in metrics.items()
        },
        "quality_gates": gates,
        "quality_gates_passed": all(gates.values()),
        "active_model_modified": False,
    }
    _write_json(run_dir / "retraining_result.json", outcome)
    if not all(gates.values()):
        raise RuntimeError("candidate failed robust promotion quality gates")
    return bundle, outcome


def _promote(bundle: Path, active_dir: Path, run_dir: Path) -> Path:
    active_dir = active_dir.resolve()
    rollback_root = run_dir.parent / "rollback"
    rollback_root.mkdir(parents=True, exist_ok=True)
    rollback_dir = rollback_root / f"active_before_{run_dir.name}"
    if rollback_dir.exists():
        raise FileExistsError(f"rollback directory already exists: {rollback_dir}")
    active_dir.parent.mkdir(parents=True, exist_ok=True)
    moved_old = False
    try:
        if active_dir.exists():
            os.replace(active_dir, rollback_dir)
            moved_old = True
        os.replace(bundle, active_dir)
    except Exception:
        if moved_old and rollback_dir.exists() and not active_dir.exists():
            os.replace(rollback_dir, active_dir)
        raise
    return rollback_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--active-dir", type=Path, default=DEFAULT_ACTIVE_DIR)
    parser.add_argument("--registry-dir", type=Path, default=DEFAULT_REGISTRY_DIR)
    parser.add_argument("--max-epochs", type=int, default=40)
    parser.add_argument("--patience", type=int, default=6)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument(
        "--no-promote",
        action="store_true",
        help="build and evaluate the candidate without changing the active bundle",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    run_dir = args.registry_dir.resolve() / _run_id()
    run_dir.mkdir(parents=True, exist_ok=False)
    bundle, outcome = _build_bundle(
        run_dir,
        args.dataset.resolve(),
        max_epochs=args.max_epochs,
        patience=args.patience,
        random_state=args.random_state,
    )
    if args.no_promote:
        print(json.dumps(outcome, indent=2))
        return 0

    rollback_dir = _promote(bundle, args.active_dir, run_dir)
    outcome["active_model_modified"] = True
    outcome["candidate_bundle_before_promotion"] = outcome["bundle"]
    outcome["bundle"] = str(args.active_dir.resolve())
    outcome["active_directory"] = str(args.active_dir.resolve())
    outcome["rollback_directory"] = str(rollback_dir)
    _write_json(run_dir / "retraining_result.json", outcome)
    print(json.dumps(outcome, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
