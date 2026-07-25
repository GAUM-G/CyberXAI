"""Train deterministic traditional IDS models from Step 8 ML-ready arrays."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier


MODEL_TRAINING_VERSION = "1.0"

REQUIRED_INPUT_FILES = (
    "X_train.npy",
    "X_test.npy",
    "y_train.npy",
    "y_test.npy",
    "feature_names.json",
    "label_mapping.json",
    "preprocessing_manifest.json",
)

MODEL_ARTIFACT_FILES = (
    "decision_tree.joblib",
    "random_forest.joblib",
    "isolation_forest.joblib",
)

REQUIRED_SAFE_PREPROCESSING_FLAGS = (
    "preprocessor_fitted_on_test_data",
    "raw_payload_used_as_direct_model_input",
    "direct_identifiers_used_as_model_inputs",
    "labels_used_for_feature_engineering",
    "future_events_used_for_feature_engineering",
)


@dataclass(frozen=True)
class MLReadyArtifacts:
    """Validated Step 8 arrays and metadata used for Step 10."""

    input_dir: Path
    X_train: np.ndarray
    X_test: np.ndarray
    y_train: np.ndarray
    y_test: np.ndarray
    feature_names: tuple[str, ...]
    label_mapping: dict[str, int]
    preprocessing_manifest: dict[str, Any]
    input_hashes: dict[str, str]


@dataclass(frozen=True)
class TrainingResult:
    """Fitted models and their label-free test predictions."""

    decision_tree: DecisionTreeClassifier
    random_forest: RandomForestClassifier
    isolation_forest: IsolationForest
    decision_tree_predictions: np.ndarray
    random_forest_predictions: np.ndarray
    isolation_forest_predictions: np.ndarray
    isolation_forest_scores: np.ndarray
    normal_training_rows: int


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
        raise ValueError(f"could not read valid JSON from {path.name}") from exc


def _write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def _load_array(path: Path) -> np.ndarray:
    try:
        return np.load(path, allow_pickle=False)
    except (OSError, ValueError) as exc:
        raise ValueError(f"could not load safe NumPy array from {path.name}") from exc


def _normalize_label_mapping(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("label_mapping.json must contain a non-empty object")

    mapping: dict[str, int] = {}
    for raw_label, raw_index in value.items():
        label = str(raw_label).strip().lower()
        if not label:
            raise ValueError("label mapping contains an empty label")
        if isinstance(raw_index, bool) or not isinstance(raw_index, int):
            raise ValueError("label mapping indexes must be integers")
        if raw_index < 0:
            raise ValueError("label mapping indexes must be non-negative")
        if label in mapping:
            raise ValueError(f"duplicate normalized label: {label}")
        mapping[label] = raw_index

    indexes = list(mapping.values())
    if len(indexes) != len(set(indexes)):
        raise ValueError("label mapping indexes must be unique")
    if "normal" not in mapping:
        raise ValueError("label mapping must include the normal class")
    return mapping


def _validate_feature_array(name: str, value: np.ndarray) -> None:
    if value.ndim != 2:
        raise ValueError(f"{name} must be a two-dimensional array")
    if value.shape[0] < 1 or value.shape[1] < 1:
        raise ValueError(f"{name} must contain rows and features")
    if not np.issubdtype(value.dtype, np.number):
        raise ValueError(f"{name} must contain numeric values")
    if not np.isfinite(value).all():
        raise ValueError(f"{name} contains non-finite values")


def _validate_label_array(
    name: str,
    value: np.ndarray,
    *,
    allowed_indexes: set[int],
) -> None:
    if value.ndim != 1:
        raise ValueError(f"{name} must be a one-dimensional array")
    if value.shape[0] < 1:
        raise ValueError(f"{name} must not be empty")
    if not np.issubdtype(value.dtype, np.integer):
        raise ValueError(f"{name} must contain integer label indexes")
    unknown = sorted(set(int(item) for item in value.tolist()) - allowed_indexes)
    if unknown:
        raise ValueError(f"{name} contains unknown label indexes: {unknown}")


def _require_manifest_shape(
    manifest: Mapping[str, Any],
    filename: str,
    actual_shape: Sequence[int],
) -> None:
    arrays = manifest.get("arrays")
    if not isinstance(arrays, Mapping):
        raise ValueError("preprocessing manifest is missing arrays metadata")
    metadata = arrays.get(filename)
    if not isinstance(metadata, Mapping):
        raise ValueError(f"preprocessing manifest is missing {filename} metadata")
    recorded = metadata.get("shape")
    recorded_shape = list(recorded) if isinstance(recorded, list) else None
    if recorded_shape != list(actual_shape):
        raise ValueError(f"{filename} shape does not match preprocessing manifest")


def _validate_preprocessing_manifest(
    manifest: Mapping[str, Any],
    *,
    input_dir: Path,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    feature_names: Sequence[str],
    label_mapping: Mapping[str, int],
) -> None:
    split = manifest.get("split")
    features = manifest.get("features")
    labels = manifest.get("labels")
    safety = manifest.get("safety")
    files = manifest.get("files")

    if not isinstance(split, Mapping):
        raise ValueError("preprocessing manifest is missing split metadata")
    if split.get("strategy") != "chronological":
        raise ValueError("Step 10 requires a chronological train/test split")
    if split.get("transform_fit_scope") != "training_rows_only":
        raise ValueError("preprocessor must be fitted on training rows only")
    if split.get("train_rows") != len(X_train):
        raise ValueError("training row count does not match preprocessing manifest")
    if split.get("test_rows") != len(X_test):
        raise ValueError("test row count does not match preprocessing manifest")

    if not isinstance(features, Mapping):
        raise ValueError("preprocessing manifest is missing feature metadata")
    if features.get("encoded_feature_count") != len(feature_names):
        raise ValueError("encoded feature count does not match feature_names.json")
    engineering_scope = features.get("engineering_scope")
    if not isinstance(engineering_scope, Mapping):
        raise ValueError("Step 8 feature-engineering metadata is required")
    if engineering_scope.get("history") != "current and past events only":
        raise ValueError("feature engineering must use only current and past events")
    if engineering_scope.get("label_used") is not False:
        raise ValueError("labels must not be used for feature engineering")

    if not isinstance(labels, Mapping):
        raise ValueError("preprocessing manifest is missing label metadata")
    manifest_mapping = _normalize_label_mapping(labels.get("mapping"))
    if manifest_mapping != dict(label_mapping):
        raise ValueError("label mapping does not match preprocessing manifest")

    if not isinstance(safety, Mapping):
        raise ValueError("preprocessing manifest is missing safety metadata")
    for flag in REQUIRED_SAFE_PREPROCESSING_FLAGS:
        if safety.get(flag) is not False:
            raise ValueError(f"unsafe or missing preprocessing safety flag: {flag}")

    if not isinstance(files, Mapping):
        raise ValueError("preprocessing manifest is missing file hashes")
    for filename in REQUIRED_INPUT_FILES:
        if filename == "preprocessing_manifest.json":
            continue
        metadata = files.get(filename)
        if not isinstance(metadata, Mapping) or not metadata.get("sha256"):
            raise ValueError(f"preprocessing manifest is missing hash for {filename}")
        actual_hash = _sha256_file(input_dir / filename)
        if actual_hash != str(metadata["sha256"]).lower():
            raise ValueError(f"{filename} hash does not match preprocessing manifest")

    _require_manifest_shape(manifest, "X_train.npy", X_train.shape)
    _require_manifest_shape(manifest, "X_test.npy", X_test.shape)
    _require_manifest_shape(manifest, "y_train.npy", y_train.shape)
    _require_manifest_shape(manifest, "y_test.npy", y_test.shape)


def load_ml_ready_artifacts(input_dir: Path) -> MLReadyArtifacts:
    """Load and strictly validate the leakage-safe Step 8 artifacts."""

    input_dir = input_dir.resolve()
    missing = [
        filename
        for filename in REQUIRED_INPUT_FILES
        if not (input_dir / filename).is_file()
    ]
    if missing:
        raise FileNotFoundError(
            "missing Step 8 ML-ready artifacts: " + ", ".join(missing)
        )

    X_train = _load_array(input_dir / "X_train.npy")
    X_test = _load_array(input_dir / "X_test.npy")
    y_train = _load_array(input_dir / "y_train.npy")
    y_test = _load_array(input_dir / "y_test.npy")
    _validate_feature_array("X_train.npy", X_train)
    _validate_feature_array("X_test.npy", X_test)

    if X_train.shape[1] != X_test.shape[1]:
        raise ValueError("training and test arrays must have the same feature count")
    if len(X_train) != len(y_train):
        raise ValueError("X_train.npy and y_train.npy row counts differ")
    if len(X_test) != len(y_test):
        raise ValueError("X_test.npy and y_test.npy row counts differ")

    feature_names_value = _read_json(input_dir / "feature_names.json")
    if not isinstance(feature_names_value, list):
        raise ValueError("feature_names.json must contain a list")
    feature_names = tuple(str(item).strip() for item in feature_names_value)
    if any(not item for item in feature_names):
        raise ValueError("feature_names.json contains an empty feature name")
    if len(feature_names) != len(set(feature_names)):
        raise ValueError("feature_names.json contains duplicate names")
    if len(feature_names) != X_train.shape[1]:
        raise ValueError("feature_names.json does not match encoded feature count")

    label_mapping = _normalize_label_mapping(
        _read_json(input_dir / "label_mapping.json")
    )
    allowed_indexes = set(label_mapping.values())
    _validate_label_array(
        "y_train.npy",
        y_train,
        allowed_indexes=allowed_indexes,
    )
    _validate_label_array(
        "y_test.npy",
        y_test,
        allowed_indexes=allowed_indexes,
    )
    if len(np.unique(y_train)) < 2:
        raise ValueError("supervised training requires at least two label classes")

    normal_index = label_mapping["normal"]
    if int(np.count_nonzero(y_train == normal_index)) < 2:
        raise ValueError(
            "Isolation Forest requires at least two normal training rows"
        )

    preprocessing_manifest_value = _read_json(
        input_dir / "preprocessing_manifest.json"
    )
    if not isinstance(preprocessing_manifest_value, Mapping):
        raise ValueError("preprocessing_manifest.json must contain an object")
    preprocessing_manifest = dict(preprocessing_manifest_value)
    _validate_preprocessing_manifest(
        preprocessing_manifest,
        input_dir=input_dir,
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        feature_names=feature_names,
        label_mapping=label_mapping,
    )

    input_hashes = {
        filename: _sha256_file(input_dir / filename)
        for filename in REQUIRED_INPUT_FILES
    }
    return MLReadyArtifacts(
        input_dir=input_dir,
        X_train=np.asarray(X_train, dtype=np.float32),
        X_test=np.asarray(X_test, dtype=np.float32),
        y_train=np.asarray(y_train, dtype=np.int64),
        y_test=np.asarray(y_test, dtype=np.int64),
        feature_names=feature_names,
        label_mapping=label_mapping,
        preprocessing_manifest=preprocessing_manifest,
        input_hashes=input_hashes,
    )


def fit_traditional_models(
    artifacts: MLReadyArtifacts,
    *,
    random_state: int = 42,
    forest_trees: int = 200,
    isolation_trees: int = 200,
    isolation_contamination: float = 0.05,
    tree_max_depth: int = 12,
    forest_max_depth: int = 16,
) -> TrainingResult:
    """Fit known-attack classifiers and a normal-only anomaly detector."""

    if forest_trees < 1 or isolation_trees < 1:
        raise ValueError("tree counts must be at least 1")
    if tree_max_depth < 1 or forest_max_depth < 1:
        raise ValueError("maximum depths must be at least 1")
    if not 0.0 < isolation_contamination <= 0.5:
        raise ValueError("isolation_contamination must be in (0.0, 0.5]")

    decision_tree = DecisionTreeClassifier(
        criterion="gini",
        max_depth=tree_max_depth,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=random_state,
    )
    random_forest = RandomForestClassifier(
        n_estimators=forest_trees,
        criterion="gini",
        max_depth=forest_max_depth,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=1,
    )

    # Only supervised classifiers receive training labels.
    decision_tree.fit(artifacts.X_train, artifacts.y_train)
    random_forest.fit(artifacts.X_train, artifacts.y_train)

    normal_index = artifacts.label_mapping["normal"]
    normal_mask = artifacts.y_train == normal_index
    normal_training_features = artifacts.X_train[normal_mask]
    isolation_forest = IsolationForest(
        n_estimators=isolation_trees,
        contamination=isolation_contamination,
        random_state=random_state,
        n_jobs=1,
    )
    # The unsupervised detector receives features from normal training rows only.
    isolation_forest.fit(normal_training_features)

    decision_tree_predictions = np.asarray(
        decision_tree.predict(artifacts.X_test),
        dtype=np.int64,
    )
    random_forest_predictions = np.asarray(
        random_forest.predict(artifacts.X_test),
        dtype=np.int64,
    )
    isolation_forest_predictions = np.asarray(
        isolation_forest.predict(artifacts.X_test),
        dtype=np.int8,
    )
    isolation_forest_scores = np.asarray(
        isolation_forest.decision_function(artifacts.X_test),
        dtype=np.float64,
    )

    if not np.isfinite(isolation_forest_scores).all():
        raise RuntimeError("Isolation Forest produced non-finite test scores")
    return TrainingResult(
        decision_tree=decision_tree,
        random_forest=random_forest,
        isolation_forest=isolation_forest,
        decision_tree_predictions=decision_tree_predictions,
        random_forest_predictions=random_forest_predictions,
        isolation_forest_predictions=isolation_forest_predictions,
        isolation_forest_scores=isolation_forest_scores,
        normal_training_rows=len(normal_training_features),
    )


def _label_name_by_index(label_mapping: Mapping[str, int]) -> dict[int, str]:
    return {index: label for label, index in label_mapping.items()}


def _classification_counts(
    predictions: np.ndarray,
    label_mapping: Mapping[str, int],
) -> dict[str, int]:
    counts = Counter(int(item) for item in predictions.tolist())
    by_index = _label_name_by_index(label_mapping)
    return {
        by_index[index]: counts[index]
        for index in sorted(counts)
        if index in by_index
    }


def _training_label_counts(
    labels: np.ndarray,
    label_mapping: Mapping[str, int],
) -> dict[str, int]:
    counts = Counter(int(item) for item in labels.tolist())
    return {
        label: counts.get(index, 0)
        for label, index in sorted(label_mapping.items(), key=lambda item: item[1])
    }


def _classifier_bundle(
    *,
    model_name: str,
    estimator: DecisionTreeClassifier | RandomForestClassifier,
    artifacts: MLReadyArtifacts,
) -> dict[str, Any]:
    return {
        "model_training_version": MODEL_TRAINING_VERSION,
        "model_name": model_name,
        "purpose": "known_attack_classification",
        "fit_scope": "training_rows_only",
        "feature_names": list(artifacts.feature_names),
        "label_mapping": dict(artifacts.label_mapping),
        "estimator": estimator,
    }


def _isolation_bundle(
    *,
    estimator: IsolationForest,
    artifacts: MLReadyArtifacts,
) -> dict[str, Any]:
    return {
        "model_training_version": MODEL_TRAINING_VERSION,
        "model_name": "isolation_forest",
        "purpose": "unknown_anomaly_detection",
        "fit_scope": "normal_training_features_only",
        "feature_names": list(artifacts.feature_names),
        "normal_label_index": artifacts.label_mapping["normal"],
        "prediction_encoding": {"1": "inlier", "-1": "anomaly"},
        "estimator": estimator,
    }


def _publish_files(staging: Path, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in sorted(staging.iterdir()):
        os.replace(path, output_dir / path.name)


def train_and_save_models(
    input_dir: Path,
    output_dir: Path,
    *,
    random_state: int = 42,
    forest_trees: int = 200,
    isolation_trees: int = 200,
    isolation_contamination: float = 0.05,
    tree_max_depth: int = 12,
    forest_max_depth: int = 16,
) -> dict[str, Any]:
    """Validate Step 8 artifacts, train three models, and publish bundles."""

    artifacts = load_ml_ready_artifacts(input_dir)
    result = fit_traditional_models(
        artifacts,
        random_state=random_state,
        forest_trees=forest_trees,
        isolation_trees=isolation_trees,
        isolation_contamination=isolation_contamination,
        tree_max_depth=tree_max_depth,
        forest_max_depth=forest_max_depth,
    )

    output_dir = output_dir.resolve()
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".step10-",
        dir=output_dir.parent,
    ) as temporary:
        staging = Path(temporary)
        joblib.dump(
            _classifier_bundle(
                model_name="decision_tree",
                estimator=result.decision_tree,
                artifacts=artifacts,
            ),
            staging / "decision_tree.joblib",
            compress=3,
        )
        joblib.dump(
            _classifier_bundle(
                model_name="random_forest",
                estimator=result.random_forest,
                artifacts=artifacts,
            ),
            staging / "random_forest.joblib",
            compress=3,
        )
        joblib.dump(
            _isolation_bundle(
                estimator=result.isolation_forest,
                artifacts=artifacts,
            ),
            staging / "isolation_forest.joblib",
            compress=3,
        )

        isolation_counts = Counter(
            int(item) for item in result.isolation_forest_predictions.tolist()
        )
        score_values = result.isolation_forest_scores
        manifest = {
            "model_training_version": MODEL_TRAINING_VERSION,
            "generated_at_utc": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "input": {
                "directory": str(artifacts.input_dir),
                "preprocessing_version": artifacts.preprocessing_manifest.get(
                    "preprocessing_version"
                ),
                "preprocessing_manifest_sha256": artifacts.input_hashes[
                    "preprocessing_manifest.json"
                ],
                "files": {
                    filename: {"sha256": file_hash}
                    for filename, file_hash in artifacts.input_hashes.items()
                },
            },
            "data": {
                "train_rows": len(artifacts.X_train),
                "test_rows": len(artifacts.X_test),
                "encoded_features": len(artifacts.feature_names),
                "training_label_counts": _training_label_counts(
                    artifacts.y_train,
                    artifacts.label_mapping,
                ),
                "normal_training_rows": result.normal_training_rows,
            },
            "configuration": {
                "random_state": random_state,
                "decision_tree": {
                    "criterion": "gini",
                    "max_depth": tree_max_depth,
                    "min_samples_leaf": 2,
                    "class_weight": "balanced",
                },
                "random_forest": {
                    "n_estimators": forest_trees,
                    "criterion": "gini",
                    "max_depth": forest_max_depth,
                    "min_samples_leaf": 2,
                    "max_features": "sqrt",
                    "class_weight": "balanced_subsample",
                    "n_jobs": 1,
                },
                "isolation_forest": {
                    "n_estimators": isolation_trees,
                    "contamination": isolation_contamination,
                    "n_jobs": 1,
                },
            },
            "models": {
                "decision_tree": {
                    "artifact": "decision_tree.joblib",
                    "purpose": "known_attack_classification",
                    "fit_scope": "training_rows_only",
                    "fit_rows": len(artifacts.X_train),
                    "classes_trained": [
                        _label_name_by_index(artifacts.label_mapping)[int(index)]
                        for index in result.decision_tree.classes_
                    ],
                    "test_prediction_counts": _classification_counts(
                        result.decision_tree_predictions,
                        artifacts.label_mapping,
                    ),
                },
                "random_forest": {
                    "artifact": "random_forest.joblib",
                    "purpose": "known_attack_classification",
                    "fit_scope": "training_rows_only",
                    "fit_rows": len(artifacts.X_train),
                    "classes_trained": [
                        _label_name_by_index(artifacts.label_mapping)[int(index)]
                        for index in result.random_forest.classes_
                    ],
                    "test_prediction_counts": _classification_counts(
                        result.random_forest_predictions,
                        artifacts.label_mapping,
                    ),
                },
                "isolation_forest": {
                    "artifact": "isolation_forest.joblib",
                    "purpose": "unknown_anomaly_detection",
                    "fit_scope": "normal_training_features_only",
                    "fit_rows": result.normal_training_rows,
                    "test_prediction_counts": {
                        "inlier": isolation_counts.get(1, 0),
                        "anomaly": isolation_counts.get(-1, 0),
                    },
                    "test_score_summary": {
                        "minimum": float(np.min(score_values)),
                        "maximum": float(np.max(score_values)),
                        "mean": float(np.mean(score_values)),
                    },
                    "prediction_encoding": {"1": "inlier", "-1": "anomaly"},
                },
            },
            "dependencies": {
                "numpy": np.__version__,
                "scikit_learn": sklearn.__version__,
                "joblib": joblib.__version__,
            },
            "safety": {
                "chronological_split_preserved": True,
                "preprocessed_input_arrays_modified": False,
                "supervised_models_fitted_on_test_rows": False,
                "test_labels_used_for_model_fit": False,
                "isolation_forest_used_labels_as_features": False,
                "training_labels_used_only_to_select_normal_rows": True,
                "isolation_forest_fit_scope": "normal_training_features_only",
                "raw_payload_used_as_direct_model_input": False,
                "direct_identifiers_used_as_model_inputs": False,
                "deterministic_random_state": True,
                "model_selection_performed": False,
            },
            "files": {
                filename: {"sha256": _sha256_file(staging / filename)}
                for filename in MODEL_ARTIFACT_FILES
            },
        }

        for filename, before_hash in artifacts.input_hashes.items():
            after_hash = _sha256_file(artifacts.input_dir / filename)
            if after_hash != before_hash:
                raise RuntimeError(f"input artifact changed during training: {filename}")

        _write_json(staging / "training_manifest.json", manifest)
        _publish_files(staging, output_dir)

    return manifest
