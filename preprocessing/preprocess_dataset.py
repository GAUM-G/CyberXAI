"""Convert the sanitized Step 6 dataset into leakage-safe ML arrays."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from dataset.labeling import APPROVED_LABELS
    from feature_engineering.engineer_features import (
        ENGINEERED_NUMERICAL_FEATURES,
        FEATURE_DEFINITIONS,
        FEATURE_ENGINEERING_VERSION,
        FeatureEngineeringState,
        engineer_rows,
    )
else:
    from dataset.labeling import APPROVED_LABELS
    from feature_engineering.engineer_features import (
        ENGINEERED_NUMERICAL_FEATURES,
        FEATURE_DEFINITIONS,
        FEATURE_ENGINEERING_VERSION,
        FeatureEngineeringState,
        engineer_rows,
    )


PREPROCESSING_VERSION = "1.1"

# Safe non-behavioural inputs retained from the Step 7 baseline.
BASE_NUMERICAL_FEATURES = (
    "source_port",
    "destination_port",
    "username_present",
    "session_id_present",
)

# Step 8 adds exactly the eight reviewed behavioural/security features.
NUMERICAL_FEATURES = BASE_NUMERICAL_FEATURES + ENGINEERED_NUMERICAL_FEATURES

CATEGORICAL_FEATURES = (
    "source_ip_scope",
    "service",
    "protocol",
    "request_method",
)

MODEL_FEATURES = NUMERICAL_FEATURES + CATEGORICAL_FEATURES
LABEL_TO_INDEX = {label: index for index, label in enumerate(APPROVED_LABELS)}

# These columns remain in the sanitized Step 6 dataset for ordering, grouping,
# auditing, and future Step 8 feature extraction. They are not direct model
# inputs because identifiers, raw text, or attack-named events can leak targets.
EXCLUDED_MODEL_FIELDS = (
    "event_id",
    "timestamp_utc",
    "source_ip_hash",
    "event_type",
    "event",
    "request_path",
    "payload_json",
    "metadata_json",
    "severity",
    "status",
    "label",
)

REQUIRED_INPUT_FIELDS = frozenset(
    {
        "event_id",
        "timestamp_utc",
        "source_ip_hash",
        "label",
        *BASE_NUMERICAL_FEATURES,
        *CATEGORICAL_FEATURES,
        "severity",
        "status",
        "event_type",
        "event",
        "request_path",
        "payload_length",
        "payload_json",
        "metadata_json",
    }
)

OUTPUT_ARRAY_FILES = (
    "X_train.npy",
    "X_test.npy",
    "y_train.npy",
    "y_test.npy",
    "X_train_sequences.npy",
    "X_test_sequences.npy",
    "y_train_sequences.npy",
    "y_test_sequences.npy",
)


def _parse_timestamp(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("timestamp_utc must be a non-empty ISO-8601 value")
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _clean_category(value: Any) -> str | float:
    text = str(value or "").strip().lower()
    return text if text else np.nan


def _clean_number(value: Any) -> float:
    if value is None:
        return np.nan
    text = str(value).strip()
    if not text:
        return np.nan
    lowered = text.lower()
    if lowered in {"true", "yes"}:
        return 1.0
    if lowered in {"false", "no"}:
        return 0.0
    try:
        number = float(text)
    except ValueError:
        return np.nan
    return number if math.isfinite(number) else np.nan


def read_dataset(input_csv: Path) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Read, validate, chronologically sort, and deduplicate Step 6 rows."""

    if not input_csv.is_file():
        raise FileNotFoundError(f"dataset not found: {input_csv}")

    with input_csv.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        input_fields = set(reader.fieldnames or ())
        missing = sorted(REQUIRED_INPUT_FIELDS - input_fields)
        if missing:
            raise ValueError(f"dataset is missing required columns: {', '.join(missing)}")

        rows: list[dict[str, str]] = []
        seen_event_ids: set[str] = set()
        duplicates = 0

        for line_number, raw_row in enumerate(reader, start=2):
            row = {str(key): "" if value is None else str(value) for key, value in raw_row.items()}
            event_id = row["event_id"].strip().lower()
            if not event_id:
                raise ValueError(f"line {line_number}: event_id must not be empty")
            if event_id in seen_event_ids:
                duplicates += 1
                continue

            try:
                parsed_timestamp = _parse_timestamp(row["timestamp_utc"])
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError(f"line {line_number}: invalid timestamp_utc") from exc

            label = row["label"].strip().lower()
            if label not in LABEL_TO_INDEX:
                raise ValueError(
                    f"line {line_number}: label must be one of {', '.join(APPROVED_LABELS)}"
                )

            row["event_id"] = event_id
            row["label"] = label
            row["_timestamp"] = parsed_timestamp.isoformat()
            seen_event_ids.add(event_id)
            rows.append(row)

    if len(rows) < 2:
        raise ValueError("at least two unique dataset rows are required")

    rows.sort(key=lambda row: (_parse_timestamp(row["_timestamp"]), row["event_id"]))
    return rows, {
        "input_rows": len(rows) + duplicates,
        "unique_rows": len(rows),
        "duplicate_event_ids_removed": duplicates,
    }


def split_rows(
    rows: Sequence[Mapping[str, str]],
    *,
    test_size: float,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Create a deterministic chronological split before fitting transforms."""

    if not 0.0 < test_size < 1.0:
        raise ValueError("test_size must be greater than 0 and less than 1")
    if len(rows) < 2:
        raise ValueError("at least two rows are required for train/test splitting")

    test_count = max(1, int(math.ceil(len(rows) * test_size)))
    train_count = len(rows) - test_count
    if train_count < 1:
        raise ValueError("test_size leaves no training rows")

    return [dict(row) for row in rows[:train_count]], [
        dict(row) for row in rows[train_count:]
    ]


def rows_to_matrix(rows: Sequence[Mapping[str, str]]) -> np.ndarray:
    """Create the mixed-type matrix consumed by the scikit-learn transformer."""

    matrix = np.empty((len(rows), len(MODEL_FEATURES)), dtype=object)
    for row_index, row in enumerate(rows):
        for column_index, feature in enumerate(NUMERICAL_FEATURES):
            matrix[row_index, column_index] = _clean_number(row.get(feature))
        offset = len(NUMERICAL_FEATURES)
        for category_index, feature in enumerate(CATEGORICAL_FEATURES):
            matrix[row_index, offset + category_index] = _clean_category(row.get(feature))
    return matrix


def build_preprocessor() -> ColumnTransformer:
    """Build imputers, one-hot encoding, and train-fitted normalization."""

    numeric_indexes = list(range(len(NUMERICAL_FEATURES)))
    categorical_indexes = list(range(len(NUMERICAL_FEATURES), len(MODEL_FEATURES)))

    numeric_pipeline = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(strategy="median", keep_empty_features=True),
            ),
            ("scaler", StandardScaler()),
        ]
    )
    categorical_pipeline = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(
                    strategy="constant",
                    fill_value="missing",
                    keep_empty_features=True,
                ),
            ),
            (
                "encoder",
                OneHotEncoder(
                    handle_unknown="ignore",
                    sparse_output=False,
                    dtype=np.float32,
                ),
            ),
        ]
    )
    return ColumnTransformer(
        transformers=[
            ("numeric", numeric_pipeline, numeric_indexes),
            ("categorical", categorical_pipeline, categorical_indexes),
        ],
        remainder="drop",
        sparse_threshold=0.0,
        verbose_feature_names_out=True,
    )


def encode_labels(rows: Sequence[Mapping[str, str]]) -> np.ndarray:
    return np.asarray([LABEL_TO_INDEX[row["label"]] for row in rows], dtype=np.int64)


def create_sequences(
    features: np.ndarray,
    labels: np.ndarray,
    rows: Sequence[Mapping[str, str]],
    *,
    sequence_length: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Create sliding windows within each pseudonymous source/service group."""

    if sequence_length < 2:
        raise ValueError("sequence_length must be at least 2")
    if len(features) != len(labels) or len(features) != len(rows):
        raise ValueError("features, labels, and rows must contain the same number of items")

    grouped_indexes: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        source = str(row.get("source_ip_hash") or "missing-source").strip()
        service = str(row.get("service") or "missing-service").strip().lower()
        grouped_indexes[(source, service)].append(index)

    windows: list[tuple[datetime, np.ndarray, int]] = []
    for indexes in grouped_indexes.values():
        indexes.sort(
            key=lambda index: (
                _parse_timestamp(rows[index]["_timestamp"]),
                str(rows[index]["event_id"]),
            )
        )
        for end in range(sequence_length, len(indexes) + 1):
            window_indexes = indexes[end - sequence_length : end]
            target_index = window_indexes[-1]
            windows.append(
                (
                    _parse_timestamp(rows[target_index]["_timestamp"]),
                    features[window_indexes],
                    int(labels[target_index]),
                )
            )

    windows.sort(key=lambda item: item[0])
    if not windows:
        return (
            np.empty(
                (0, sequence_length, features.shape[1]),
                dtype=np.float32,
            ),
            np.empty((0,), dtype=np.int64),
        )

    sequence_features = np.stack([item[1] for item in windows]).astype(
        np.float32,
        copy=False,
    )
    sequence_labels = np.asarray([item[2] for item in windows], dtype=np.int64)
    return sequence_features, sequence_labels


def _label_counts(rows: Sequence[Mapping[str, str]]) -> dict[str, int]:
    counts = Counter(row["label"] for row in rows)
    return {label: counts.get(label, 0) for label in APPROVED_LABELS}


def _sequence_label_counts(labels: np.ndarray) -> dict[str, int]:
    counts = Counter(int(value) for value in labels.tolist())
    return {
        label: counts.get(LABEL_TO_INDEX[label], 0)
        for label in APPROVED_LABELS
    }


def _write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def _publish_files(staging: Path, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in sorted(staging.iterdir()):
        os.replace(path, output_dir / path.name)


def preprocess_dataset(
    input_csv: Path,
    output_dir: Path,
    *,
    test_size: float = 0.2,
    sequence_length: int = 10,
) -> dict[str, Any]:
    """Run Step 7 without modifying the Step 6 input dataset."""

    rows, read_stats = read_dataset(input_csv)
    train_rows, test_rows = split_rows(rows, test_size=test_size)

    feature_state = FeatureEngineeringState()
    train_rows = engineer_rows(train_rows, state=feature_state)
    test_rows = engineer_rows(test_rows, state=feature_state)

    train_matrix = rows_to_matrix(train_rows)
    test_matrix = rows_to_matrix(test_rows)

    preprocessor = build_preprocessor()
    X_train = np.asarray(
        preprocessor.fit_transform(train_matrix),
        dtype=np.float32,
    )
    X_test = np.asarray(preprocessor.transform(test_matrix), dtype=np.float32)
    if not np.isfinite(X_train).all() or not np.isfinite(X_test).all():
        raise RuntimeError("preprocessing produced non-finite feature values")

    y_train = encode_labels(train_rows)
    y_test = encode_labels(test_rows)
    X_train_sequences, y_train_sequences = create_sequences(
        X_train,
        y_train,
        train_rows,
        sequence_length=sequence_length,
    )
    X_test_sequences, y_test_sequences = create_sequences(
        X_test,
        y_test,
        test_rows,
        sequence_length=sequence_length,
    )

    feature_names = [
        str(name)
        for name in preprocessor.get_feature_names_out(MODEL_FEATURES).tolist()
    ]
    input_hash = _sha256_file(input_csv)

    output_dir = output_dir.resolve()
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".step7-",
        dir=output_dir.parent,
    ) as temporary:
        staging = Path(temporary)
        arrays = {
            "X_train.npy": X_train,
            "X_test.npy": X_test,
            "y_train.npy": y_train,
            "y_test.npy": y_test,
            "X_train_sequences.npy": X_train_sequences,
            "X_test_sequences.npy": X_test_sequences,
            "y_train_sequences.npy": y_train_sequences,
            "y_test_sequences.npy": y_test_sequences,
        }
        for filename, array in arrays.items():
            np.save(staging / filename, array, allow_pickle=False)

        joblib.dump(preprocessor, staging / "preprocessor.joblib", compress=3)
        _write_json(staging / "feature_names.json", feature_names)
        _write_json(staging / "label_mapping.json", LABEL_TO_INDEX)

        artifact_files = [
            *OUTPUT_ARRAY_FILES,
            "preprocessor.joblib",
            "feature_names.json",
            "label_mapping.json",
        ]
        manifest = {
            "preprocessing_version": PREPROCESSING_VERSION,
            "generated_at_utc": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "input": {
                "path": str(input_csv.resolve()),
                "sha256": input_hash,
                **read_stats,
            },
            "split": {
                "strategy": "chronological",
                "test_size": test_size,
                "train_rows": len(train_rows),
                "test_rows": len(test_rows),
                "train_end_utc": train_rows[-1]["_timestamp"],
                "test_start_utc": test_rows[0]["_timestamp"],
                "transform_fit_scope": "training_rows_only",
            },
            "features": {
                "feature_engineering_version": FEATURE_ENGINEERING_VERSION,
                "engineered_numerical": list(ENGINEERED_NUMERICAL_FEATURES),
                "engineered_definitions": FEATURE_DEFINITIONS,
                "engineering_scope": {
                    "ordering": "chronological",
                    "grouping": ["source_ip_hash", "service"],
                    "history": "current and past events only",
                    "test_context": (
                        "past training rows and chronologically earlier "
                        "test rows only"
                    ),
                    "label_used": False,
                },
                "numerical": list(NUMERICAL_FEATURES),
                "categorical": list(CATEGORICAL_FEATURES),
                "excluded_direct_model_fields": list(EXCLUDED_MODEL_FIELDS),
                "encoded_feature_count": len(feature_names),
                "missing_values": {
                    "numerical": "training median",
                    "categorical": "missing category",
                },
                "categorical_encoding": "one-hot; unknown test categories ignored",
                "numerical_normalization": "standard scaling fitted on training rows",
            },
            "labels": {
                "mapping": LABEL_TO_INDEX,
                "train_counts": _label_counts(train_rows),
                "test_counts": _label_counts(test_rows),
            },
            "sequences": {
                "length": sequence_length,
                "grouping": ["source_ip_hash", "service"],
                "target": "last event label",
                "crosses_train_test_boundary": False,
                "train_sequences": len(X_train_sequences),
                "test_sequences": len(X_test_sequences),
                "train_label_counts": _sequence_label_counts(y_train_sequences),
                "test_label_counts": _sequence_label_counts(y_test_sequences),
            },
            "arrays": {
                filename: {
                    "shape": list(array.shape),
                    "dtype": str(array.dtype),
                }
                for filename, array in arrays.items()
            },
            "dependencies": {
                "numpy": np.__version__,
                "scikit_learn": sklearn.__version__,
                "joblib": joblib.__version__,
            },
            "files": {
                filename: {"sha256": _sha256_file(staging / filename)}
                for filename in artifact_files
            },
            "safety": {
                "input_dataset_modified": False,
                "preprocessor_fitted_on_test_data": False,
                "raw_payload_used_as_direct_model_input": False,
                "direct_identifiers_used_as_model_inputs": False,
                "labels_used_for_feature_engineering": False,
                "future_events_used_for_feature_engineering": False,
            },
        }
        _write_json(staging / "preprocessing_manifest.json", manifest)
        _publish_files(staging, output_dir)

    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-csv",
        type=Path,
        default=Path("data/processed/honeypot_dataset.csv"),
        help="sanitized Step 6 CSV (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/ml_ready"),
        help="generated ML artifacts directory (default: %(default)s)",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="chronological test fraction (default: %(default)s)",
    )
    parser.add_argument(
        "--sequence-length",
        type=int,
        default=10,
        help="events per source/service LSTM sequence (default: %(default)s)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = preprocess_dataset(
        args.input_csv,
        args.output_dir,
        test_size=args.test_size,
        sequence_length=args.sequence_length,
    )

    print(f"[PREPROCESS] Input rows: {manifest['input']['input_rows']}")
    print(
        "[PREPROCESS] Unique rows: "
        f"{manifest['input']['unique_rows']} "
        f"(duplicates removed: {manifest['input']['duplicate_event_ids_removed']})"
    )
    print(
        f"[PREPROCESS] Train/Test rows: "
        f"{manifest['split']['train_rows']}/{manifest['split']['test_rows']}"
    )
    print(
        f"[PREPROCESS] Encoded features: "
        f"{manifest['features']['encoded_feature_count']}"
    )
    print(
        f"[PREPROCESS] Engineered features: "
        f"{len(manifest['features']['engineered_numerical'])}"
    )
    print(
        f"[PREPROCESS] Train/Test sequences: "
        f"{manifest['sequences']['train_sequences']}/"
        f"{manifest['sequences']['test_sequences']}"
    )
    print(f"[PREPROCESS] Output: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
