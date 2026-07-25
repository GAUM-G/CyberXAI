from __future__ import annotations

import csv
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np

from preprocessing.preprocess_dataset import (
    APPROVED_LABELS,
    LABEL_TO_INDEX,
    MODEL_FEATURES,
    build_preprocessor,
    create_sequences,
    preprocess_dataset,
    read_dataset,
    rows_to_matrix,
    split_rows,
)


CSV_FIELDS = (
    "event_id",
    "timestamp_utc",
    "source_ip_hash",
    "source_ip_scope",
    "source_port",
    "destination_port",
    "service",
    "protocol",
    "event_type",
    "event",
    "severity",
    "status",
    "username_present",
    "session_id_present",
    "request_method",
    "request_path",
    "payload_length",
    "payload_json",
    "metadata_json",
    "label",
)


def make_row(index: int, **overrides):
    timestamp = datetime(2026, 7, 25, tzinfo=timezone.utc) + timedelta(minutes=index)
    row = {
        "event_id": f"9f7648bc-6797-4db1-b50a-{index:012d}",
        "timestamp_utc": timestamp.isoformat().replace("+00:00", "Z"),
        "source_ip_hash": f"source-{index % 2}",
        "source_ip_scope": "loopback",
        "source_port": str(50000 + index),
        "destination_port": "2222" if index % 2 == 0 else "8080",
        "service": "ssh" if index % 2 == 0 else "http",
        "protocol": "ssh" if index % 2 == 0 else "http",
        "event_type": "authentication",
        "event": "login_attempt",
        "severity": "warning",
        "status": "failed",
        "username_present": "1",
        "session_id_present": "1",
        "request_method": "POST" if index % 2 else "",
        "request_path": "/login",
        "payload_length": str(20 + index),
        "payload_json": "{}",
        "metadata_json": "{}",
        "label": APPROVED_LABELS[index % len(APPROVED_LABELS)],
    }
    row.update(overrides)
    return row


def write_csv(path: Path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


class DatasetReadAndSplitTests(unittest.TestCase):
    def test_duplicate_event_ids_are_removed_and_rows_are_sorted(self):
        rows = [make_row(2), make_row(0), make_row(1), make_row(1)]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dataset.csv"
            write_csv(path, rows)
            loaded, stats = read_dataset(path)

        self.assertEqual(3, len(loaded))
        self.assertEqual(1, stats["duplicate_event_ids_removed"])
        self.assertEqual(make_row(0)["event_id"], loaded[0]["event_id"])
        self.assertEqual(make_row(2)["event_id"], loaded[-1]["event_id"])

    def test_split_is_chronological_and_non_overlapping(self):
        rows = [make_row(index) for index in range(10)]
        for row in rows:
            row["_timestamp"] = row["timestamp_utc"]
        train, test = split_rows(rows, test_size=0.2)

        self.assertEqual(8, len(train))
        self.assertEqual(2, len(test))
        self.assertLess(train[-1]["_timestamp"], test[0]["_timestamp"])
        self.assertTrue(set(row["event_id"] for row in train).isdisjoint(
            row["event_id"] for row in test
        ))


class TransformerTests(unittest.TestCase):
    def test_missing_values_are_imputed_and_numbers_are_normalized(self):
        rows = [
            make_row(0, source_port="", request_method=""),
            make_row(1, source_port="51000", request_method="POST"),
            make_row(2, source_port="52000", request_method="POST"),
        ]
        matrix = rows_to_matrix(rows)
        transformer = build_preprocessor()
        transformed = np.asarray(transformer.fit_transform(matrix), dtype=np.float32)

        self.assertEqual(3, transformed.shape[0])
        self.assertTrue(np.isfinite(transformed).all())
        self.assertAlmostEqual(0.0, float(transformed[:, 0].mean()), places=5)

    def test_test_only_category_does_not_change_fitted_feature_space(self):
        train_rows = [
            make_row(0, request_method="GET"),
            make_row(1, request_method="POST"),
        ]
        test_rows = [make_row(2, request_method="PATCH")]
        transformer = build_preprocessor()
        train = transformer.fit_transform(rows_to_matrix(train_rows))
        test = transformer.transform(rows_to_matrix(test_rows))
        names = transformer.get_feature_names_out(MODEL_FEATURES)

        self.assertEqual(train.shape[1], test.shape[1])
        self.assertFalse(any("PATCH" in name for name in names))


class SequenceAndArtifactTests(unittest.TestCase):
    def test_sequences_stay_within_source_and_service_groups(self):
        rows = [make_row(index) for index in range(8)]
        for row in rows:
            row["_timestamp"] = row["timestamp_utc"]
        features = np.asarray([[index] for index in range(8)], dtype=np.float32)
        labels = np.arange(8, dtype=np.int64)

        X_sequences, y_sequences = create_sequences(
            features,
            labels,
            rows,
            sequence_length=2,
        )

        self.assertEqual((6, 2, 1), X_sequences.shape)
        for sequence in X_sequences:
            self.assertEqual(0, int(sequence[0, 0]) % 2 ^ int(sequence[1, 0]) % 2)
        self.assertEqual(6, len(y_sequences))

    def test_end_to_end_outputs_are_finite_and_leakage_safe(self):
        rows = [make_row(index) for index in range(24)]
        rows.append(dict(rows[5]))
        rows[-1]["source_port"] = ""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_csv = root / "dataset.csv"
            output_dir = root / "ml_ready"
            write_csv(input_csv, rows)

            manifest = preprocess_dataset(
                input_csv,
                output_dir,
                test_size=0.25,
                sequence_length=2,
            )

            X_train = np.load(output_dir / "X_train.npy", allow_pickle=False)
            X_test = np.load(output_dir / "X_test.npy", allow_pickle=False)
            y_train = np.load(output_dir / "y_train.npy", allow_pickle=False)
            X_train_sequences = np.load(
                output_dir / "X_train_sequences.npy",
                allow_pickle=False,
            )
            loaded_transformer = joblib.load(output_dir / "preprocessor.joblib")
            with (output_dir / "preprocessing_manifest.json").open(
                "r", encoding="utf-8"
            ) as handle:
                disk_manifest = json.load(handle)

        self.assertEqual(25, manifest["input"]["input_rows"])
        self.assertEqual(1, manifest["input"]["duplicate_event_ids_removed"])
        self.assertEqual(18, len(X_train))
        self.assertEqual(6, len(X_test))
        self.assertEqual(len(X_train), len(y_train))
        self.assertTrue(np.isfinite(X_train).all())
        self.assertTrue(np.isfinite(X_test).all())
        self.assertGreater(len(X_train_sequences), 0)
        self.assertEqual(X_train.shape[1], len(loaded_transformer.get_feature_names_out()))
        self.assertEqual("training_rows_only", disk_manifest["split"]["transform_fit_scope"])
        self.assertFalse(disk_manifest["safety"]["preprocessor_fitted_on_test_data"])
        self.assertNotIn(
            "event",
            disk_manifest["features"]["numerical"]
            + disk_manifest["features"]["categorical"],
        )
        self.assertEqual(LABEL_TO_INDEX, disk_manifest["labels"]["mapping"])


if __name__ == "__main__":
    unittest.main()
