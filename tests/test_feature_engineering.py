from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

from feature_engineering.engineer_features import (
    ENGINEERED_NUMERICAL_FEATURES,
    FeatureEngineeringState,
    engineer_rows,
)
from preprocessing.preprocess_dataset import preprocess_dataset


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


def make_row(seconds: int, **overrides):
    timestamp = datetime(2026, 7, 25, tzinfo=timezone.utc) + timedelta(
        seconds=seconds
    )
    row = {
        "event_id": f"9f7648bc-6797-4db1-b50a-{seconds:012d}",
        "timestamp_utc": timestamp.isoformat().replace("+00:00", "Z"),
        "source_ip_hash": "source-a",
        "source_ip_scope": "loopback",
        "source_port": "51000",
        "destination_port": "8080",
        "service": "http",
        "protocol": "http",
        "event_type": "authentication",
        "event": "login_attempt",
        "severity": "warning",
        "status": "success",
        "username_present": "1",
        "session_id_present": "1",
        "request_method": "POST",
        "request_path": "/login",
        "payload_length": "20",
        "payload_json": json.dumps({"username": "demo-user"}),
        "metadata_json": "{}",
        "label": "normal",
    }
    row.update(overrides)
    return row


def write_csv(path: Path, rows) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class FeatureDefinitionTests(unittest.TestCase):
    def test_exact_eight_features_are_added(self):
        featured = engineer_rows([make_row(0)])[0]

        self.assertEqual(8, len(ENGINEERED_NUMERICAL_FEATURES))
        self.assertEqual(
            set(ENGINEERED_NUMERICAL_FEATURES),
            set(ENGINEERED_NUMERICAL_FEATURES) & set(featured),
        )
        for name in ENGINEERED_NUMERICAL_FEATURES:
            self.assertTrue(np.isfinite(float(featured[name])))

    def test_labels_do_not_change_engineered_values(self):
        normal = engineer_rows([make_row(0, label="normal")])[0]
        attack = engineer_rows([make_row(0, label="xss")])[0]

        self.assertEqual(
            [normal[name] for name in ENGINEERED_NUMERICAL_FEATURES],
            [attack[name] for name in ENGINEERED_NUMERICAL_FEATURES],
        )

    def test_rolling_counts_time_gaps_and_groups_are_causal(self):
        rows = [
            make_row(0, status="failed"),
            make_row(30, status="failed"),
            make_row(
                40,
                source_ip_hash="source-b",
                status="success",
                event_id="9f7648bc-6797-4db1-b50a-000000000040",
            ),
            make_row(70, status="success"),
        ]
        featured = engineer_rows(rows)

        self.assertEqual([1, 2, 1, 2], [
            row["requests_per_minute"] for row in featured
        ])
        self.assertEqual([1, 2, 0, 1], [
            row["failed_attempts"] for row in featured
        ])
        self.assertEqual([0.0, 30.0, 0.0, 40.0], [
            row["time_between_requests"] for row in featured
        ])

    def test_session_duration_resets_after_five_minute_inactivity(self):
        featured = engineer_rows(
            [
                make_row(0),
                make_row(120),
                make_row(421),
            ]
        )

        self.assertEqual(
            [0.0, 120.0, 0.0],
            [row["session_duration"] for row in featured],
        )

    def test_username_repetition_uses_value_without_emitting_it_as_a_feature(self):
        featured = engineer_rows(
            [
                make_row(0, payload_json=json.dumps({"username": "admin"})),
                make_row(30, payload_json=json.dumps({"username": "ADMIN"})),
                make_row(45, payload_json=json.dumps({"username": "guest"})),
                make_row(90, payload_json=json.dumps({"username": "admin"})),
            ]
        )

        self.assertEqual(
            [0, 1, 0, 2],
            [row["username_repetition"] for row in featured],
        )
        self.assertFalse(any("admin" in name for name in ENGINEERED_NUMERICAL_FEATURES))

    def test_security_pattern_counts_cover_recon_sqli_and_xss(self):
        row = make_row(
            0,
            request_path="/admin/../../.env",
            payload_json=json.dumps(
                {
                    "query": (
                        "' UNION SELECT password FROM users WHERE 1=1 -- "
                        "<script>alert(1)</script>"
                    )
                }
            ),
        )
        featured = engineer_rows([row])[0]

        self.assertGreaterEqual(featured["suspicious_keyword_count"], 3)
        self.assertGreaterEqual(featured["sqli_xss_pattern_count"], 4)

    def test_future_rows_cannot_change_earlier_features(self):
        first_two = [make_row(0, status="failed"), make_row(20, status="failed")]
        before_future = engineer_rows(first_two)
        after_future = engineer_rows([*first_two, make_row(40, status="failed")])

        for index in range(2):
            self.assertEqual(
                [before_future[index][name] for name in ENGINEERED_NUMERICAL_FEATURES],
                [after_future[index][name] for name in ENGINEERED_NUMERICAL_FEATURES],
            )

    def test_invalid_length_and_json_have_safe_fallbacks(self):
        row = make_row(
            0,
            payload_length="not-a-number",
            payload_json="{malformed",
            metadata_json="not-json",
        )
        featured = engineer_rows([row])[0]

        self.assertEqual(float(len("{malformed")), featured["payload_length"])
        for name in ENGINEERED_NUMERICAL_FEATURES:
            self.assertTrue(np.isfinite(float(featured[name])))


class PreprocessingIntegrationTests(unittest.TestCase):
    def test_step8_features_are_in_leakage_safe_ml_artifacts(self):
        rows = []
        for index in range(20):
            rows.append(
                make_row(
                    index * 20,
                    event_id=f"9f7648bc-6797-4db1-b50a-{index:012d}",
                    status="failed" if index % 3 == 0 else "success",
                    payload_json=json.dumps(
                        {
                            "username": f"user-{index % 2}",
                            "query": "<script>alert(1)</script>"
                            if index % 5 == 0
                            else "normal",
                        }
                    ),
                    label="xss" if index % 5 == 0 else "normal",
                )
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_csv = root / "dataset.csv"
            output_dir = root / "ml_ready"
            write_csv(input_csv, rows)
            before_hash = sha256_file(input_csv)

            manifest = preprocess_dataset(
                input_csv,
                output_dir,
                test_size=0.25,
                sequence_length=2,
            )

            after_hash = sha256_file(input_csv)
            X_train = np.load(output_dir / "X_train.npy", allow_pickle=False)
            X_test = np.load(output_dir / "X_test.npy", allow_pickle=False)
            with (output_dir / "feature_names.json").open(
                "r", encoding="utf-8"
            ) as handle:
                feature_names = json.load(handle)

        self.assertEqual(before_hash, after_hash)
        self.assertEqual(
            list(ENGINEERED_NUMERICAL_FEATURES),
            manifest["features"]["engineered_numerical"],
        )
        self.assertEqual(8, len(manifest["features"]["engineered_numerical"]))
        self.assertEqual(15, manifest["split"]["train_rows"])
        self.assertEqual(5, manifest["split"]["test_rows"])
        self.assertTrue(np.isfinite(X_train).all())
        self.assertTrue(np.isfinite(X_test).all())
        self.assertEqual(X_train.shape[1], manifest["features"]["encoded_feature_count"])
        for name in ENGINEERED_NUMERICAL_FEATURES:
            self.assertTrue(any(feature.endswith(name) for feature in feature_names))
        self.assertFalse(manifest["features"]["engineering_scope"]["label_used"])
        self.assertFalse(manifest["safety"]["labels_used_for_feature_engineering"])
        self.assertFalse(manifest["safety"]["future_events_used_for_feature_engineering"])


if __name__ == "__main__":
    unittest.main()
