from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dataset.labeling import APPROVED_LABELS, assign_label
from dataset.prepare_dataset import (
    DATASET_FIELDS,
    fetch_backend_events,
    prepare_events,
    sanitize_sensitive,
    write_dataset,
)


def sample_event(**overrides):
    event = {
        "schema_version": "1.0",
        "event_id": "9f7648bc-6797-4db1-b50a-71bb288c0001",
        "timestamp": "2026-07-25T04:30:00+00:00",
        "source_ip": "127.0.0.1",
        "source_port": 51000,
        "destination_port": 2222,
        "service": "ssh",
        "protocol": "ssh",
        "event_type": "authentication",
        "event": "ssh_login_attempt",
        "attack_type": "authentication_probe",
        "severity": "warning",
        "status": "failed",
        "username": "demo-user",
        "session_id": "session-1",
        "request_method": None,
        "request_path": None,
        "payload": {"username": "demo-user", "password": "fake-password"},
        "metadata": {"attempt_count": 1, "authorization": "Bearer fake-token"},
    }
    event.update(overrides)
    return event


class LabelingTests(unittest.TestCase):
    def test_all_approved_attack_labels_are_assigned(self):
        explicit = APPROVED_LABELS[1:-1]
        for attack_type in explicit:
            with self.subTest(attack_type=attack_type):
                self.assertEqual(
                    attack_type,
                    assign_label(sample_event(attack_type=attack_type)),
                )

    def test_only_informational_normal_activity_is_normal(self):
        self.assertEqual(
            "normal",
            assign_label(sample_event(attack_type="web_activity", severity="info")),
        )
        self.assertEqual(
            "other_anomaly",
            assign_label(sample_event(attack_type="web_activity", severity="warning")),
        )

    def test_unapproved_probe_types_become_other_anomaly(self):
        for attack_type in (
            "authentication_probe",
            "connection_probe",
            "credential_access",
            "command_activity",
            "http_bruteforce",
            "file_access",
            "unknown",
        ):
            with self.subTest(attack_type=attack_type):
                self.assertEqual(
                    "other_anomaly",
                    assign_label(sample_event(attack_type=attack_type)),
                )


class SanitizationTests(unittest.TestCase):
    def test_nested_and_inline_credentials_are_redacted(self):
        value = {
            "password": "secret-value",
            "nested": {"apiKey": "token-value"},
            "form": "username=admin&password=do-not-store&query=<script>alert(1)</script>",
        }
        sanitized = sanitize_sensitive(value)
        text = json.dumps(sanitized)
        self.assertNotIn("secret-value", text)
        self.assertNotIn("token-value", text)
        self.assertNotIn("do-not-store", text)
        self.assertIn("<script>alert(1)</script>", text)


class DatasetPreparationTests(unittest.TestCase):
    def test_prepare_deduplicates_rejects_and_removes_leakage_fields(self):
        accepted = sample_event(
            attack_type="ssh_bruteforce",
            payload={"password": "must-disappear"},
        )
        duplicate = dict(accepted)
        invalid = sample_event(
            event_id="not-a-uuid",
            attack_type="sql_injection",
        )

        rows, rejected, stats = prepare_events([accepted, duplicate, invalid])

        self.assertEqual(1, len(rows))
        self.assertEqual(1, len(rejected))
        self.assertEqual(3, stats["total_events"])
        self.assertEqual(1, stats["accepted_events"])
        self.assertEqual(1, stats["duplicate_events"])
        self.assertEqual("ssh_bruteforce", rows[0]["label"])
        self.assertNotIn("attack_type", rows[0])
        self.assertNotIn("source_ip", rows[0])
        self.assertNotIn("username", rows[0])
        self.assertNotIn("session_id", rows[0])
        self.assertNotIn("must-disappear", rows[0]["payload_json"])

    def test_csv_jsonl_and_manifest_counts_match(self):
        events = [
            sample_event(
                event_id="9f7648bc-6797-4db1-b50a-71bb288c0001",
                attack_type="web_activity",
                severity="info",
                service="http",
                protocol="http",
                destination_port=8080,
            ),
            sample_event(
                event_id="9f7648bc-6797-4db1-b50a-71bb288c0002",
                attack_type="xss",
                service="http",
                protocol="http",
                destination_port=8080,
            ),
        ]
        rows, rejected, stats = prepare_events(events)

        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            manifest = write_dataset(
                rows,
                rejected,
                stats,
                output_dir=output_dir,
                source="unit-test",
            )

            with (output_dir / "honeypot_dataset.csv").open(
                "r", encoding="utf-8", newline=""
            ) as handle:
                csv_rows = list(csv.DictReader(handle))
            with (output_dir / "honeypot_dataset.jsonl").open(
                "r", encoding="utf-8"
            ) as handle:
                jsonl_rows = [json.loads(line) for line in handle if line.strip()]

            self.assertEqual(list(DATASET_FIELDS), list(csv_rows[0].keys()))
            self.assertEqual(2, len(csv_rows))
            self.assertEqual(2, len(jsonl_rows))
            self.assertEqual(2, manifest["accepted_events"])
            self.assertEqual(1, manifest["labels"]["normal"])
            self.assertEqual(1, manifest["labels"]["xss"])
            self.assertNotIn("attack_type", manifest["dataset_fields"])


class BackendPaginationTests(unittest.TestCase):
    def test_fetches_all_backend_pages_with_offset(self):
        page_one = [
            sample_event(event_id="9f7648bc-6797-4db1-b50a-71bb288c0001"),
            sample_event(event_id="9f7648bc-6797-4db1-b50a-71bb288c0002"),
        ]
        page_two = [
            sample_event(event_id="9f7648bc-6797-4db1-b50a-71bb288c0003")
        ]

        with patch(
            "dataset.prepare_dataset._read_json",
            side_effect=[
                {"total_events": 3},
                {"events": page_one},
                {"events": page_two},
            ],
        ) as mocked_read:
            events = fetch_backend_events(
                "http://127.0.0.1:5000",
                page_size=2,
            )

        self.assertEqual(3, len(events))
        self.assertIn("offset=0", mocked_read.call_args_list[1].args[0])
        self.assertIn("offset=2", mocked_read.call_args_list[2].args[0])

    def test_repeated_page_reports_missing_backend_pagination(self):
        repeated = [
            sample_event(event_id="9f7648bc-6797-4db1-b50a-71bb288c0001")
        ]
        with patch(
            "dataset.prepare_dataset._read_json",
            side_effect=[
                {"total_events": 2},
                {"events": repeated},
                {"events": repeated},
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "offset pagination"):
                fetch_backend_events(
                    "http://127.0.0.1:5000",
                    page_size=1,
                )


if __name__ == "__main__":
    unittest.main()
