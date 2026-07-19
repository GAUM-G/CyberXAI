from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.event_schema import COMMON_EVENT_FIELDS, build_common_event, validate_common_event
from core import logger


class CommonEventSchemaTests(unittest.TestCase):
    def test_common_fields_are_present_for_all_honeypot_services(self) -> None:
        cases = (
            ("ssh", "authentication", 2222),
            ("ftp", "command", 2121),
            ("http", "request", 8080),
        )

        for service, event_type, destination_port in cases:
            with self.subTest(service=service):
                record = build_common_event(
                    source_ip="127.0.0.1",
                    source_port=49152,
                    destination_port=destination_port,
                    service=service,
                    protocol=service,
                    event=f"{service}_test_event",
                    event_type=event_type,
                    attack_type="test_activity",
                    status="observed",
                    payload={"test": True},
                )

                self.assertEqual(set(COMMON_EVENT_FIELDS), set(record))
                self.assertEqual([], validate_common_event(record))

    def test_legacy_fields_and_values_are_preserved(self) -> None:
        record = build_common_event(
            source_ip="192.0.2.10",
            service="ssh",
            event="ssh_login_attempt",
            attack_type="authentication_probe",
            payload={"username": "admin", "password": "test"},
            metadata={"attempt_count": 1},
            severity="warning",
        )

        self.assertEqual("ssh_login_attempt", record["event"])
        self.assertEqual("authentication_probe", record["attack_type"])
        self.assertEqual("warning", record["severity"])
        self.assertEqual("admin", record["username"])
        self.assertEqual(2222, record["destination_port"])

    def test_event_ids_are_unique(self) -> None:
        values = {
            build_common_event(
                source_ip="127.0.0.1",
                service="http",
                event="http_index_request",
                attack_type="web_activity",
            )["event_id"]
            for _ in range(10)
        }
        self.assertEqual(10, len(values))

    def test_request_fields_can_be_derived_from_existing_metadata(self) -> None:
        record = build_common_event(
            source_ip="127.0.0.1",
            service="http",
            event="http_search_xss",
            attack_type="xss",
            payload="<script>alert(1)</script>",
            metadata={"method": "get", "path": "/search", "source_port": "50100"},
            severity="warning",
            event_type="attack",
            status="detected",
        )

        self.assertEqual("GET", record["request_method"])
        self.assertEqual("/search", record["request_path"])
        self.assertEqual(50100, record["source_port"])

    def test_invalid_severity_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_common_event(
                source_ip="127.0.0.1",
                service="ftp",
                event="ftp_connection",
                attack_type="connection_probe",
                severity="danger",
            )


class LoggerCompatibilityTests(unittest.TestCase):
    def test_old_log_event_call_still_writes_a_valid_common_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_log_file = logger.LOG_FILE
            old_webhook = logger.N8N_WEBHOOK_URL
            old_collector_url = logger.EVENT_COLLECTOR_URL
            logger.LOG_FILE = Path(temp_dir) / "honeypot_events.jsonl"
            logger.N8N_WEBHOOK_URL = ""
            logger.EVENT_COLLECTOR_URL = ""
            try:
                record = logger.log_event(
                    source_ip="127.0.0.1",
                    service="ssh",
                    event="ssh_login_attempt",
                    attack_type="authentication_probe",
                    payload={"username": "admin", "password": "test"},
                    metadata={"attempt_count": 1},
                    severity="info",
                )

                written = json.loads(logger.LOG_FILE.read_text(encoding="utf-8").strip())
                self.assertEqual(record, written)
                self.assertEqual([], validate_common_event(written))
            finally:
                logger.LOG_FILE = old_log_file
                logger.N8N_WEBHOOK_URL = old_webhook
                logger.EVENT_COLLECTOR_URL = old_collector_url


if __name__ == "__main__":
    unittest.main()
