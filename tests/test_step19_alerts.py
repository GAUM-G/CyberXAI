"""Focused tests for Step 19 IDS-to-n8n alert enrichment."""

from __future__ import annotations

import copy
import json
import unittest

from simulation.n8n import AlertDeduplicator, normalize_record


def sample_ids_result(
    *,
    threat_level: str = "Critical",
    prediction: str = "attack",
    attack_type: str = "sql_injection",
    confidence: object = 0.93,
) -> dict[str, object]:
    return {
        "ids_result_schema_version": "1.0",
        "hybrid_ids_version": "1.2",
        "event_id": "5a9d7628-8cec-482a-98f2-0a88a53ebf6d",
        "timestamp": "2026-07-28T08:15:00+00:00",
        "source_ip": "127.0.0.1",
        "destination_port": 8080,
        "service": "http",
        "event": "http_search_sql_injection",
        "attack_type": attack_type,
        "prediction": prediction,
        "confidence": confidence,
        "anomaly_score": 0.04,
        "model_used": "rules",
        "threat_level": threat_level,
        "threat_score": 91,
        "request_path": "/search",
        "fusion_reason": "deterministic rule matched",
        "xai": {
            "human_reason": {
                "summary": "A sanitized SQL security pattern matched."
            },
            "privacy": {
                "raw_payload_included": False,
                "source_ip_included": False,
                "credentials_included": False,
            },
        },
        "integration": {
            "raw_payload_included": False,
            "credentials_included": False,
            "producer_attack_type_used_as_prediction": False,
        },
    }


class Step19AlertTests(unittest.TestCase):
    def test_critical_ids_alert_contains_all_required_fields(self) -> None:
        payload = normalize_record(sample_ids_result(), source="ids")

        self.assertTrue(payload["alert_eligible"])
        self.assertEqual(payload["severity_label"], "Critical")
        self.assertEqual(payload["severity"], "critical")
        self.assertEqual(payload["attack_type"], "sql_injection")
        self.assertEqual(payload["source_ip"], "127.0.0.1")
        self.assertEqual(payload["target_service"], "http")
        self.assertEqual(payload["confidence"], 0.93)
        self.assertEqual(payload["confidence_percent"], 93.0)
        self.assertEqual(
            payload["detection_reason"],
            "A sanitized SQL security pattern matched.",
        )
        self.assertIn("affected web route", payload["recommended_action"])
        self.assertEqual(payload["timestamp"], "2026-07-28T08:15:00+00:00")

    def test_only_high_and_critical_attack_predictions_are_immediate(self) -> None:
        for level in ("High", "Critical"):
            with self.subTest(level=level):
                payload = normalize_record(
                    sample_ids_result(threat_level=level),
                    source="ids",
                )
                self.assertTrue(payload["alert_eligible"])

        for level in ("Medium", "Low"):
            with self.subTest(level=level):
                payload = normalize_record(
                    sample_ids_result(threat_level=level),
                    source="ids",
                )
                self.assertFalse(payload["alert_eligible"])

        normal_payload = normalize_record(
            sample_ids_result(threat_level="Critical", prediction="normal"),
            source="ids",
        )
        self.assertFalse(normal_payload["alert_eligible"])

    def test_alert_context_removes_raw_and_credential_fields(self) -> None:
        record = sample_ids_result()
        record["payload"] = {
            "query": "private-query",
            "password": "never-copy-this-secret",
        }
        record["metadata"] = {"authorization": "private-bearer-value"}
        record["username"] = "private-user"
        record["components"] = {
            "nested": {
                "credentials": {"password": "nested-secret"},
                "safe_finding": "rule matched",
            }
        }

        payload = normalize_record(record, source="ids")
        serialized = json.dumps(payload)

        self.assertNotIn("never-copy-this-secret", serialized)
        self.assertNotIn("private-bearer-value", serialized)
        self.assertNotIn("private-user", serialized)
        self.assertNotIn("nested-secret", serialized)
        self.assertIn("rule matched", serialized)
        self.assertFalse(payload["privacy"]["raw_payload_included"])
        self.assertFalse(payload["privacy"]["credentials_included"])

    def test_detection_reason_has_safe_fallback(self) -> None:
        record = sample_ids_result()
        record["xai"] = {"human_reason": {"summary": ""}}
        payload = normalize_record(record, source="ids")
        self.assertEqual(
            payload["detection_reason"],
            "deterministic rule matched",
        )

        record["fusion_reason"] = ""
        fallback = normalize_record(record, source="ids")
        self.assertIn("Hybrid IDS classified", fallback["detection_reason"])

    def test_recommended_actions_cover_supported_attack_types(self) -> None:
        cases = {
            "ssh_bruteforce": "authentication logs",
            "ftp_bruteforce": "authentication logs",
            "sql_injection": "database-facing input controls",
            "xss": "content security policy",
            "directory_scanning": "exposed files or directories",
            "port_scanning": "probed services and ports",
            "unknown_attack": "sanitized IDS evidence",
        }

        for attack_type, expected_text in cases.items():
            with self.subTest(attack_type=attack_type):
                payload = normalize_record(
                    sample_ids_result(attack_type=attack_type),
                    source="ids",
                )
                self.assertIn(expected_text, payload["recommended_action"])

    def test_invalid_confidence_is_not_formatted(self) -> None:
        for confidence in (True, "not-a-number", -0.1, 1.1, float("inf")):
            with self.subTest(confidence=confidence):
                payload = normalize_record(
                    sample_ids_result(confidence=confidence),
                    source="ids",
                )
                self.assertIsNone(payload["confidence_percent"])

    def test_existing_raw_adapter_contract_is_unchanged(self) -> None:
        raw_record = {
            "timestamp": "2026-07-28T08:15:00+00:00",
            "source_ip": "127.0.0.1",
            "service": "ftp",
            "event": "ftp_login_failed",
            "attack_type": "ftp_bruteforce",
            "severity": "critical",
            "payload": {"username": "admin", "password": "test"},
            "metadata": {"attempt_count": 5},
        }
        original = copy.deepcopy(raw_record)

        payload = normalize_record(raw_record, source="raw")

        self.assertEqual(raw_record, original)
        self.assertEqual(payload["severity"], "critical")
        self.assertEqual(payload["ip"], "127.0.0.1")
        self.assertEqual(payload["type"], "ftp")
        self.assertEqual(payload["attack_type"], "ftp_bruteforce")

    def test_same_alert_group_is_suppressed_within_five_minutes(self) -> None:
        deduplicator = AlertDeduplicator()
        first = normalize_record(sample_ids_result(), source="ids")
        repeated_record = sample_ids_result()
        repeated_record["event_id"] = "different-event-id"
        repeated_record["request_path"] = "/login"
        repeated = normalize_record(repeated_record, source="ids")

        self.assertFalse(deduplicator.is_duplicate(first, now=100.0))
        deduplicator.mark_sent(first, now=100.0)
        self.assertTrue(deduplicator.is_duplicate(repeated, now=100.001))

    def test_different_attack_type_or_service_is_not_suppressed(self) -> None:
        deduplicator = AlertDeduplicator()
        sql_alert = normalize_record(sample_ids_result(), source="ids")
        deduplicator.mark_sent(sql_alert, now=100.0)

        xss_alert = normalize_record(
            sample_ids_result(attack_type="xss"),
            source="ids",
        )
        ftp_record = sample_ids_result()
        ftp_record["service"] = "ftp"
        ftp_alert = normalize_record(ftp_record, source="ids")

        self.assertFalse(deduplicator.is_duplicate(xss_alert, now=101.0))
        self.assertFalse(deduplicator.is_duplicate(ftp_alert, now=101.0))

    def test_alert_group_is_allowed_after_five_minutes(self) -> None:
        deduplicator = AlertDeduplicator()
        alert = normalize_record(sample_ids_result(), source="ids")
        deduplicator.mark_sent(alert, now=100.0)

        self.assertTrue(deduplicator.is_duplicate(alert, now=399.999))
        self.assertFalse(deduplicator.is_duplicate(alert, now=400.0))

    def test_ineligible_ids_result_does_not_reserve_deduplication_key(self) -> None:
        deduplicator = AlertDeduplicator()
        low_alert = normalize_record(
            sample_ids_result(threat_level="Low"),
            source="ids",
        )
        critical_alert = normalize_record(sample_ids_result(), source="ids")

        deduplicator.mark_sent(low_alert, now=100.0)
        self.assertFalse(deduplicator.is_duplicate(critical_alert, now=101.0))


if __name__ == "__main__":
    unittest.main()
