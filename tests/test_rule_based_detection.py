from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from rule_based_detection.detector import RuleBasedDetector
from rule_based_detection.run_detection import detect_rows, run


def event(number: int = 1, **overrides):
    value = {
        "event_id": f"9f7648bc-6797-4db1-b50a-71bb288c{number:04d}",
        "timestamp_utc": f"2026-07-25T04:30:{number:02d}Z",
        "source_ip_hash": "source-a",
        "service": "ssh",
        "event_type": "authentication",
        "event": "ssh_login_attempt",
        "status": "failed",
        "request_path": "",
        "payload_json": "{}",
        "metadata_json": "{}",
        "label": "other_anomaly",
    }
    value.update(overrides)
    return value


class RepeatedLoginFailureTests(unittest.TestCase):
    def test_third_failure_in_sixty_seconds_triggers_once(self):
        detector = RuleBasedDetector()

        self.assertEqual([], detector.inspect(event(1)))
        self.assertEqual([], detector.inspect(event(2)))
        findings = detector.inspect(event(3))
        self.assertEqual(1, len(findings))
        self.assertEqual("ssh_bruteforce", findings[0].attack_type)
        self.assertEqual(("repeated_login_failures",), findings[0].matched_rules)
        self.assertEqual(3, findings[0].evidence["failure_count"])

        self.assertEqual([], detector.inspect(event(4)))

    def test_sources_and_services_are_isolated(self):
        detector = RuleBasedDetector()
        rows = [
            event(1, source_ip_hash="source-a", service="ssh"),
            event(2, source_ip_hash="source-b", service="ssh"),
            event(3, source_ip_hash="source-a", service="ftp"),
            event(4, source_ip_hash="source-a", service="ssh"),
        ]
        self.assertEqual([], [finding for row in rows for finding in detector.inspect(row)])

    def test_http_login_names_with_underscores_are_correlated(self):
        detector = RuleBasedDetector()
        findings = []
        for number in range(1, 4):
            findings.extend(
                detector.inspect(
                    event(
                        number,
                        service="http",
                        event_type="authentication",
                        event="website_login",
                    )
                )
            )
        self.assertEqual(1, len(findings))
        self.assertEqual("http_bruteforce", findings[0].attack_type)

    def test_old_failures_expire_and_success_resets_state(self):
        detector = RuleBasedDetector()
        detector.inspect(event(1, timestamp_utc="2026-07-25T04:30:00Z"))
        detector.inspect(event(2, timestamp_utc="2026-07-25T04:30:20Z"))
        self.assertEqual(
            [],
            detector.inspect(event(3, timestamp_utc="2026-07-25T04:31:21Z")),
        )

        detector.inspect(event(4, timestamp_utc="2026-07-25T04:31:22Z"))
        detector.inspect(
            event(
                5,
                timestamp_utc="2026-07-25T04:31:23Z",
                status="success",
            )
        )
        self.assertEqual(
            [],
            detector.inspect(event(6, timestamp_utc="2026-07-25T04:31:24Z")),
        )

    def test_missing_timestamp_cannot_create_a_correlated_finding(self):
        detector = RuleBasedDetector()
        for number in range(1, 5):
            self.assertEqual(
                [],
                detector.inspect(event(number, timestamp_utc="not-a-time")),
            )


class InjectionRuleTests(unittest.TestCase):
    def test_sqli_detects_plain_and_encoded_tautologies(self):
        for payload in (
            '{"username":"admin\' OR \'1\'=\'1"}',
            "%27%20OR%201%3D1--",
            "1 UNION SELECT password FROM users",
        ):
            with self.subTest(payload=payload):
                findings = RuleBasedDetector().inspect(
                    event(
                        1,
                        service="http",
                        event_type="request",
                        event="website_login",
                        status="observed",
                        payload_json=payload,
                    )
                )
                self.assertIn(
                    "sql_injection",
                    [finding.attack_type for finding in findings],
                )

    def test_xss_detects_plain_encoded_and_event_handler_payloads(self):
        for payload in (
            "<script>alert(1)</script>",
            "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            '<img src=x onerror="alert(1)">',
        ):
            with self.subTest(payload=payload):
                findings = RuleBasedDetector().inspect(
                    event(
                        1,
                        service="http",
                        event_type="request",
                        event="website_search",
                        status="observed",
                        request_path=payload,
                    )
                )
                self.assertIn("xss", [finding.attack_type for finding in findings])

    def test_benign_web_content_is_not_detected(self):
        benign = event(
            1,
            service="http",
            event_type="request",
            event="website_search",
            status="observed",
            request_path="/search?q=union+festival+script+writing",
            payload_json='{"message":"select a report from the menu"}',
        )
        self.assertEqual([], RuleBasedDetector().inspect(benign))

    def test_ordinary_unequal_boolean_comparison_is_not_sqli(self):
        ordinary = event(
            1,
            service="http",
            event_type="request",
            event="website_search",
            status="observed",
            request_path="/search?q=active+and+role=user",
        )
        self.assertEqual([], RuleBasedDetector().inspect(ordinary))

    def test_one_event_can_emit_independent_sqli_and_xss_findings(self):
        findings = RuleBasedDetector().inspect(
            event(
                1,
                service="http",
                event_type="request",
                event="website_login",
                status="observed",
                payload_json=(
                    '{"username":"admin\' OR \'1\'=\'1",'
                    '"note":"<script>alert(1)</script>"}'
                ),
            )
        )
        self.assertEqual(
            {"sql_injection", "xss"},
            {finding.attack_type for finding in findings},
        )


class SafetyAndBatchTests(unittest.TestCase):
    def test_labels_never_change_rule_decisions(self):
        original = [
            event(1),
            event(2),
            event(3),
            event(
                4,
                service="http",
                status="observed",
                payload_json="' OR 1=1",
            ),
        ]
        changed = deepcopy(original)
        for index, row in enumerate(changed):
            row["label"] = ["normal", "xss", "sql_injection", "ftp_bruteforce"][index]

        first, _ = detect_rows(original)
        second, _ = detect_rows(changed)
        self.assertEqual(first, second)

    def test_future_rows_do_not_change_earlier_findings(self):
        prefix = [
            event(
                1,
                service="http",
                status="observed",
                payload_json="<script>alert(1)</script>",
            ),
            event(2),
            event(3),
        ]
        extended = [
            *prefix,
            event(4),
            event(5, payload_json="' UNION SELECT password FROM users"),
        ]

        prefix_findings, _ = detect_rows(prefix)
        extended_findings, _ = detect_rows(extended)
        earlier_ids = {row["event_id"] for row in prefix}
        self.assertEqual(
            prefix_findings,
            [
                finding
                for finding in extended_findings
                if finding["event_id"] in earlier_ids
            ],
        )

    def test_findings_never_contain_raw_payload_or_source_ip(self):
        marker = "DO-NOT-EMIT-THIS-PAYLOAD"
        raw_ip = "203.0.113.99"
        finding = RuleBasedDetector().inspect(
            {
                **event(
                    1,
                    service="http",
                    status="observed",
                    payload_json=f"{marker}<script>alert(1)</script>",
                ),
                "source_ip_hash": "",
                "source_ip": raw_ip,
            }
        )[0]
        serialized = json.dumps(finding.to_dict())
        self.assertNotIn(marker, serialized)
        self.assertNotIn(raw_ip, serialized)
        self.assertFalse(finding.evidence["raw_text_included"])

    def test_runner_deduplicates_sorts_and_writes_safe_manifest(self):
        rows = [
            event(
                4,
                timestamp_utc="2026-07-25T04:30:04Z",
                service="http",
                status="observed",
                payload_json="<script>alert(1)</script>",
            ),
            event(3, timestamp_utc="2026-07-25T04:30:03Z"),
            event(1, timestamp_utc="2026-07-25T04:30:01Z"),
            event(2, timestamp_utc="2026-07-25T04:30:02Z"),
            event(2, timestamp_utc="2026-07-25T04:30:02Z"),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            manifest = run(rows, output_dir=output_dir, source="unit-test")

            self.assertEqual(5, manifest["input_rows"])
            self.assertEqual(4, manifest["unique_rows"])
            self.assertEqual(1, manifest["duplicate_event_ids_removed"])
            self.assertEqual(2, manifest["findings"])
            self.assertEqual(
                {"ssh_bruteforce": 1, "xss": 1},
                manifest["counts_by_attack_type"],
            )
            self.assertFalse(
                manifest["safety"]["input_labels_used_for_decisions"]
            )
            self.assertFalse(manifest["safety"]["future_events_used"])
            self.assertFalse(
                manifest["safety"][
                    "raw_payload_or_request_text_written_to_findings"
                ]
            )

            findings_path = output_dir / "rule_findings.jsonl"
            manifest_path = output_dir / "rule_detection_manifest.json"
            self.assertTrue(findings_path.is_file())
            self.assertTrue(manifest_path.is_file())
            self.assertEqual(
                manifest["findings"],
                len(
                    [
                        line
                        for line in findings_path.read_text(
                            encoding="utf-8"
                        ).splitlines()
                        if line
                    ]
                ),
            )

    def test_runner_orders_timezone_offsets_by_actual_instant(self):
        rows = [
            event(3, timestamp_utc="2026-07-25T10:01:00+05:30"),
            event(1, timestamp_utc="2026-07-25T04:30:00Z"),
            event(2, timestamp_utc="2026-07-25T10:00:30+05:30"),
        ]
        findings, _ = detect_rows(rows)
        self.assertEqual(1, len(findings))
        self.assertEqual(rows[0]["event_id"], findings[0]["event_id"])


if __name__ == "__main__":
    unittest.main()
