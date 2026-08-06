"""Focused safety tests for controlled dataset expansion."""

from __future__ import annotations

import ipaddress
import random
import unittest

from dataset.labeling import APPROVED_LABELS, assign_label
from simulation.expand_dataset import (
    _ISOLATED_PROBE_MAX_ORDINAL,
    _event_spec,
    _isolated_probe_ip,
)


class DatasetExpansionTests(unittest.TestCase):
    """Verify that generated classes remain valid and behaviourally distinct."""

    def test_each_event_spec_receives_its_requested_label(self) -> None:
        for label in APPROVED_LABELS:
            with self.subTest(label=label):
                spec = _event_spec(label, 0, random.Random(20260726))
                self.assertEqual(assign_label(spec), label)

    def test_other_anomaly_uses_unique_source_per_probe(self) -> None:
        specs = [
            _event_spec(
                "other_anomaly",
                ordinal,
                random.Random(20260726 + ordinal),
            )
            for ordinal in range(510)
        ]

        source_ips = [spec["source_ip"] for spec in specs]
        session_ids = [spec["session_id"] for spec in specs]

        self.assertEqual(len(source_ips), len(set(source_ips)))
        self.assertEqual(len(session_ids), len(set(session_ids)))

    def test_other_anomaly_matches_pre_threshold_probe_semantics(self) -> None:
        spec = _event_spec(
            "other_anomaly",
            42,
            random.Random(20260726),
        )

        self.assertEqual(spec["event"], "ssh_login_attempt")
        self.assertEqual(spec["attack_type"], "authentication_probe")
        self.assertEqual(spec["severity"], "info")
        self.assertEqual(spec["status"], "failed")
        self.assertEqual(spec["metadata"]["attempt_count"], 1)
        self.assertEqual(spec["metadata"]["threshold"], 3)
        self.assertEqual(spec["metadata"]["probe_mode"], "isolated")
        self.assertEqual(assign_label(spec), "other_anomaly")

    def test_isolated_probe_addresses_are_non_public_ipv4(self) -> None:
        for ordinal in (0, 1, 253, 254, 509):
            with self.subTest(ordinal=ordinal):
                address = ipaddress.ip_address(
                    _isolated_probe_ip(ordinal)
                )
                self.assertEqual(address.version, 4)
                self.assertFalse(address.is_global)

    def test_isolated_probe_address_pool_rejects_invalid_ordinals(self) -> None:
        for ordinal in (-1, _ISOLATED_PROBE_MAX_ORDINAL):
            with self.subTest(ordinal=ordinal):
                with self.assertRaises(ValueError):
                    _isolated_probe_ip(ordinal)

    def test_ssh_bruteforce_generator_remains_unchanged(self) -> None:
        first = _event_spec(
            "ssh_bruteforce",
            0,
            random.Random(20260726),
        )
        repeated_source = _event_spec(
            "ssh_bruteforce",
            28,
            random.Random(20260727),
        )

        self.assertEqual(first["source_ip"], repeated_source["source_ip"])
        self.assertEqual(first["event"], "ssh_bruteforce_attempt")
        self.assertEqual(first["severity"], "warning")
        self.assertGreaterEqual(first["metadata"]["attempt_count"], 3)
        self.assertEqual(assign_label(first), "ssh_bruteforce")


if __name__ == "__main__":
    unittest.main()
