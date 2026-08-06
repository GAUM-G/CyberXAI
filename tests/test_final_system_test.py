from __future__ import annotations

import unittest

from scripts.final_system_test import (
    AGENT_RUN_ORDER,
    _validate_ids_result,
)


class FinalSystemContractTests(unittest.TestCase):
    def test_complete_result_contract_passes(self):
        result = {
            "prediction": "attack",
            "threat_level": "Critical",
            "confidence": 0.97,
            "xai": {
                "human_reason": {"summary": "A sanitized SQL pattern matched."},
                "privacy": {
                    "raw_payload_included": False,
                    "source_ip_included": False,
                    "credentials_included": False,
                },
            },
            "agents": {
                "run_order": AGENT_RUN_ORDER,
                **{name: {"status": "completed"} for name in AGENT_RUN_ORDER},
                "safety": {"host_firewall_changed": False},
            },
        }
        self.assertEqual([], _validate_ids_result(result))

    def test_unsafe_or_incomplete_result_fails(self):
        errors = _validate_ids_result(
            {
                "prediction": "maybe",
                "threat_level": "Urgent",
                "confidence": "high",
                "xai": {"privacy": {"raw_payload_included": True}},
                "agents": {"run_order": []},
            }
        )
        self.assertIn("prediction", errors)
        self.assertIn("threat_level", errors)
        self.assertIn("xai.privacy", errors)
        self.assertIn("agents.run_order", errors)


if __name__ == "__main__":
    unittest.main()
