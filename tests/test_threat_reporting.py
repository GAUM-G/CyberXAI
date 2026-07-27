"""Focused tests for Step 14 level-based threat reporting."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from machine_learning.threat_reporting import (
    THREAT_LEVEL_RANGES,
    ThreatReporter,
    threat_level_for_score,
)


START = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)


def make_event(
    *,
    timestamp: datetime = START,
    source_ip: str = "192.0.2.10",
    service: str = "http",
) -> dict[str, object]:
    return {
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "source_ip": source_ip,
        "service": service,
    }


def make_result(
    *,
    service: str = "http",
    attack_type: str = "normal",
    prediction: str = "normal",
    confidence: float | None = 0.95,
    anomaly_score: float = -0.05,
) -> dict[str, object]:
    return {
        "service": service,
        "attack_type": attack_type,
        "prediction": prediction,
        "confidence": confidence,
        "anomaly_score": anomaly_score,
    }


class ThreatLevelRangeTests(unittest.TestCase):
    def test_exact_score_boundaries_cover_all_four_levels(self) -> None:
        self.assertEqual(
            THREAT_LEVEL_RANGES,
            (
                ("Low", 0, 24),
                ("Medium", 25, 49),
                ("High", 50, 74),
                ("Critical", 75, 100),
            ),
        )
        expected = {
            0: "Low",
            24: "Low",
            25: "Medium",
            49: "Medium",
            50: "High",
            74: "High",
            75: "Critical",
            100: "Critical",
        }
        for score, level in expected.items():
            with self.subTest(score=score):
                self.assertEqual(threat_level_for_score(score), level)

    def test_invalid_scores_are_rejected(self) -> None:
        for score in (-1, 101, True, 50.0):
            with self.subTest(score=score):
                with self.assertRaises(ValueError):
                    threat_level_for_score(score)  # type: ignore[arg-type]


class ThreatReporterTests(unittest.TestCase):
    def test_normal_event_is_low_and_does_not_count_as_incident(self) -> None:
        reporter = ThreatReporter()
        report = reporter.assess(make_event(), make_result())

        self.assertEqual(report["threat_level"], "Low")
        self.assertEqual(report["threat_score"], 0)
        repetition = report["threat_factors"][2]
        self.assertEqual(repetition["factor"], "repetition")
        self.assertEqual(repetition["value"], 0)

    def test_unknown_anomaly_without_confidence_is_medium(self) -> None:
        report = ThreatReporter().assess(
            make_event(),
            make_result(
                attack_type="other_anomaly",
                prediction="attack",
                confidence=None,
                anomaly_score=0.06,
            ),
        )

        self.assertEqual(report["threat_level"], "Medium")
        self.assertEqual(report["threat_score"], 35)
        confidence = report["threat_factors"][1]
        self.assertIsNone(confidence["value"])
        self.assertEqual(confidence["points"], 0)

    def test_known_attack_is_high(self) -> None:
        report = ThreatReporter().assess(
            make_event(),
            make_result(
                attack_type="xss",
                prediction="attack",
                confidence=0.93,
                anomaly_score=0.02,
            ),
        )

        self.assertEqual(report["threat_level"], "High")
        self.assertEqual(report["threat_score"], 68)

    def test_repetition_escalates_same_source_incident_to_critical(self) -> None:
        reporter = ThreatReporter()
        result = make_result(
            service="ssh",
            attack_type="ssh_bruteforce",
            prediction="attack",
            confidence=0.89,
            anomaly_score=-0.01,
        )
        reports = [
            reporter.assess(
                make_event(
                    timestamp=START + timedelta(seconds=index),
                    service="ssh",
                ),
                result,
            )
            for index in range(3)
        ]

        self.assertEqual(reports[0]["threat_level"], "High")
        self.assertEqual(reports[1]["threat_level"], "High")
        self.assertEqual(reports[2]["threat_level"], "Critical")
        self.assertEqual(reports[2]["threat_score"], 78)
        self.assertEqual(reports[2]["threat_factors"][2]["value"], 3)

    def test_repetition_isolated_by_source_service_and_attack_type(self) -> None:
        reporter = ThreatReporter()
        result = make_result(
            attack_type="sql_injection",
            prediction="attack",
            confidence=0.80,
            anomaly_score=0.0,
        )
        reporter.assess(make_event(), result)
        different_source = reporter.assess(
            make_event(
                timestamp=START + timedelta(seconds=1),
                source_ip="192.0.2.11",
            ),
            result,
        )
        different_service = reporter.assess(
            make_event(
                timestamp=START + timedelta(seconds=2),
                service="ftp",
            ),
            {**result, "service": "ftp"},
        )
        different_attack = reporter.assess(
            make_event(timestamp=START + timedelta(seconds=3)),
            {
                **result,
                "attack_type": "xss",
            },
        )

        for report in (
            different_source,
            different_service,
            different_attack,
        ):
            self.assertEqual(report["threat_factors"][2]["value"], 1)

    def test_incidents_outside_sixty_seconds_do_not_escalate(self) -> None:
        reporter = ThreatReporter()
        result = make_result(
            attack_type="sql_injection",
            prediction="attack",
            confidence=0.90,
            anomaly_score=0.0,
        )
        reporter.assess(make_event(), result)
        report = reporter.assess(
            make_event(timestamp=START + timedelta(seconds=61)),
            result,
        )

        self.assertEqual(report["threat_factors"][2]["value"], 1)
        self.assertEqual(report["threat_factors"][2]["points"], 0)

    def test_anomaly_score_contributes_to_attack_score(self) -> None:
        reporter = ThreatReporter()
        baseline = reporter.assess(
            make_event(source_ip="192.0.2.20"),
            make_result(
                attack_type="other_anomaly",
                prediction="attack",
                confidence=None,
                anomaly_score=-0.01,
            ),
        )
        strong_anomaly = reporter.assess(
            make_event(source_ip="192.0.2.21"),
            make_result(
                attack_type="other_anomaly",
                prediction="attack",
                confidence=None,
                anomaly_score=0.16,
            ),
        )

        self.assertEqual(
            strong_anomaly["threat_score"] - baseline["threat_score"],
            15,
        )

    def test_every_agreed_factor_is_exposed(self) -> None:
        report = ThreatReporter().assess(
            make_event(service="ftp"),
            make_result(
                service="ftp",
                attack_type="ftp_bruteforce",
                prediction="attack",
                confidence=0.91,
                anomaly_score=0.04,
            ),
        )

        self.assertEqual(
            [factor["factor"] for factor in report["threat_factors"]],
            [
                "attack_type",
                "confidence",
                "repetition",
                "service",
                "anomaly_score",
            ],
        )
        self.assertEqual(
            report["threat_score"],
            sum(
                int(factor["points"])
                for factor in report["threat_factors"]
            ),
        )

    def test_non_finite_or_out_of_range_values_are_rejected(self) -> None:
        reporter = ThreatReporter()
        invalid_results = (
            make_result(
                prediction="attack",
                confidence=1.1,
            ),
            make_result(
                prediction="attack",
                anomaly_score=float("nan"),
            ),
        )
        for result in invalid_results:
            with self.subTest(result=result):
                with self.assertRaises(ValueError):
                    reporter.assess(make_event(), result)


if __name__ == "__main__":
    unittest.main()
