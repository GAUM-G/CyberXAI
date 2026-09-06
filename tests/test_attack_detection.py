from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core import logger
from core.attack_detection import PortScanDetector
from core.event_schema import validate_common_event
from dashboard import app as dashboard_module
from simulation.n8n import normalize_record
from simulation.sim_port_scan import _require_loopback


class PortScanDetectorTests(unittest.TestCase):
    def test_telegram_payload_type_uses_honeypot_service(self) -> None:
        payload = normalize_record(
            {
                "source_ip": "127.0.0.1",
                "service": "ftp",
                "event": "ftp_login_success",
                "attack_type": "credential_access",
                "severity": "critical",
                "metadata": {},
            }
        )

        self.assertEqual("ftp", payload["type"])
        self.assertEqual("ftp", payload["service"])
        self.assertEqual("ftp", payload["record"]["type"])
        self.assertEqual("ftp", payload["record"]["service"])
        self.assertEqual("credential_access", payload["attack_type"])

        direct_payload = logger._build_n8n_payload(payload["record"])
        self.assertEqual("ftp", direct_payload["type"])
        self.assertEqual("ftp", direct_payload["service"])
        self.assertEqual("ftp", direct_payload["record"]["type"])

    def test_port_scan_simulator_rejects_external_targets(self) -> None:
        _require_loopback("127.0.0.1")
        _require_loopback("localhost")
        with self.assertRaises(ValueError):
            _require_loopback("192.0.2.50")

    def test_three_distinct_ports_trigger_one_finding(self) -> None:
        detector = PortScanDetector(threshold=3, window_seconds=30)

        self.assertIsNone(detector.register("192.0.2.10", 2222, now=1))
        self.assertIsNone(detector.register("192.0.2.10", 2121, now=2))
        finding = detector.register("192.0.2.10", 8080, now=3)

        self.assertIsNotNone(finding)
        self.assertEqual((2121, 2222, 8080), finding.observed_ports)
        self.assertIsNone(detector.register("192.0.2.10", 8080, now=4))

    def test_repeated_port_does_not_reach_threshold(self) -> None:
        detector = PortScanDetector(threshold=3, window_seconds=30)
        for observed_at in range(1, 6):
            self.assertIsNone(
                detector.register("192.0.2.20", 2222, now=observed_at)
            )

    def test_expired_ports_are_not_counted(self) -> None:
        detector = PortScanDetector(threshold=3, window_seconds=5)
        self.assertIsNone(detector.register("192.0.2.30", 2222, now=1))
        self.assertIsNone(detector.register("192.0.2.30", 2121, now=2))
        self.assertIsNone(detector.register("192.0.2.30", 8080, now=10))


class LoggerPortScanEventTests(unittest.TestCase):
    def test_logger_publishes_valid_port_scan_event(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_log_file = logger.LOG_FILE
            old_webhook = logger.N8N_WEBHOOK_URL
            old_collector_url = logger.EVENT_COLLECTOR_URL
            old_detector = logger._port_scan_detector

            logger.LOG_FILE = Path(temp_dir) / "honeypot_events.jsonl"
            logger.N8N_WEBHOOK_URL = ""
            logger.EVENT_COLLECTOR_URL = ""
            logger._port_scan_detector = PortScanDetector(
                threshold=3,
                window_seconds=30,
            )

            try:
                for service, protocol, port in (
                    ("ssh", "ssh", 2222),
                    ("ftp", "ftp", 2121),
                    ("http", "http", 8080),
                ):
                    logger.log_event(
                        source_ip="192.0.2.40",
                        source_port=51000,
                        destination_port=port,
                        service=service,
                        protocol=protocol,
                        event_type="connection",
                        event=f"{service}_test_connection",
                        attack_type="connection_probe",
                        status="observed",
                        severity="info",
                    )

                records = [
                    json.loads(line)
                    for line in logger.LOG_FILE.read_text(encoding="utf-8").splitlines()
                ]
                alerts = [
                    record
                    for record in records
                    if record.get("attack_type") == "port_scanning"
                ]

                self.assertEqual(4, len(records))
                self.assertEqual(1, len(alerts))
                self.assertEqual("warning", alerts[0]["severity"])
                self.assertEqual("detected", alerts[0]["status"])
                self.assertEqual([2121, 2222, 8080], alerts[0]["payload"]["observed_ports"])
                self.assertEqual([], validate_common_event(alerts[0]))
            finally:
                logger.LOG_FILE = old_log_file
                logger.N8N_WEBHOOK_URL = old_webhook
                logger.EVENT_COLLECTOR_URL = old_collector_url
                logger._port_scan_detector = old_detector


class DashboardPortScanVisibilityTests(unittest.TestCase):
    def test_port_scan_remains_in_expanded_recent_lists(self) -> None:
        events = [
            {
                "timestamp": f"2026-07-19T09:00:{index:02d}+00:00",
                "source_ip": "127.0.0.1",
                "service": "http",
                "event": "http_test_event",
                "attack_type": "web_activity",
                "severity": "info",
                "payload": None,
            }
            for index in range(120)
        ]
        events[99].update(
            {
                "event": "port_scan_detected",
                "attack_type": "port_scanning",
                "severity": "warning",
                "status": "detected",
                "payload": {"observed_ports": [2121, 2222, 8080]},
            }
        )

        old_all_events = dashboard_module._all_events
        old_central_stats = dashboard_module._central_event_stats
        dashboard_module._all_events = lambda limit: events[:limit]
        dashboard_module._central_event_stats = lambda: None
        try:
            client = dashboard_module.create_dashboard_app().test_client()
            monitor_response = client.get("/api/monitor").get_json()
            monitor_events = monitor_response["recent_events"]
            service_events = client.get("/api/honeypot").get_json()["services"]["http"]["recent"]
            dashboard_html = client.get("/").get_data(as_text=True)

            self.assertEqual(100, len(monitor_events))
            self.assertEqual(100, len(service_events))
            self.assertTrue(
                any(event["attack_type"] == "port_scanning" for event in monitor_events)
            )
            self.assertTrue(
                any(event["attack_type"] == "port_scanning" for event in service_events)
            )
            self.assertEqual(1, monitor_response["port_scans_detected"])
            self.assertEqual(
                [2121, 2222, 8080],
                monitor_response["latest_port_scan"]["observed_ports"],
            )
            self.assertIn('id="port-scan-panel"', dashboard_html)
            self.assertIn('id="port-scan-status"', dashboard_html)
            self.assertIn("timeZone:'Asia/Kolkata'", dashboard_html)
            self.assertIn("TIMESTAMP (IST)", dashboard_html)
            self.assertIn("<th>Attack</th>", dashboard_html)
            self.assertIn("Port Scanning", dashboard_html)
        finally:
            dashboard_module._all_events = old_all_events
            dashboard_module._central_event_stats = old_central_stats

    def test_monitor_uses_uncapped_central_statistics(self) -> None:
        old_all_events = dashboard_module._all_events
        old_central_stats = dashboard_module._central_event_stats
        dashboard_module._all_events = lambda limit: [
            {
                "timestamp": "2026-07-19T09:00:00+00:00",
                "source_ip": "127.0.0.1",
                "service": "http",
                "event": "website_decoy_search",
                "attack_type": "web_activity",
                "severity": "info",
                "payload": None,
            }
        ]
        dashboard_module._central_event_stats = lambda: {
            "total_events": 2501,
            "unique_ips": 7,
            "by_service": {"http": 2400, "ssh": 101},
            "by_severity": {"info": 2400, "warning": 100, "critical": 1},
            "by_attack_type": {"web_activity": 2400, "sql_injection": 101},
        }
        try:
            payload = dashboard_module.create_dashboard_app().test_client().get(
                "/api/monitor"
            ).get_json()
            self.assertEqual(2501, payload["total_events"])
            self.assertEqual(7, payload["unique_ips"])
            self.assertEqual(101, payload["threats_detected"])
            self.assertEqual(101, payload["by_attack"]["sql_injection"])
            self.assertEqual(1, len(payload["recent_events"]))
        finally:
            dashboard_module._all_events = old_all_events
            dashboard_module._central_event_stats = old_central_stats


if __name__ == "__main__":
    unittest.main()
