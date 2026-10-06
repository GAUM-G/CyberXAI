"""Focused Step 21 safety, runtime-state and dashboard integration tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from core.simulated_ips import (
    AUTOMATIC_HOST_BLOCKING,
    HOST_FIREWALL_CHANGED,
    IPS_MODE,
    annotate_event_with_simulated_ips,
    apply_simulated_rate_limit,
    get_simulated_response,
    load_simulated_ips_state,
)
from simulation.n8n import normalize_record


ROOT = Path(__file__).resolve().parents[1]


def write_state(path: Path, **overrides: object) -> None:
    value = {
        "schema_version": "1.0",
        "mode": "simulation",
        "automatic_host_blocking": False,
        "host_firewall_changed": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "simulated_blocks": [],
        "rate_limits": [],
        "terminated_sessions": [],
        **overrides,
    }
    path.write_text(json.dumps(value), encoding="utf-8")


class Step21SimulatedIPSTests(unittest.TestCase):
    def test_safety_defaults_are_hard_disabled(self) -> None:
        self.assertEqual(IPS_MODE, "simulation")
        self.assertFalse(AUTOMATIC_HOST_BLOCKING)
        self.assertFalse(HOST_FIREWALL_CHANGED)

        config = (ROOT / "config" / "config.yaml").read_text(encoding="utf-8")
        env_example = (
            ROOT / "website" / "backend" / ".env.example"
        ).read_text(encoding="utf-8")
        self.assertIn('mode: "simulation"', config)
        self.assertIn("automatic_host_blocking: false", config)
        self.assertIn("AUTOMATIC_HOST_BLOCKING=false", env_example)

    def test_non_simulation_or_host_blocking_state_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            write_state(
                path,
                mode="active",
                automatic_host_blocking=True,
                host_firewall_changed=True,
                simulated_blocks=[{"source_ip": "10.0.0.5", "service": "ssh"}],
            )
            state = load_simulated_ips_state(path)
            self.assertEqual(state["mode"], "simulation")
            self.assertFalse(state["automatic_host_blocking"])
            self.assertFalse(state["host_firewall_changed"])
            self.assertEqual(state["simulated_blocks"], [])

    def test_simulated_block_marks_later_event_without_dropping_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            write_state(
                path,
                simulated_blocks=[
                    {
                        "action_id": 12,
                        "event_id": "event-1",
                        "source_ip": "10.0.0.8",
                        "service": "ssh",
                        "expires_at": expires,
                    }
                ],
            )
            response = get_simulated_response(
                "10.0.0.8", "ssh", "session-2", state_file=path
            )
            self.assertTrue(response["would_have_been_blocked"])
            self.assertFalse(response["host_firewall_changed"])

            record = {
                "source_ip": "10.0.0.8",
                "service": "ssh",
                "session_id": "session-2",
                "metadata": {"attempt_count": 9},
            }
            returned = annotate_event_with_simulated_ips(record, state_file=path)
            self.assertIs(returned, record)
            self.assertEqual(returned["metadata"]["attempt_count"], 9)
            self.assertTrue(
                returned["metadata"]["ips"]["would_have_been_blocked"]
            )

    def test_rate_limit_is_bounded_to_one_second(self) -> None:
        delays: list[float] = []
        seconds = apply_simulated_rate_limit(
            {"rate_limited": True, "rate_limit_delay_ms": 5000},
            sleeper=delays.append,
        )
        self.assertEqual(seconds, 1.0)
        self.assertEqual(delays, [1.0])

    def test_rate_limit_and_session_termination_are_targeted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            write_state(
                path,
                rate_limits=[
                    {
                        "action_id": 21,
                        "source_ip": "10.0.0.9",
                        "service": "ftp",
                        "rate_limit_delay_ms": 750,
                        "expires_at": expires,
                    }
                ],
                terminated_sessions=[
                    {
                        "action_id": 22,
                        "source_ip": "10.0.0.9",
                        "service": "ftp",
                        "session_id": "selected-session",
                        "expires_at": expires,
                    }
                ],
            )
            selected = get_simulated_response(
                "10.0.0.9", "ftp", "selected-session", state_file=path
            )
            other = get_simulated_response(
                "10.0.0.9", "ftp", "other-session", state_file=path
            )
            unrelated = get_simulated_response(
                "10.0.0.9", "ssh", "selected-session", state_file=path
            )
            different_ip = get_simulated_response(
                "10.0.0.10", "ftp", "selected-session", state_file=path
            )
            self.assertTrue(selected["rate_limited"])
            self.assertTrue(selected["session_terminated"])
            self.assertEqual(selected["rate_limit_delay_ms"], 750)
            self.assertFalse(other["session_terminated"])
            self.assertFalse(unrelated["rate_limited"])
            self.assertFalse(unrelated["session_terminated"])
            self.assertFalse(different_ip["session_terminated"])

    def test_cached_state_cannot_be_mutated_by_a_caller(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            write_state(path, simulated_blocks=[{"source_ip": "10.0.0.8", "service": "ssh"}])
            state = load_simulated_ips_state(path)
            state["simulated_blocks"][0]["source_ip"] = "10.0.0.9"
            state["simulated_blocks"].clear()
            self.assertTrue(get_simulated_response("10.0.0.8", "ssh", state_file=path)["would_have_been_blocked"])

    def test_replaced_state_is_reloaded_even_with_same_mtime_and_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            write_state(path, simulated_blocks=[{"source_ip": "10.0.0.8", "service": "ssh"}])
            self.assertTrue(get_simulated_response("10.0.0.8", "ssh", state_file=path)["would_have_been_blocked"])
            stat = path.stat()
            replacement = Path(directory) / "replacement.json"
            replacement.write_text(path.read_text(encoding="utf-8").replace("10.0.0.8", "10.0.0.9"), encoding="utf-8")
            os.utime(replacement, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            replacement.replace(path)
            self.assertFalse(get_simulated_response("10.0.0.8", "ssh", state_file=path)["would_have_been_blocked"])
            self.assertTrue(get_simulated_response("10.0.0.9", "ssh", state_file=path)["would_have_been_blocked"])

    def test_invalid_unicode_and_unbounded_numeric_fields_are_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_bytes(b"\xff\xfe")
            self.assertEqual(load_simulated_ips_state(path)["rate_limits"], [])
            write_state(path, rate_limits=[{"source_ip": "10.0.0.8", "service": "ftp", "action_id": True, "rate_limit_delay_ms": float("inf")}])
            response = get_simulated_response("10.0.0.8", "ftp", state_file=path)
            self.assertEqual(response["rate_limit_delay_ms"], 0)
            self.assertEqual(response["action_ids"], [])

    def test_http_rate_limit_cannot_be_bypassed_with_forwarded_ip(self) -> None:
        from core.honeypots import http_honeypot
        with patch.object(http_honeypot, "get_simulated_response", return_value={"rate_limited": True, "rate_limit_delay_ms": 750}) as get_response, patch.object(http_honeypot, "log_event") as log:
            app = http_honeypot.create_http_honeypot()
            reply = app.test_client().get("/", headers={"X-Forwarded-For": "198.51.100.22"})
            self.assertEqual(reply.status_code, 429)
            self.assertEqual(reply.headers["Retry-After"], "1")
            self.assertEqual(get_response.call_args.args[0], "127.0.0.1")
            self.assertEqual(log.call_args.kwargs["source_ip"], "127.0.0.1")

    def test_ftp_uses_per_client_threads_and_does_not_sleep_on_accept(self) -> None:
        from core.honeypots import ftp_honeypot
        from pyftpdlib.servers import ThreadedFTPServer
        self.assertIs(ftp_honeypot.ThreadedFTPServer, ThreadedFTPServer)
        class Handler:
            remote_ip = "127.0.0.1"
            remote_port = 43210
            def _session_id(self):
                return "selected-session"
            def _destination_port(self):
                return 2121
        with patch.object(ftp_honeypot, "apply_simulated_rate_limit") as delay, patch.object(ftp_honeypot, "log_event"):
            ftp_honeypot._LoggingFTPHandler.on_connect(Handler())
            delay.assert_not_called()

    def test_expired_actions_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            write_state(
                path,
                simulated_blocks=[
                    {
                        "action_id": 5,
                        "source_ip": "10.0.0.1",
                        "service": "http",
                        "expires_at": expired,
                    }
                ],
            )
            response = get_simulated_response(
                "10.0.0.1", "http", "request-1", state_file=path
            )
            self.assertFalse(response["would_have_been_blocked"])

    def test_runtime_contains_no_os_blocking_command_path(self) -> None:
        runtime_files = [
            ROOT / "core" / "simulated_ips.py",
            ROOT / "website" / "backend" / "ips_response_store.js",
            ROOT / "core" / "honeypots" / "ssh_honeypot.py",
            ROOT / "core" / "honeypots" / "ftp_honeypot.py",
            ROOT / "core" / "honeypots" / "http_honeypot.py",
        ]
        forbidden = (
            "subprocess.",
            "os.system(",
            "shell=true",
            "netsh advfirewall",
            "iptables ",
            "new-netfirewallrule",
        )
        combined = "\n".join(
            path.read_text(encoding="utf-8").lower() for path in runtime_files
        )
        for marker in forbidden:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, combined)

    def test_honeypots_use_only_application_level_controls(self) -> None:
        ssh = (ROOT / "core" / "honeypots" / "ssh_honeypot.py").read_text(
            encoding="utf-8"
        )
        ftp = (ROOT / "core" / "honeypots" / "ftp_honeypot.py").read_text(
            encoding="utf-8"
        )
        http = (ROOT / "core" / "honeypots" / "http_honeypot.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("apply_simulated_rate_limit", ssh)
        self.assertIn("ftp_session_terminated_by_simulated_ips", ftp)
        self.assertIn("close_when_done", ftp)
        self.assertIn("http_rate_limited_by_simulated_ips", http)
        self.assertIn("reply.status_code = 429", http)

    def test_backend_and_5050_dashboard_expose_complete_ips_workflow(self) -> None:
        server = (
            ROOT / "website" / "backend" / "server.js"
        ).read_text(encoding="utf-8")
        dashboard = (
            ROOT / "dashboard" / "templates" / "index.html"
        ).read_text(encoding="utf-8")

        for route in (
            '/api/ips/safety',
            '/api/ips/status',
            '/api/ips/recommendations',
            '/api/ips/actions',
        ):
            self.assertIn(route, server)
        for marker in (
            'id="sec-ips"',
            "Simulated IPS Response",
            "Automatic host blocking",
            "Host firewall changed",
            "Recommend Block",
            "Simulate Block",
            "Rate Limit",
            "Terminate Session",
            "Release / Undo",
            "Response Audit History",
        ):
            self.assertIn(marker, dashboard)

    def test_telegram_payload_carries_explicit_ips_safety_fields(self) -> None:
        n8n = (ROOT / "simulation" / "n8n.py").read_text(encoding="utf-8")
        for marker in (
            '"response_recommendation"',
            '"ips_mode": "simulation"',
            '"automatic_host_blocking": False',
            '"host_firewall_changed": False',
        ):
            self.assertIn(marker, n8n)

        payload = normalize_record(
            {
                "event_id": "event-step21",
                "timestamp": "2026-08-03T12:00:00+00:00",
                "source_ip": "127.0.0.1",
                "destination_port": 8080,
                "service": "http",
                "event": "http_login_sql_injection",
                "attack_type": "sql_injection",
                "prediction": "attack",
                "confidence": 0.96,
                "anomaly_score": 0.3,
                "model_used": "rules",
                "threat_level": "Critical",
                "threat_score": 95,
                "request_path": "/login",
                "fusion_reason": "Rule match",
                "xai": {"human_reason": {"summary": "SQL pattern matched."}},
            },
            source="ids",
        )
        self.assertEqual(payload["ips_mode"], "simulation")
        self.assertFalse(payload["automatic_host_blocking"])
        self.assertFalse(payload["host_firewall_changed"])
        self.assertIn("Simulation-only IP block", payload["response_recommendation"])


if __name__ == "__main__":
    unittest.main()
