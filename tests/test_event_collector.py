from __future__ import annotations

import json
import queue
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from core import logger
from core.event_schema import validate_common_event


class EventCollectorTests(unittest.TestCase):
    def test_common_event_is_sent_to_backend_and_kept_in_jsonl(self) -> None:
        received: queue.Queue[dict] = queue.Queue()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - required HTTP handler name
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                received.put(json.loads(body.decode("utf-8")))
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"stored":true}')

            def log_message(self, _format: str, *_args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        with tempfile.TemporaryDirectory() as temp_dir:
            old_log_file = logger.LOG_FILE
            old_webhook = logger.N8N_WEBHOOK_URL
            old_collector_url = logger.EVENT_COLLECTOR_URL
            old_timeout = logger.EVENT_COLLECTOR_TIMEOUT
            old_retry = logger.EVENT_COLLECTOR_RETRY_SECONDS

            logger.LOG_FILE = Path(temp_dir) / "honeypot_events.jsonl"
            logger.N8N_WEBHOOK_URL = ""
            logger.EVENT_COLLECTOR_URL = (
                f"http://127.0.0.1:{server.server_address[1]}/api/events"
            )
            logger.EVENT_COLLECTOR_TIMEOUT = 1.0
            logger.EVENT_COLLECTOR_RETRY_SECONDS = 0.2

            try:
                record = logger.log_event(
                    source_ip="127.0.0.1",
                    source_port=51000,
                    destination_port=2222,
                    service="ssh",
                    protocol="ssh",
                    event_type="authentication",
                    event="ssh_login_attempt",
                    attack_type="authentication_probe",
                    status="failed",
                    username="test-user",
                    session_id="collector-test-session",
                    payload={"username": "test-user", "password": "fake-test-value"},
                    severity="info",
                )

                delivered = received.get(timeout=3)
                written = json.loads(logger.LOG_FILE.read_text(encoding="utf-8").strip())

                self.assertEqual(record, delivered)
                self.assertEqual(record, written)
                self.assertEqual([], validate_common_event(delivered))
            finally:
                logger.LOG_FILE = old_log_file
                logger.N8N_WEBHOOK_URL = old_webhook
                logger.EVENT_COLLECTOR_URL = old_collector_url
                logger.EVENT_COLLECTOR_TIMEOUT = old_timeout
                logger.EVENT_COLLECTOR_RETRY_SECONDS = old_retry
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
