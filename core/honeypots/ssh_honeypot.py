"""
SSH Honeypot
============
Listens on a configurable port and mimics an OpenSSH banner.
Every login attempt (username + password) is captured and logged.
After N failed attempts from the same IP, the event is escalated to
a brute-force alert.
"""

from __future__ import annotations

import socketserver
import sys
from collections import defaultdict
from pathlib import Path
from threading import Lock
from uuid import uuid4

# Allow running standalone
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.logger import log_event
from core.simulated_ips import apply_simulated_rate_limit, get_simulated_response


# --------------------------------------------------------------------------- #
#  Brute-force tracker                                                         #
# --------------------------------------------------------------------------- #

class _BruteForceTracker:
    def __init__(self, threshold: int = 5) -> None:
        self.threshold = threshold
        self._counts: dict[str, int] = defaultdict(int)
        self._lock = Lock()

    def register(self, ip: str) -> tuple[int, bool]:
        with self._lock:
            self._counts[ip] += 1
            count = self._counts[ip]
        return count, count >= self.threshold


_TRACKER = _BruteForceTracker(threshold=3)


# --------------------------------------------------------------------------- #
#  Request handler                                                              #
# --------------------------------------------------------------------------- #

class SSHHoneypotHandler(socketserver.StreamRequestHandler):
    """Handle one fake SSH connection."""

    def handle(self) -> None:
        source_ip: str = self.client_address[0]
        source_port: int = self.client_address[1]
        destination_port: int = self.server.server_address[1]
        session_id = str(uuid4())
        ips_response = get_simulated_response(source_ip, "ssh", session_id)
        apply_simulated_rate_limit(ips_response)
        try:
            # Send a realistic-looking SSH banner
            self.wfile.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
            self.wfile.write(b"login as: ")
            self.wfile.flush()

            username = self.rfile.readline(256).decode("utf-8", errors="ignore").strip()

            self.wfile.write(f"{username}@honeypot's password: ".encode())
            self.wfile.flush()

            password = self.rfile.readline(256).decode("utf-8", errors="ignore").strip()

            count, is_brute = _TRACKER.register(source_ip)

            log_event(
                source_ip=source_ip,
                service="ssh",
                event="ssh_bruteforce_attempt" if is_brute else "ssh_login_attempt",
                attack_type="ssh_bruteforce" if is_brute else "authentication_probe",
                payload={"username": username, "password": password},
                metadata={
                    "attempt_count": count,
                    "threshold": _TRACKER.threshold,
                    "source_port": source_port,
                    "destination_port": destination_port,
                    "session_id": session_id,
                    "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
                },
                severity="warning" if is_brute else "info",
                event_type="authentication",
                protocol="ssh",
                source_port=source_port,
                destination_port=destination_port,
                username=username,
                session_id=session_id,
                status="failed",
            )

            self.wfile.write(b"Permission denied, please try again.\r\n")
            self.wfile.flush()

        except (OSError, ConnectionResetError):
            pass


class _ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


# --------------------------------------------------------------------------- #
#  Public start function                                                        #
# --------------------------------------------------------------------------- #

def start_ssh_honeypot(host: str = "0.0.0.0", port: int = 2222) -> None:
    server = _ThreadedTCPServer((host, port), SSHHoneypotHandler)
    print(f"[SSH] Honeypot listening on {host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    start_ssh_honeypot()
