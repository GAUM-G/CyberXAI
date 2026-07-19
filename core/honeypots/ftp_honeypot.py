"""
FTP Honeypot
============
Uses pyftpdlib to run a realistic FTP server.
All login failures (brute-force) and successful logins are logged.
Decoy files are placed in data/ftp_decoy/ to make the server look real.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path
from threading import Lock
from uuid import uuid4

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.logger import log_event

try:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
    _FTP_AVAILABLE = True
except ImportError:
    DummyAuthorizer = None
    FTPHandler = object
    FTPServer = None
    _FTP_AVAILABLE = False
    print("[FTP] pyftpdlib not installed. Run: pip install pyftpdlib")


# --------------------------------------------------------------------------- #
#  Failed login tracker                                                         #
# --------------------------------------------------------------------------- #

_failed_counts: dict[str, int] = defaultdict(int)
_failed_lock = Lock()


# --------------------------------------------------------------------------- #
#  Custom handler                                                               #
# --------------------------------------------------------------------------- #

class _LoggingFTPHandler(FTPHandler):

    def _session_id(self) -> str:
        session_id = getattr(self, "_honeypot_session_id", None)
        if not session_id:
            session_id = str(uuid4())
            self._honeypot_session_id = session_id
        return session_id

    def _destination_port(self) -> int | None:
        try:
            return int(self.socket.getsockname()[1])
        except (AttributeError, OSError, TypeError, ValueError):
            return None

    def on_connect(self) -> None:
        session_id = self._session_id()
        destination_port = self._destination_port()
        log_event(
            source_ip=self.remote_ip,
            service="ftp",
            event="ftp_connection",
            attack_type="connection_probe",
            payload="FTP connection opened",
            metadata={
                "remote_port": self.remote_port,
                "destination_port": destination_port,
                "session_id": session_id,
            },
            severity="info",
            event_type="connection",
            protocol="ftp",
            source_port=self.remote_port,
            destination_port=destination_port,
            session_id=session_id,
            status="opened",
        )

    def on_login_failed(self, username: str, password: str) -> None:
        with _failed_lock:
            _failed_counts[self.remote_ip] += 1
            count = _failed_counts[self.remote_ip]

        log_event(
            source_ip=self.remote_ip,
            service="ftp",
            event="ftp_login_failed",
            attack_type="ftp_bruteforce",
            payload={"username": username, "password": password},
            metadata={
                "failed_attempts": count,
                "source_port": self.remote_port,
                "destination_port": self._destination_port(),
                "session_id": self._session_id(),
            },
            severity="warning",
            event_type="authentication",
            protocol="ftp",
            source_port=self.remote_port,
            destination_port=self._destination_port(),
            username=username,
            session_id=self._session_id(),
            status="failed",
        )

    def on_login(self, username: str) -> None:
        log_event(
            source_ip=self.remote_ip,
            service="ftp",
            event="ftp_login_success",
            attack_type="credential_access",
            payload={"username": username},
            metadata={
                "home": self.fs.root,
                "source_port": self.remote_port,
                "destination_port": self._destination_port(),
                "session_id": self._session_id(),
            },
            severity="critical",
            event_type="authentication",
            protocol="ftp",
            source_port=self.remote_port,
            destination_port=self._destination_port(),
            username=username,
            session_id=self._session_id(),
            status="success",
        )

    def pre_process_command(self, line: str, cmd: str, arg: str | None) -> None:
        log_event(
            source_ip=self.remote_ip,
            service="ftp",
            event="ftp_command",
            attack_type="command_activity",
            payload=line,
            metadata={
                "command": cmd,
                "argument": arg,
                "source_port": self.remote_port,
                "destination_port": self._destination_port(),
                "session_id": self._session_id(),
            },
            severity="info",
            event_type="command",
            protocol="ftp",
            source_port=self.remote_port,
            destination_port=self._destination_port(),
            session_id=self._session_id(),
            status="observed",
        )
        super().pre_process_command(line, cmd, arg)


# --------------------------------------------------------------------------- #
#  Public start function                                                        #
# --------------------------------------------------------------------------- #

def start_ftp_honeypot(host: str = "0.0.0.0", port: int = 2121) -> None:
    if not _FTP_AVAILABLE:
        print("[FTP] Skipping — pyftpdlib not installed.")
        return

    # Create decoy directory with fake files
    decoy_dir = Path(__file__).resolve().parents[2] / "data" / "ftp_decoy"
    decoy_dir.mkdir(parents=True, exist_ok=True)

    # Drop some enticing decoy files
    _create_decoy_files(decoy_dir)

    authorizer = DummyAuthorizer()
    # Allow "anonymous" login so attackers can browse
    authorizer.add_anonymous(str(decoy_dir), perm="elradfmwMT")
    # Also accept any credential (DummyAuthorizer requires known users — we use a catch-all)
    authorizer.add_user("admin", "admin", str(decoy_dir), perm="elradfmwMT")
    authorizer.add_user("root", "root", str(decoy_dir), perm="elradfmwMT")
    authorizer.add_user("ftp", "ftp", str(decoy_dir), perm="elradfmwMT")

    handler = _LoggingFTPHandler
    handler.authorizer = authorizer
    handler.banner = "220 ProFTPD 1.3.5a Server (ProFTPD) ready"
    handler.passive_ports = range(60000, 60100)

    server = FTPServer((host, port), handler)
    server.max_cons_per_ip = 10
    print(f"[FTP] Honeypot listening on {host}:{port}")
    server.serve_forever(timeout=0.5, blocking=True)


def _create_decoy_files(directory: Path) -> None:
    """Place realistic-looking bait files in the FTP root."""
    files = {
        "credentials_backup.csv": "username,password\nadmin,P@ssw0rd!\nroot,toor123\n",
        "finance_report_2024.txt": "CONFIDENTIAL - Q4 Revenue: $4,231,000\nOperating Costs: $1,890,000\n",
        "server_config.conf": "[database]\nhost=192.168.1.10\nport=5432\npassword=db_secret_2024\n",
        "employee_data.txt": "John Smith - CTO - john@company.com\nJane Doe - CEO - jane@company.com\n",
    }
    for name, content in files.items():
        fpath = directory / name
        if not fpath.exists():
            fpath.write_text(content)


if __name__ == "__main__":
    start_ftp_honeypot()
