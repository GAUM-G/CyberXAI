"""
Honeypot Launcher
=================
Starts SSH, FTP, and HTTP honeypots each in their own daemon thread.
Import this module and call start_all() from run.py.
"""

from __future__ import annotations

import threading
import time


def start_all(
    ssh_host: str = "0.0.0.0",  ssh_port: int = 2222,
    ftp_host: str = "0.0.0.0",  ftp_port: int = 2121,
    http_host: str = "0.0.0.0", http_port: int = 8080,
) -> list[threading.Thread]:
    """Start all honeypot services in background threads. Returns thread list."""

    from core.honeypots.ssh_honeypot import start_ssh_honeypot
    from core.honeypots.ftp_honeypot import start_ftp_honeypot
    from core.honeypots.http_honeypot import start_http_honeypot

    services = [
        ("SSH",  start_ssh_honeypot,  (ssh_host,  ssh_port)),
        ("FTP",  start_ftp_honeypot,  (ftp_host,  ftp_port)),
        ("HTTP", start_http_honeypot, (http_host, http_port)),
    ]

    threads: list[threading.Thread] = []
    for name, fn, args in services:
        t = threading.Thread(target=fn, args=args, name=f"honeypot-{name.lower()}", daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.3)  # slight stagger to avoid port-bind races

    return threads
