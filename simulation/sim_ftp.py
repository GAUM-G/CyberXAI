"""

FTP Brute-Force Simulation
==========================
Attempts logins against the FTP honeypot using common credentials.
Failed logins → logged as ftp_bruteforce (warning).
Successful logins → logged as credential_access (critical) + browsing activity.

Usage:
    python simulation/sim_ftp.py
    python simulation/sim_ftp.py --host 127.0.0.1 --port 2121
"""

from __future__ import annotations

import argparse
import ftplib
import time

CREDENTIALS = [
    ("ftp",       "ftp"),
       # anonymous login — often accepted
]


def simulate_ftp_bruteforce(host: str = "127.0.0.1", port: int = 2121, delay: float = 0.5) -> None:
    print(f"\n[FTP-SIM] Starting → {host}:{port}")
    print(f"[FTP-SIM] {len(CREDENTIALS)} credential pairs to try")
    print(f"[FTP-SIM] Events will appear in dashboard Live Feed\n")

    for i, (username, password) in enumerate(CREDENTIALS, 1):
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=4)
            try:
                ftp.login(username, password)
                print(f"  [{i:02d}] ✓ LOGIN SUCCESS  {username}:{password}")
                # Browse a bit — this creates more log entries
                try:
                    files = ftp.nlst()
                    print(f"       → Files found: {files}")
                    # Try to read a file
                    if files:
                        fname = files[0]
                        lines = []
                        ftp.retrlines(f"RETR {fname}", lines.append)
                        print(f"       → Read {fname}: {len(lines)} lines")
                except Exception:
                    pass
                ftp.quit()
            except ftplib.error_perm:
                print(f"  [{i:02d}] ✗ failed         {username}:{password}")
                try:
                    ftp.quit()
                except Exception:
                    pass
        except (ConnectionRefusedError, OSError) as e:
            print(f"  [{i:02d}] ✗ connection error: {e}")
            break

        time.sleep(delay)

    print(f"\n[FTP-SIM] Done. Check dashboard → Honeypot → FTP for all captured credentials.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2121)
    parser.add_argument("--delay", type=float, default=0.5)
    args = parser.parse_args()
    simulate_ftp_bruteforce(args.host, args.port, args.delay)
