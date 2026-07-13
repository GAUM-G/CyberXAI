"""
SSH Brute-Force Simulation
==========================
Sends repeated login attempts to the SSH honeypot.
Every attempt is captured (username + password) and logged.
After 3 attempts from the same IP → escalated to ssh_bruteforce (warning severity).

Usage:
    python simulation/sim_ssh.py
    python simulation/sim_ssh.py --host 127.0.0.1 --port 2222
"""

from __future__ import annotations

import argparse
import socket
import time

CREDENTIALS = [
    ("root",          "root"),
    ("root",          "toor"),
    ("root",          "password"),
    ("root",          "123456"),
    ("root",          "admin"),
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         "123456"),
    ("admin",         "letmein"),
    ("ubuntu",        "ubuntu"),
    ("pi",            "raspberry"),
    ("user",          "user"),
    ("test",          "test"),
    ("guest",         "guest"),
    ("oracle",        "oracle"),
    ("postgres",      "postgres"),
]


def simulate_ssh_bruteforce(host: str = "127.0.0.1", port: int = 2222, delay: float = 0.4) -> None:
    print(f"\n[SSH-SIM] Starting → {host}:{port}")
    print(f"[SSH-SIM] {len(CREDENTIALS)} credential pairs to try")
    print(f"[SSH-SIM] Events will appear in dashboard Live Feed\n")

    success = 0
    failed  = 0

    for i, (username, password) in enumerate(CREDENTIALS, 1):
        try:
            with socket.create_connection((host, port), timeout=4) as sock:
                # Read SSH banner
                banner = sock.recv(128).decode("utf-8", errors="ignore").strip()
                # Send username
                sock.sendall(f"{username}\n".encode())
                time.sleep(0.15)
                # Read "password: " prompt
                sock.recv(128)
                # Send password
                sock.sendall(f"{password}\n".encode())
                time.sleep(0.15)
                # Read response
                sock.recv(128)
            print(f"  [{i:02d}/{len(CREDENTIALS)}] ✓ sent  {username}:{password}")
            success += 1
        except (ConnectionRefusedError, OSError) as e:
            print(f"  [{i:02d}] ✗ connection failed: {e}")
            failed += 1
            if failed >= 3:
                print("[SSH-SIM] Too many failures — is the honeypot running?")
                break

        time.sleep(delay)

    print(f"\n[SSH-SIM] Done. {success} attempts sent, {failed} connection errors.")
    print("[SSH-SIM] Check dashboard → Honeypot → SSH section for captured credentials.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--delay", type=float, default=0.4)
    args = parser.parse_args()
    simulate_ssh_bruteforce(args.host, args.port, args.delay)
