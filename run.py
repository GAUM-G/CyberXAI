"""
run.py — Start the entire Honeypot system with one command.

Usage:
    python run.py                  # starts honeypots + IDS + dashboard
    python run.py --no-dashboard   # honeypots only
    python run.py --no-ids         # skip automatic IDS integration
    python run.py --simulate       # also runs built-in attack simulation
    python run_website.py          # starts standalone decoy website

Ports used (all on localhost for prototype / change host in config):
    SSH honeypot  →  :2222
    FTP honeypot  →  :2121
    HTTP honeypot →  :8080
    Dashboard     →  :5050  (open this in your browser)
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

# Make sure the project root is on sys.path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def _banner() -> None:
    print("""
╔══════════════════════════════════════════════════════════╗
║          🍯  HONEYPOT SECURITY FRAMEWORK  🍯            ║
║     SSH · FTP · HTTP  |  Real-time Monitoring            ║
╚══════════════════════════════════════════════════════════╝
""")


def main() -> None:
    parser = argparse.ArgumentParser(description="Honeypot Framework")
    parser.add_argument("--no-dashboard", action="store_true", help="Skip the web dashboard")
    parser.add_argument("--no-ids",       action="store_true", help="Skip the automatic real-time Hybrid IDS")
    parser.add_argument("--no-agents",    action="store_true", help="Disable Step 22 intelligent agents")
    parser.add_argument("--simulate",     action="store_true", help="Run built-in attack simulation after 5s")
    parser.add_argument(
        "--ids-replay-existing",
        action="store_true",
        help="Process existing common-event records before following new ones",
    )
    parser.add_argument(
        "--ids-backend-url",
        default=None,
        help="Override the IDS result collector URL",
    )
    parser.add_argument("--ssh-port",     type=int, default=2222)
    parser.add_argument("--ftp-port",     type=int, default=2121)
    parser.add_argument("--http-port",    type=int, default=8080)
    parser.add_argument("--dash-port",    type=int, default=5050)
    args = parser.parse_args()

    _banner()

    # ── Start the protected real-time IDS before producers append events ──
    ids_service = None
    if not args.no_ids:
        from machine_learning.realtime_ids import (
            DEFAULT_BACKEND_URL,
            create_realtime_ids_service,
        )

        ids_service = create_realtime_ids_service(
            backend_url=args.ids_backend_url or DEFAULT_BACKEND_URL,
            replay_existing=args.ids_replay_existing,
            enable_agents=not args.no_agents,
        )
        ids_service.start()
        print(
            "[✓] Real-time Hybrid IDS → automatic inference, threat score, "
            "SHAP, intelligent agents and backend delivery"
        )

    # ── Start honeypots ────────────────────────────────────────────────────
    print("[*] Starting honeypot services...")
    from core.launcher import start_all

    threads = start_all(
        ssh_port=args.ssh_port,
        ftp_port=args.ftp_port,
        http_port=args.http_port,
    )
    time.sleep(1.0)  # let the servers bind

    print(f"\n[✓] SSH  honeypot  → port {args.ssh_port}")
    print(f"[✓] FTP  honeypot  → port {args.ftp_port}")
    print(f"[✓] HTTP honeypot  → port {args.http_port}  (open http://127.0.0.1:{args.http_port} to see the fake site)")

    # ── Start dashboard ────────────────────────────────────────────────────
    if not args.no_dashboard:
        from dashboard.app import start_dashboard
        dash_thread = threading.Thread(
            target=start_dashboard,
            kwargs={"host": "127.0.0.1", "port": args.dash_port},
            name="dashboard",
            daemon=True,
        )
        dash_thread.start()
        print(f"\n[✓] Dashboard active      → http://127.0.0.1:{args.dash_port}  ← open this!\n")

    # ── Optional simulation ────────────────────────────────────────────────
    if args.simulate:
        def _run_simulation() -> None:
            time.sleep(3)
            print("[SIM] Running built-in attack simulation")
            try:
                from simulation.simulate_attacks import run_all
                run_all(
                    ssh_port=args.ssh_port,
                    ftp_port=args.ftp_port,
                    http_port=args.http_port,
                )
            except Exception as exc:
                print(f"[SIM] Error: {exc}")

        threading.Thread(target=_run_simulation, daemon=True).start()

    print("[*] Press Ctrl+C to stop all services.\n")

    # ── Keep alive ─────────────────────────────────────────────────────────
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
    finally:
        if ids_service is not None:
            ids_service.stop()
        print("[*] Goodbye.")


if __name__ == "__main__":
    main()
