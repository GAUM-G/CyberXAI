"""
simulate_attacks.py
====================
Runs all Step 5 traffic simulations in a controlled local sequence.
Used by run.py --simulate, or call run_all() directly.

Usage:
    python simulate_attacks.py
    python simulate_attacks.py --ssh-only
    python simulate_attacks.py --http-only
    python simulate_attacks.py --ftp-only
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def run_all(
    ssh_port:  int = 2222,
    ftp_port:  int = 2121,
    http_port: int = 8080,
    delay:     float = 0.3,
) -> None:
    from simulation.sim_ssh  import simulate_ssh_bruteforce
    from simulation.sim_ftp  import simulate_ftp_bruteforce
    from simulation.sim_http import simulate_http_attacks
    from simulation.sim_port_scan import simulate_port_scan

    print("\n" + "="*55)
    print("  🔴  ATTACK SIMULATION STARTING")
    print("  All events will appear in the dashboard live feed.")
    print("="*55 + "\n")

    # Correlate one source across all three honeypot ports first.
    simulate_port_scan(
        ssh_port=ssh_port,
        ftp_port=ftp_port,
        http_port=http_port,
        delay=delay,
    )

    # SSH and FTP can run in parallel; HTTP follows.
    ssh_thread = threading.Thread(
        target=simulate_ssh_bruteforce,
        kwargs={"port": ssh_port, "delay": delay},
        daemon=True,
    )
    ftp_thread = threading.Thread(
        target=simulate_ftp_bruteforce,
        kwargs={"port": ftp_port, "delay": delay},
        daemon=True,
    )

    ssh_thread.start()
    time.sleep(0.5)
    ftp_thread.start()

    ssh_thread.join(timeout=30)
    ftp_thread.join(timeout=30)

    # HTTP last (most events)
    simulate_http_attacks(port=http_port, delay=delay)

    print("\n[SIM] All simulations complete. Check the dashboard!")


def main() -> None:
    parser = argparse.ArgumentParser(description="Attack simulation for honeypot testing")
    parser.add_argument("--ssh-only",  action="store_true")
    parser.add_argument("--ftp-only",  action="store_true")
    parser.add_argument("--http-only", action="store_true")
    parser.add_argument("--ssh-port",  type=int, default=2222)
    parser.add_argument("--ftp-port",  type=int, default=2121)
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--delay",     type=float, default=0.3)
    args = parser.parse_args()

    from simulation.sim_ssh  import simulate_ssh_bruteforce
    from simulation.sim_ftp  import simulate_ftp_bruteforce
    from simulation.sim_http import simulate_http_attacks

    if args.ssh_only:
        simulate_ssh_bruteforce(port=args.ssh_port, delay=args.delay)
    elif args.ftp_only:
        simulate_ftp_bruteforce(port=args.ftp_port, delay=args.delay)
    elif args.http_only:
        simulate_http_attacks(port=args.http_port, delay=args.delay)
    else:
        run_all(
            ssh_port=args.ssh_port,
            ftp_port=args.ftp_port,
            http_port=args.http_port,
            delay=args.delay,
        )


if __name__ == "__main__":
    main()
