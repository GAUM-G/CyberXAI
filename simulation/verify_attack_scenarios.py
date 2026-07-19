"""Run Step 5 simulations and verify their centralized backend records."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.event_schema import validate_common_event
from simulation.simulate_attacks import run_all


Predicate = Callable[[dict[str, Any]], bool]


SCENARIOS: tuple[tuple[str, Predicate], ...] = (
    ("SSH brute force", lambda event: event.get("attack_type") == "ssh_bruteforce"),
    ("FTP brute force", lambda event: event.get("attack_type") == "ftp_bruteforce"),
    ("SQL injection", lambda event: event.get("attack_type") == "sql_injection"),
    ("XSS", lambda event: event.get("attack_type") == "xss"),
    (
        "Directory scanning",
        lambda event: event.get("attack_type") == "directory_scanning",
    ),
    ("Port scanning", lambda event: event.get("attack_type") == "port_scanning"),
    (
        "Normal traffic",
        lambda event: event.get("service") == "http"
        and event.get("attack_type") == "web_activity"
        and event.get("severity") == "info"
        and event.get("event")
        in {"http_index_request", "http_search_request", "http_forgot_request"},
    ),
)


def _parse_timestamp(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _get_events(collector_base_url: str) -> list[dict[str, Any]]:
    url = f"{collector_base_url.rstrip('/')}/api/events?limit=1000"
    with urllib.request.urlopen(url, timeout=4) as response:
        body = json.loads(response.read().decode("utf-8"))
    events = body.get("events", [])
    return events if isinstance(events, list) else []


def _matches(
    events: list[dict[str, Any]],
    started_at: datetime,
) -> dict[str, dict[str, Any] | None]:
    current_events = [
        event
        for event in events
        if (_parse_timestamp(event.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))
        >= started_at
    ]
    return {
        name: next((event for event in current_events if predicate(event)), None)
        for name, predicate in SCENARIOS
    }


def _print_results(results: dict[str, dict[str, Any] | None]) -> bool:
    print("\nSTEP 5 CENTRALIZED EVENT VERIFICATION")
    print("-" * 94)
    print(f"{'Scenario':<22} {'Result':<7} {'Service':<8} {'Attack type':<22} Event")
    print("-" * 94)

    all_passed = True
    for name, event in results.items():
        schema_valid = event is not None and not validate_common_event(event)
        passed = event is not None and schema_valid
        all_passed = all_passed and passed
        if event is None:
            print(f"{name:<22} {'FAIL':<7} {'-':<8} {'missing':<22} -")
            continue

        result = "PASS" if passed else "FAIL"
        print(
            f"{name:<22} {result:<7} "
            f"{str(event.get('service', '-')):<8} "
            f"{str(event.get('attack_type', '-')):<22} "
            f"{event.get('event', '-')}"
        )
        if not schema_valid:
            print(f"  schema errors: {', '.join(validate_common_event(event))}")

    print("-" * 94)
    print("OVERALL: PASS" if all_passed else "OVERALL: FAIL")
    return all_passed


def verify_step5(
    collector_base_url: str,
    *,
    ssh_port: int,
    ftp_port: int,
    http_port: int,
    delay: float,
    delivery_timeout: float,
) -> bool:
    started_at = datetime.now(timezone.utc)
    run_all(
        ssh_port=ssh_port,
        ftp_port=ftp_port,
        http_port=http_port,
        delay=delay,
    )

    deadline = time.monotonic() + delivery_timeout
    results: dict[str, dict[str, Any] | None] = {
        name: None for name, _ in SCENARIOS
    }
    while time.monotonic() < deadline:
        try:
            results = _matches(_get_events(collector_base_url), started_at)
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            time.sleep(0.5)
            continue
        if all(results.values()):
            break
        time.sleep(0.5)

    return _print_results(results)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify all Step 5 attack scenarios")
    parser.add_argument("--collector", default="http://127.0.0.1:5000")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--ftp-port", type=int, default=2121)
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--delivery-timeout", type=float, default=20.0)
    args = parser.parse_args()

    passed = verify_step5(
        args.collector,
        ssh_port=args.ssh_port,
        ftp_port=args.ftp_port,
        http_port=args.http_port,
        delay=args.delay,
        delivery_timeout=args.delivery_timeout,
    )
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
