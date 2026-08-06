"""Run Step 5 simulations and verify their centralized backend records."""

from __future__ import annotations

import argparse
import getpass
import json
import os
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


def _login(
    collector_base_url: str,
    username: str,
    password: str,
) -> tuple[str, str]:
    url = f"{collector_base_url.rstrip('/')}/login"
    request = urllib.request.Request(
        url,
        data=json.dumps({"username": username, "password": password}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=4) as response:
        body = json.loads(response.read().decode("utf-8"))

    token = body.get("token")
    if not isinstance(token, str) or not token.strip():
        raise ValueError("Login response did not contain an authentication token")

    user = body.get("user", {})
    authenticated_username = user.get("username", username)
    return token, str(authenticated_username)


def _get_events(
    collector_base_url: str,
    token: str,
) -> list[dict[str, Any]]:
    url = f"{collector_base_url.rstrip('/')}/api/events?limit=1000"
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=4) as response:
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
    token: str,
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
            results = _matches(_get_events(collector_base_url, token), started_at)
        except urllib.error.HTTPError as error:
            if error.code in {401, 403}:
                print(
                    "[AUTH] The collector rejected the login token. "
                    "Sign in again and rerun the verifier."
                )
                return False
            time.sleep(0.5)
            continue
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
    parser.add_argument(
        "--username",
        default=os.getenv("HONEYPOT_API_USERNAME", ""),
        help="Existing portal username; prompted when omitted",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("HONEYPOT_API_TOKEN", ""),
        help="Existing API token; defaults to HONEYPOT_API_TOKEN",
    )
    args = parser.parse_args()

    token = args.token.strip()
    if token:
        print("[AUTH] Using the supplied API token.")
    else:
        username = args.username.strip() or input("Portal username: ").strip()
        if not username:
            parser.error("A portal username is required")
        password = getpass.getpass("Portal password: ")
        if not password:
            parser.error("A portal password is required")

        try:
            token, authenticated_username = _login(
                args.collector,
                username,
                password,
            )
        except urllib.error.HTTPError as error:
            message = error.read().decode("utf-8", errors="replace")
            print(f"[AUTH] Login failed (HTTP {error.code}): {message}")
            raise SystemExit(2) from error
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as error:
            print(f"[AUTH] Could not authenticate with the collector: {error}")
            raise SystemExit(2) from error

        print(f"[AUTH] Authenticated as {authenticated_username}.")

    passed = verify_step5(
        args.collector,
        ssh_port=args.ssh_port,
        ftp_port=args.ftp_port,
        http_port=args.http_port,
        delay=args.delay,
        delivery_timeout=args.delivery_timeout,
        token=token,
    )
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
