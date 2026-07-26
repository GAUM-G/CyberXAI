"""Safely expand each approved honeypot dataset class to a minimum target.

This utility appends controlled, schema-valid events through the project's
central ``core.logger.log_event`` function. It never edits CSV or NumPy
artifacts directly.

Run from the project root:

    python simulation/expand_dataset.py --dry-run
    python simulation/expand_dataset.py --target 310
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import logger  # noqa: E402
from core.event_schema import validate_common_event  # noqa: E402
from dataset.labeling import APPROVED_LABELS, assign_label  # noqa: E402


DEFAULT_TARGET = 310
GENERATOR_NAME = "controlled-local-v2"
_ISOLATED_PROBE_NETWORK_PREFIX = "198.18"
_ISOLATED_PROBE_HOSTS_PER_SUBNET = 254
_ISOLATED_PROBE_MAX_ORDINAL = (
    256 * _ISOLATED_PROBE_HOSTS_PER_SUBNET
)

_LABEL_INDEX = {
    label: index
    for index, label in enumerate(APPROVED_LABELS)
}

_NORMAL_PATHS = (
    "/",
    "/about",
    "/contact",
    "/help",
    "/news",
    "/products",
    "/search?q=annual+report",
    "/search?q=employee+handbook",
)

_USERS = (
    "admin",
    "root",
    "operator",
    "service",
    "test",
    "ubuntu",
    "guest",
    "support",
)

_PASSWORDS = (
    "test-password-01",
    "sample-admin-02",
    "demo-access-03",
    "local-only-04",
    "training-pass-05",
    "fake-secret-06",
)

_SQL_PAYLOADS = (
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin' --",
    "' UNION SELECT username, password FROM users --",
    "'; DROP TABLE users; --",
    "1' AND SLEEP(2) --",
    "' OR 1=1#",
    "' AND 1=0 UNION SELECT NULL --",
)

_XSS_PAYLOADS = (
    "<script>alert('test')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert('test')>",
    "\"><script>alert(1)</script>",
    "<body onload=alert('demo')>",
    "<iframe src=javascript:alert(1)>",
)

_DIRECTORY_PATHS = (
    "/.env",
    "/.git/config",
    "/wp-admin",
    "/phpmyadmin",
    "/../../../etc/passwd",
    "/config.php",
    "/web.config",
    "/server-status",
    "/admin/config",
    "/backup/.env",
    "/api/admin",
    "/etc/passwd",
)

_SCAN_PORTS = (
    20,
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    2121,
    2222,
    3306,
    3389,
    5000,
    5050,
    5173,
    5432,
    5678,
    6379,
    8080,
    8443,
    9200,
)


def _source_ip(label: str, ordinal: int) -> str:
    """Return label-separated RFC 5737 documentation addresses."""

    first_host = (_LABEL_INDEX[label] * 28) + 1
    host = first_host + (ordinal % 28)
    return f"192.0.2.{host}"


def _isolated_probe_ip(ordinal: int) -> str:
    """Return one non-repeating local benchmark address per auth probe."""

    if not 0 <= ordinal < _ISOLATED_PROBE_MAX_ORDINAL:
        raise ValueError(
            "other_anomaly ordinal exceeds the isolated probe address pool"
        )

    third_octet, host_index = divmod(
        ordinal,
        _ISOLATED_PROBE_HOSTS_PER_SUBNET,
    )
    return (
        f"{_ISOLATED_PROBE_NETWORK_PREFIX}."
        f"{third_octet}.{host_index + 1}"
    )


def _source_port(rng: random.Random) -> int:
    return rng.randrange(40000, 60001)


def _common_metadata(ordinal: int) -> dict[str, Any]:
    return {
        "synthetic": True,
        "generator": GENERATOR_NAME,
        "sample_number": ordinal,
    }


def _event_spec(
    label: str,
    ordinal: int,
    rng: random.Random,
) -> dict[str, Any]:
    source_ip = _source_ip(label, ordinal)
    source_port = _source_port(rng)
    session_id = f"controlled-{_LABEL_INDEX[label]:02d}-{ordinal // 12:04d}"
    metadata = _common_metadata(ordinal)

    if label == "normal":
        path = _NORMAL_PATHS[ordinal % len(_NORMAL_PATHS)]
        return {
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_port": 8080,
            "service": "http",
            "protocol": "http",
            "event_type": "request",
            "event": "http_page_request",
            "attack_type": "web_activity",
            "severity": "info",
            "status": "200",
            "session_id": session_id,
            "request_method": "GET",
            "request_path": path.split("?", 1)[0],
            "payload": path,
            "metadata": {
                **metadata,
                "method": "GET",
                "path": path.split("?", 1)[0],
            },
        }

    if label == "ssh_bruteforce":
        username = _USERS[ordinal % len(_USERS)]
        password = _PASSWORDS[(ordinal * 3) % len(_PASSWORDS)]
        return {
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_port": 2222,
            "service": "ssh",
            "protocol": "ssh",
            "event_type": "authentication",
            "event": "ssh_bruteforce_attempt",
            "attack_type": label,
            "severity": "warning",
            "status": "failed",
            "username": username,
            "session_id": session_id,
            "payload": {
                "username": username,
                "password": password,
            },
            "metadata": {
                **metadata,
                "attempt_count": 3 + (ordinal % 18),
                "threshold": 3,
            },
        }

    if label == "ftp_bruteforce":
        username = _USERS[(ordinal * 5) % len(_USERS)]
        password = _PASSWORDS[(ordinal * 7) % len(_PASSWORDS)]
        return {
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_port": 2121,
            "service": "ftp",
            "protocol": "ftp",
            "event_type": "authentication",
            "event": "ftp_login_failed",
            "attack_type": label,
            "severity": "warning",
            "status": "failed",
            "username": username,
            "session_id": session_id,
            "payload": {
                "username": username,
                "password": password,
            },
            "metadata": {
                **metadata,
                "failed_attempts": 1 + (ordinal % 20),
            },
        }

    if label == "sql_injection":
        payload = _SQL_PAYLOADS[ordinal % len(_SQL_PAYLOADS)]
        is_login = ordinal % 2 == 0
        path = "/login" if is_login else "/search"
        method = "POST" if is_login else "GET"
        return {
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_port": 8080,
            "service": "http",
            "protocol": "http",
            "event_type": "attack",
            "event": f"http_{path[1:]}_sql_injection",
            "attack_type": label,
            "severity": "warning",
            "status": "detected",
            "session_id": session_id,
            "request_method": method,
            "request_path": path,
            "payload": payload,
            "metadata": {
                **metadata,
                "method": method,
                "path": path,
                "query_length": len(payload),
            },
        }

    if label == "xss":
        payload = _XSS_PAYLOADS[ordinal % len(_XSS_PAYLOADS)]
        return {
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_port": 8080,
            "service": "http",
            "protocol": "http",
            "event_type": "attack",
            "event": "http_search_xss",
            "attack_type": label,
            "severity": "warning",
            "status": "detected",
            "session_id": session_id,
            "request_method": "GET",
            "request_path": "/search",
            "payload": payload,
            "metadata": {
                **metadata,
                "method": "GET",
                "path": "/search",
                "query_length": len(payload),
            },
        }

    if label == "directory_scanning":
        path = _DIRECTORY_PATHS[ordinal % len(_DIRECTORY_PATHS)]
        return {
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_port": 8080,
            "service": "http",
            "protocol": "http",
            "event_type": "attack",
            "event": "http_directory_scan",
            "attack_type": label,
            "severity": "warning",
            "status": "detected",
            "session_id": session_id,
            "request_method": "GET",
            "request_path": path,
            "payload": path,
            "metadata": {
                **metadata,
                "method": "GET",
                "path": path,
            },
        }

    if label == "port_scanning":
        observed = sorted(rng.sample(_SCAN_PORTS, k=3 + (ordinal % 6)))
        return {
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_port": observed[-1],
            "service": "http",
            "protocol": "http",
            "event_type": "attack",
            "event": "port_scan_detected",
            "attack_type": label,
            "severity": "warning",
            "status": "detected",
            "session_id": session_id,
            "payload": {
                "observed_ports": observed,
            },
            "metadata": {
                **metadata,
                "observed_ports": observed,
                "distinct_port_count": len(observed),
                "threshold": 3,
                "window_seconds": 60,
            },
        }

    if label == "other_anomaly":
        username = _USERS[ordinal % len(_USERS)]
        return {
            # Each pre-threshold authentication probe is intentionally
            # isolated. Reusing an address would create an artificial burst
            # that is behaviourally indistinguishable from SSH brute force.
            "source_ip": _isolated_probe_ip(ordinal),
            "source_port": source_port,
            "destination_port": 2222,
            "service": "ssh",
            "protocol": "ssh",
            "event_type": "authentication",
            "event": "ssh_login_attempt",
            "attack_type": "authentication_probe",
            "severity": "info",
            "status": "failed",
            "username": username,
            "session_id": f"controlled-07-probe-{ordinal:06d}",
            "payload": {
                "username": username,
                "password": _PASSWORDS[ordinal % len(_PASSWORDS)],
            },
            "metadata": {
                **metadata,
                "attempt_count": 1,
                "threshold": 3,
                "probe_mode": "isolated",
            },
        }

    raise ValueError(f"Unsupported label: {label}")


def _load_valid_counts(path: Path) -> tuple[Counter[str], int, int]:
    counts: Counter[str] = Counter()
    valid = 0
    rejected = 0

    if not path.exists():
        return counts, valid, rejected

    with path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                rejected += 1
                continue

            if not isinstance(record, dict) or validate_common_event(record):
                rejected += 1
                continue

            valid += 1
            counts[assign_label(record)] += 1

    return counts, valid, rejected


def _print_counts(
    title: str,
    counts: Counter[str],
    target: int,
) -> None:
    print(f"\n===== {title} =====")
    print(f"{'Label':24} {'Count':>8} {'Needed':>8}")
    for label in APPROVED_LABELS:
        count = counts[label]
        print(f"{label:24} {count:8d} {max(0, target - count):8d}")


def _build_plan(
    counts: Counter[str],
    target: int,
    rng: random.Random,
) -> list[str]:
    plan = [
        label
        for label in APPROVED_LABELS
        for _ in range(max(0, target - counts[label]))
    ]
    rng.shuffle(plan)
    return plan


def expand_dataset(target: int, seed: int, dry_run: bool) -> int:
    if target < 300:
        raise ValueError("target must be at least 300")

    raw_path = logger.LOG_FILE
    before, valid, rejected = _load_valid_counts(raw_path)
    _print_counts("BEFORE EXPANSION", before, target)
    print(f"\nSchema-valid events : {valid}")
    print(f"Skipped old/invalid : {rejected}")

    rng = random.Random(seed)
    plan = _build_plan(before, target, rng)
    print(f"Planned additions   : {len(plan)}")

    if not plan:
        print("\nPASS: Every approved label already meets the target.")
        return 0

    if dry_run:
        print("\nDRY RUN: No files were changed.")
        return 0

    if not raw_path.exists():
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.touch()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    backup_path = raw_path.with_name(
        f"{raw_path.stem}.pre_expansion_{stamp}{raw_path.suffix}"
    )
    shutil.copy2(raw_path, backup_path)
    print(f"Backup             : {backup_path}")

    # Dataset expansion should not flood Telegram or the backend collector.
    logger.N8N_WEBHOOK_URL = ""
    if hasattr(logger, "EVENT_COLLECTOR_URL"):
        logger.EVENT_COLLECTOR_URL = ""

    ordinals: Counter[str] = Counter()
    generated: Counter[str] = Counter()

    try:
        for position, label in enumerate(plan, start=1):
            ordinal = ordinals[label]
            spec = _event_spec(label, ordinal, rng)
            record = logger.log_event(**spec)

            errors = validate_common_event(record)
            actual_label = assign_label(record)
            if errors:
                raise RuntimeError(
                    f"generated event failed validation: {'; '.join(errors)}"
                )
            if actual_label != label:
                raise RuntimeError(
                    f"expected label {label}, received {actual_label}"
                )

            ordinals[label] += 1
            generated[label] += 1

            if position % 100 == 0 or position == len(plan):
                print(f"Generated {position}/{len(plan)} events")

        after, after_valid, after_rejected = _load_valid_counts(raw_path)
        missing = {
            label: target - after[label]
            for label in APPROVED_LABELS
            if after[label] < target
        }
        if missing:
            details = ", ".join(
                f"{label}={amount}"
                for label, amount in missing.items()
            )
            raise RuntimeError(f"target verification failed: {details}")

    except Exception:
        shutil.copy2(backup_path, raw_path)
        print("\nERROR: Expansion failed; the original raw log was restored.")
        raise

    _print_counts("AFTER EXPANSION", after, target)
    print(f"\nSchema-valid events : {after_valid}")
    print(f"Skipped old/invalid : {after_rejected}")
    print(f"Generated events    : {sum(generated.values())}")
    print(f"Recovery backup     : {backup_path}")
    print("\nPASS: Every approved label meets the requested target.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Append controlled common-format events until every approved "
            "dataset label reaches the target."
        )
    )
    parser.add_argument(
        "--target",
        type=int,
        default=DEFAULT_TARGET,
        help=f"minimum accepted events per label (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20260726,
        help="deterministic plan and payload seed",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show current counts and planned additions without writing",
    )
    args = parser.parse_args()
    return expand_dataset(
        target=args.target,
        seed=args.seed,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    raise SystemExit(main())
