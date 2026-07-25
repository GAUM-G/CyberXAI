"""Build a sanitized, labeled dataset from centralized honeypot events."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from uuid import UUID

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from dataset.labeling import APPROVED_LABELS, assign_label
else:
    from .labeling import APPROVED_LABELS, assign_label


SCHEMA_VERSION = "1.0"
REQUIRED_EVENT_FIELDS = (
    "schema_version",
    "event_id",
    "timestamp",
    "source_ip",
    "source_port",
    "destination_port",
    "service",
    "protocol",
    "event_type",
    "event",
    "attack_type",
    "severity",
    "status",
    "username",
    "session_id",
    "request_method",
    "request_path",
    "payload",
    "metadata",
)

DATASET_FIELDS = (
    "event_id",
    "timestamp_utc",
    "source_ip_hash",
    "source_ip_scope",
    "source_port",
    "destination_port",
    "service",
    "protocol",
    "event_type",
    "event",
    "severity",
    "status",
    "username_present",
    "session_id_present",
    "request_method",
    "request_path",
    "payload_length",
    "payload_json",
    "metadata_json",
    "label",
)

ALLOWED_SERVICES = frozenset({"ssh", "ftp", "http"})
ALLOWED_SEVERITIES = frozenset({"info", "warning", "critical"})
LEAKAGE_EXCLUDED_INPUT_FIELDS = (
    "attack_type",
    "database_id",
    "received_at",
    "username",
    "session_id",
    "source_ip",
)

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "jwt",
)
_INLINE_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|jwt)"
    r"(\s*[:=]\s*)([^&,\s;}\]\"']+)"
)
_REDACTED = "[REDACTED]"


def _normalized_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_")


def _is_sensitive_key(key: Any) -> bool:
    normalized = _normalized_key(key)
    return any(
        normalized == part
        or normalized.startswith(f"{part}_")
        or normalized.endswith(f"_{part}")
        for part in _SENSITIVE_KEY_PARTS
    )


def sanitize_sensitive(value: Any) -> Any:
    """Recursively redact credentials while retaining attack evidence."""

    if isinstance(value, Mapping):
        return {
            str(key): _REDACTED if _is_sensitive_key(key) else sanitize_sensitive(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_sensitive(item) for item in value]
    if isinstance(value, str):
        return _INLINE_SECRET.sub(lambda match: f"{match.group(1)}{match.group(2)}{_REDACTED}", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _parse_timestamp(value: Any) -> datetime:
    text = str(value).strip()
    if not text:
        raise ValueError("timestamp must be a non-empty ISO-8601 value")
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _valid_optional_text(value: Any) -> bool:
    return value is None or isinstance(value, str)


def validate_event(event: Any) -> list[str]:
    """Validate one event using the centralized Step 3/4 schema."""

    if not isinstance(event, Mapping):
        return ["event must be a JSON object"]

    errors: list[str] = []
    missing = [field for field in REQUIRED_EVENT_FIELDS if field not in event]
    if missing:
        errors.append(f"missing fields: {', '.join(missing)}")

    if event.get("schema_version") != SCHEMA_VERSION:
        errors.append("unsupported schema_version")

    for field in (
        "event_id",
        "timestamp",
        "source_ip",
        "protocol",
        "event_type",
        "event",
        "attack_type",
        "status",
    ):
        if not isinstance(event.get(field), str) or not event[field].strip():
            errors.append(f"{field} must be a non-empty string")

    try:
        UUID(str(event.get("event_id", "")))
    except (ValueError, TypeError, AttributeError):
        errors.append("event_id must be a UUID")

    try:
        _parse_timestamp(event.get("timestamp"))
    except (ValueError, TypeError, OverflowError):
        errors.append("timestamp must be ISO-8601")

    service = event.get("service")
    if service not in ALLOWED_SERVICES:
        errors.append("service must be ssh, ftp or http")
    if event.get("protocol") != service:
        errors.append("protocol must match service")
    if event.get("severity") not in ALLOWED_SEVERITIES:
        errors.append("severity must be info, warning or critical")

    for field in ("source_port", "destination_port"):
        value = event.get(field)
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > 65535
        ):
            errors.append(f"{field} must be a valid port or null")

    if not isinstance(event.get("metadata"), Mapping):
        errors.append("metadata must be a JSON object")

    for field in ("username", "session_id", "request_method", "request_path"):
        if not _valid_optional_text(event.get(field)):
            errors.append(f"{field} must be a string or null")

    return list(dict.fromkeys(errors))


def _ip_scope(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_private:
        return "private"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved:
        return "reserved"
    return "public"


def _ip_hash(value: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()[:16]


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def normalize_event(event: Mapping[str, Any], *, hash_salt: str) -> dict[str, Any]:
    """Create one training row without target-leakage or direct identity fields."""

    timestamp = _parse_timestamp(event["timestamp"])
    payload = sanitize_sensitive(event.get("payload"))
    metadata = sanitize_sensitive(event.get("metadata", {}))
    payload_json = _json_text(payload)
    source_ip = str(event["source_ip"]).strip()

    return {
        "event_id": str(event["event_id"]).lower(),
        "timestamp_utc": timestamp.isoformat().replace("+00:00", "Z"),
        "source_ip_hash": _ip_hash(source_ip, hash_salt),
        "source_ip_scope": _ip_scope(source_ip),
        "source_port": event.get("source_port"),
        "destination_port": event.get("destination_port"),
        "service": str(event["service"]).lower(),
        "protocol": str(event["protocol"]).lower(),
        "event_type": str(event["event_type"]).strip().lower(),
        "event": str(event["event"]).strip().lower(),
        "severity": str(event["severity"]).lower(),
        "status": str(event["status"]).strip().lower(),
        "username_present": int(bool(str(event.get("username") or "").strip())),
        "session_id_present": int(bool(str(event.get("session_id") or "").strip())),
        "request_method": str(event.get("request_method") or "").strip().upper(),
        "request_path": sanitize_sensitive(str(event.get("request_path") or "").strip()),
        "payload_length": len(payload_json),
        "payload_json": payload_json,
        "metadata_json": _json_text(metadata),
        "label": assign_label(event),
    }


def prepare_events(
    events: Iterable[Any],
    *,
    hash_salt: str = "honeypot-dataset-v1",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Validate, deduplicate, sanitize and label an event sequence."""

    rows: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen_event_ids: set[str] = set()
    total_events = 0
    duplicate_events = 0

    for event in events:
        total_events += 1
        errors = validate_event(event)
        if errors:
            rejected.append({"errors": errors, "event": sanitize_sensitive(event)})
            continue

        event_id = str(event["event_id"]).lower()
        if event_id in seen_event_ids:
            duplicate_events += 1
            continue
        seen_event_ids.add(event_id)
        rows.append(normalize_event(event, hash_salt=hash_salt))

    rows.sort(key=lambda row: (row["timestamp_utc"], row["event_id"]))
    label_counter = Counter(row["label"] for row in rows)
    label_counts = {label: label_counter.get(label, 0) for label in APPROVED_LABELS}

    stats = {
        "total_events": total_events,
        "accepted_events": len(rows),
        "rejected_events": len(rejected),
        "duplicate_events": duplicate_events,
        "labels": label_counts,
    }
    return rows, rejected, stats


def _read_json(url: str, *, timeout: float) -> Any:
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise RuntimeError(f"backend returned HTTP {error.code} for {url}") from error
    except URLError as error:
        raise RuntimeError(f"could not connect to backend: {error.reason}") from error
    except json.JSONDecodeError as error:
        raise RuntimeError("backend returned invalid JSON") from error


def fetch_backend_events(
    backend_url: str,
    *,
    page_size: int = 500,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Read every centralized event using the Step 6 offset API."""

    if not 1 <= page_size <= 1000:
        raise ValueError("page_size must be between 1 and 1000")

    base_url = backend_url.rstrip("/")
    stats = _read_json(f"{base_url}/api/events/stats", timeout=timeout)
    expected_total = int(stats.get("total_events", 0))
    events: list[dict[str, Any]] = []
    seen_pages: set[tuple[str, ...]] = set()
    offset = 0

    while offset < expected_total:
        query = urlencode({"limit": page_size, "offset": offset})
        payload = _read_json(f"{base_url}/api/events?{query}", timeout=timeout)
        page = payload.get("events")
        if not isinstance(page, list):
            raise RuntimeError("backend response does not contain an events list")
        if not page:
            break

        signature = tuple(str(item.get("event_id", "")) for item in page if isinstance(item, Mapping))
        if signature in seen_pages:
            raise RuntimeError(
                "backend repeated a page; install the Step 6 offset pagination update"
            )
        seen_pages.add(signature)
        events.extend(page)
        offset += len(page)

    if len(events) < expected_total:
        raise RuntimeError(
            f"incomplete backend export: expected {expected_total}, received {len(events)}"
        )
    return events[:expected_total]


def read_jsonl(path: Path) -> tuple[list[Any], list[dict[str, Any]]]:
    """Read JSONL while retaining malformed-line errors for quarantine."""

    events: list[Any] = []
    rejected: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as error:
                rejected.append(
                    {
                        "errors": [f"line {line_number}: invalid JSON: {error.msg}"],
                        "event": {"raw": sanitize_sensitive(line.rstrip())},
                    }
                )
    return events, rejected


def _atomic_write(path: Path, writer: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            writer(handle)
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _write_jsonl(path: Path, records: Sequence[Mapping[str, Any]]) -> None:
    def writer(handle: Any) -> None:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            handle.write("\n")

    _atomic_write(path, writer)


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    def writer(handle: Any) -> None:
        csv_writer = csv.DictWriter(handle, fieldnames=DATASET_FIELDS)
        csv_writer.writeheader()
        csv_writer.writerows(rows)

    _atomic_write(path, writer)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_dataset(
    rows: Sequence[Mapping[str, Any]],
    rejected: Sequence[Mapping[str, Any]],
    stats: Mapping[str, Any],
    *,
    output_dir: Path,
    source: str,
) -> dict[str, Any]:
    """Write all Step 6 outputs and return the final manifest."""

    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "honeypot_dataset.csv"
    jsonl_path = output_dir / "honeypot_dataset.jsonl"
    rejected_path = output_dir / "rejected_events.jsonl"
    manifest_path = output_dir / "dataset_manifest.json"

    _write_csv(csv_path, rows)
    _write_jsonl(jsonl_path, rows)
    _write_jsonl(rejected_path, rejected)

    manifest = {
        "dataset_version": "1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": source,
        **stats,
        "approved_labels": list(APPROVED_LABELS),
        "dataset_fields": list(DATASET_FIELDS),
        "excluded_input_fields": list(LEAKAGE_EXCLUDED_INPUT_FIELDS),
        "sanitization": {
            "credentials_redacted": True,
            "source_ip_replaced_by_hash_and_scope": True,
            "original_logs_modified": False,
        },
        "files": {
            csv_path.name: {"sha256": _sha256_file(csv_path)},
            jsonl_path.name: {"sha256": _sha256_file(jsonl_path)},
            rejected_path.name: {"sha256": _sha256_file(rejected_path)},
        },
    }

    def write_manifest(handle: Any) -> None:
        json.dump(manifest, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")

    _atomic_write(manifest_path, write_manifest)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--backend-url",
        default="http://127.0.0.1:5000",
        help="backend base URL (default: %(default)s)",
    )
    source.add_argument("--input-jsonl", type=Path, help="offline common-event JSONL input")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/processed"),
        help="generated dataset directory (default: %(default)s)",
    )
    parser.add_argument("--page-size", type=int, default=500)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--hash-salt",
        default=os.environ.get("DATASET_HASH_SALT", "honeypot-dataset-v1"),
        help="salt used to pseudonymize source IPs",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    malformed: list[dict[str, Any]] = []

    if args.input_jsonl:
        events, malformed = read_jsonl(args.input_jsonl)
        source = str(args.input_jsonl)
    else:
        events = fetch_backend_events(
            args.backend_url,
            page_size=args.page_size,
            timeout=args.timeout,
        )
        source = f"{args.backend_url.rstrip('/')}/api/events"

    rows, rejected, stats = prepare_events(events, hash_salt=args.hash_salt)
    rejected = [*malformed, *rejected]
    if malformed:
        stats = {
            **stats,
            "total_events": stats["total_events"] + len(malformed),
            "rejected_events": stats["rejected_events"] + len(malformed),
        }

    manifest = write_dataset(
        rows,
        rejected,
        stats,
        output_dir=args.output_dir,
        source=source,
    )

    print(f"[DATASET] Source events: {manifest['total_events']}")
    print(f"[DATASET] Accepted: {manifest['accepted_events']}")
    print(f"[DATASET] Rejected: {manifest['rejected_events']}")
    print(f"[DATASET] Duplicates: {manifest['duplicate_events']}")
    print(f"[DATASET] Output: {args.output_dir.resolve()}")
    for label, count in manifest["labels"].items():
        print(f"  {label}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
