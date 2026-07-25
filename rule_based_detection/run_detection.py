"""Run the Step 9 baseline IDS on sanitized CSV or common-event JSONL data."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from rule_based_detection.detector import (
        DEFAULT_FAILURE_THRESHOLD,
        DEFAULT_FAILURE_WINDOW_SECONDS,
        RULE_ENGINE_VERSION,
        RuleBasedDetector,
    )
else:
    from .detector import (
        DEFAULT_FAILURE_THRESHOLD,
        DEFAULT_FAILURE_WINDOW_SECONDS,
        RULE_ENGINE_VERSION,
        RuleBasedDetector,
    )


def _timestamp_key(row: Mapping[str, Any]) -> tuple[int, float, str]:
    text = str(
        row.get("timestamp_utc")
        if row.get("timestamp_utc") not in (None, "")
        else row.get("timestamp", "")
    ).strip()
    try:
        timestamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        instant = timestamp.astimezone(timezone.utc).timestamp()
        invalid = 0
    except (TypeError, ValueError, OverflowError):
        instant = 0.0
        invalid = 1
    return invalid, instant, str(row.get("event_id", "")).strip()


def read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    invalid_lines = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                invalid_lines += 1
                continue
            if isinstance(value, Mapping):
                rows.append(dict(value))
            else:
                invalid_lines += 1
    return rows, invalid_lines


def _deduplicate_and_sort(
    rows: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    unique: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    duplicate_rows = 0

    for original in rows:
        row = dict(original)
        event_id = str(row.get("event_id", "")).strip().lower()
        if event_id and event_id in seen_ids:
            duplicate_rows += 1
            continue
        if event_id:
            seen_ids.add(event_id)
        unique.append(row)

    unique.sort(key=_timestamp_key)
    return unique, duplicate_rows


def detect_rows(
    rows: Iterable[Mapping[str, Any]],
    *,
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
    failure_window_seconds: float = DEFAULT_FAILURE_WINDOW_SECONDS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run causal rules without reading labels or modifying input rows."""

    ordered_rows, duplicate_rows = _deduplicate_and_sort(rows)
    detector = RuleBasedDetector(
        failure_threshold=failure_threshold,
        failure_window_seconds=failure_window_seconds,
    )

    findings: list[dict[str, Any]] = []
    for row in ordered_rows:
        findings.extend(finding.to_dict() for finding in detector.inspect(row))

    type_counts = Counter(item["attack_type"] for item in findings)
    rule_counts = Counter(
        rule_id
        for item in findings
        for rule_id in item.get("matched_rules", [])
    )
    summary = {
        "input_rows": len(list(rows)) if isinstance(rows, Sequence) else len(ordered_rows) + duplicate_rows,
        "unique_rows": len(ordered_rows),
        "duplicate_event_ids_removed": duplicate_rows,
        "findings": len(findings),
        "events_with_findings": len(
            {
                item["event_id"]
                for item in findings
                if item.get("event_id") not in (None, "")
            }
        ),
        "counts_by_attack_type": dict(sorted(type_counts.items())),
        "counts_by_rule": dict(sorted(rule_counts.items())),
    }
    return findings, summary


def _atomic_write(path: Path, writer: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
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


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    def writer(handle: Any) -> None:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")

    _atomic_write(path, writer)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    rows: Iterable[Mapping[str, Any]],
    *,
    output_dir: Path,
    source: str,
    invalid_rows: int = 0,
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
    failure_window_seconds: float = DEFAULT_FAILURE_WINDOW_SECONDS,
) -> dict[str, Any]:
    input_rows = list(rows)
    findings, summary = detect_rows(
        input_rows,
        failure_threshold=failure_threshold,
        failure_window_seconds=failure_window_seconds,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    findings_path = output_dir / "rule_findings.jsonl"
    manifest_path = output_dir / "rule_detection_manifest.json"
    _write_jsonl(findings_path, findings)

    manifest = {
        "rule_engine_version": RULE_ENGINE_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "source": source,
        **summary,
        "invalid_input_rows_skipped": int(invalid_rows),
        "configuration": {
            "failure_threshold": failure_threshold,
            "failure_window_seconds": failure_window_seconds,
            "rules": [
                "repeated_login_failures",
                "sql_injection_patterns",
                "xss_patterns",
            ],
        },
        "safety": {
            "chronological_processing": True,
            "future_events_used": False,
            "input_labels_used_for_decisions": False,
            "input_dataset_modified": False,
            "raw_payload_or_request_text_written_to_findings": False,
            "source_ip_written_to_findings": False,
            "ml_model_used": False,
        },
        "files": {
            findings_path.name: {
                "sha256": _sha256(findings_path),
                "records": len(findings),
            }
        },
    }
    _write_json(manifest_path, manifest)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--input-csv",
        type=Path,
        default=Path("data/processed/honeypot_dataset.csv"),
        help="sanitized Step 6 CSV input (default: %(default)s)",
    )
    source.add_argument(
        "--input-jsonl",
        type=Path,
        help="Step 3 common-event JSONL input",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/ml_ready/rule_based"),
        help="ignored generated-output directory (default: %(default)s)",
    )
    parser.add_argument(
        "--failure-threshold",
        type=int,
        default=DEFAULT_FAILURE_THRESHOLD,
    )
    parser.add_argument(
        "--failure-window-seconds",
        type=float,
        default=DEFAULT_FAILURE_WINDOW_SECONDS,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    invalid_rows = 0
    if args.input_jsonl is not None:
        rows, invalid_rows = read_jsonl(args.input_jsonl)
        source = str(args.input_jsonl)
    else:
        rows = read_csv(args.input_csv)
        source = str(args.input_csv)

    manifest = run(
        rows,
        output_dir=args.output_dir,
        source=source,
        invalid_rows=invalid_rows,
        failure_threshold=args.failure_threshold,
        failure_window_seconds=args.failure_window_seconds,
    )

    print(f"[RULE IDS] Input rows: {manifest['input_rows']}")
    print(
        "[RULE IDS] Unique rows: "
        f"{manifest['unique_rows']} "
        f"(duplicates removed: {manifest['duplicate_event_ids_removed']})"
    )
    print(f"[RULE IDS] Findings: {manifest['findings']}")
    print(f"[RULE IDS] Events with findings: {manifest['events_with_findings']}")
    for attack_type, count in manifest["counts_by_attack_type"].items():
        print(f"  {attack_type}: {count}")
    print(f"[RULE IDS] Output: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
