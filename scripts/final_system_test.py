"""Run final offline and optional live end-to-end project verification.

Default mode runs the full Python test suite, backend tests, frontend build,
configuration safety checks and artifact checks. Add ``--runtime`` after all
services are started. Add ``--simulate-attacks`` only in the local controlled
lab; it generates the seven supported scenarios and verifies raw logs, IDS,
XAI, agents, SQLite persistence and simulated-IPS safety.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_LOG = PROJECT_ROOT / "data" / "raw_logs" / "honeypot_events.jsonl"
IDS_LOG = PROJECT_ROOT / "data" / "detections" / "hybrid_ids_results.jsonl"
DATABASE = PROJECT_ROOT / "website" / "backend" / "data" / "honeypot.db"
REPORT_PATH = PROJECT_ROOT / "data" / "reports" / "final_system_test.json"

EXPECTED_SCENARIOS = {
    "ssh_bruteforce",
    "ftp_bruteforce",
    "sql_injection",
    "xss",
    "directory_scanning",
    "port_scanning",
    "web_activity",
}
ATTACK_SCENARIOS = EXPECTED_SCENARIOS - {"web_activity"}
FINAL_THREAT_LEVELS = {"Low", "Medium", "High", "Critical"}
AGENT_RUN_ORDER = [
    "detection",
    "correlation",
    "severity",
    "explanation",
    "response",
    "daily_report",
]


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    duration_seconds: float = 0.0


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_check(name: str, function: Callable[[], str]) -> Check:
    started = time.monotonic()
    try:
        detail = function()
        status = "PASS"
    except Warning as warning:
        detail = str(warning)
        status = "WARN"
    except Exception as error:
        detail = str(error)
        status = "FAIL"
    return Check(name, status, detail, time.monotonic() - started)


def _run_command(arguments: Sequence[str], *, cwd: Path) -> str:
    environment = dict(os.environ)
    environment.setdefault("PYTHONHASHSEED", "0")
    completed = subprocess.run(
        list(arguments),
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode != 0:
        tail = "\n".join(completed.stdout.splitlines()[-25:])
        raise RuntimeError(
            f"command exited with {completed.returncode}: {' '.join(arguments)}\n{tail}"
        )
    lines = completed.stdout.splitlines()
    return "\n".join(lines[-8:]) if lines else "completed without output"


def _check_project_contract() -> str:
    required = [
        "run.py",
        "core/event_schema.py",
        "machine_learning/realtime_ids.py",
        "intelligent_agents/orchestrator.py",
        "continuous_learning/pipeline.py",
        "simulation/n8n.py",
        "dashboard/app.py",
        "website/backend/server.js",
        "website/frontend/src/pages/DashboardPage.jsx",
        "website/frontend/src/components/IDSInsights.jsx",
    ]
    missing = [name for name in required if not (PROJECT_ROOT / name).is_file()]
    if missing:
        raise FileNotFoundError("missing project files: " + ", ".join(missing))

    config = (PROJECT_ROOT / "config" / "config.yaml").read_text(encoding="utf-8")
    required_config = (
        'mode: "simulation"',
        "automatic_host_blocking: false",
        "host_firewall_changed: false",
        "continuous_learning:",
    )
    absent = [marker for marker in required_config if marker not in config]
    if absent:
        raise ValueError("missing safe configuration markers: " + ", ".join(absent))
    return f"{len(required)} core files and simulated-IPS safety defaults verified"


def _check_active_artifacts() -> str:
    active = PROJECT_ROOT / "data" / "ml_ready"
    required = [
        active / "preprocessor.joblib",
        active / "feature_names.json",
        active / "label_mapping.json",
        active / "models" / "random_forest.joblib",
        active / "models" / "isolation_forest.joblib",
        active / "models" / "lstm_classifier.pt",
        active / "evaluation" / "model_selection.json",
    ]
    missing = [str(path.relative_to(PROJECT_ROOT)) for path in required if not path.is_file()]
    if missing:
        raise Warning(
            "generated model artifacts are not present in this copy: "
            + ", ".join(missing)
        )
    return "active Random Forest/Decision Tree, Isolation Forest and LSTM artifacts found"


def _python_tests() -> str:
    return _run_command(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=PROJECT_ROOT,
    )


def _backend_tests() -> str:
    backend = PROJECT_ROOT / "website" / "backend"
    if not (backend / "node_modules").is_dir():
        raise Warning("backend node_modules is missing; run npm.cmd install before final validation")
    npm = "npm.cmd" if os.name == "nt" else "npm"
    return _run_command([npm, "test"], cwd=backend)


def _frontend_build() -> str:
    frontend = PROJECT_ROOT / "website" / "frontend"
    if not (frontend / "node_modules").is_dir():
        raise Warning("frontend node_modules is missing; run npm.cmd install before final validation")
    npm = "npm.cmd" if os.name == "nt" else "npm"
    return _run_command([npm, "run", "build"], cwd=frontend)


def _tcp_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _check_runtime_ports() -> str:
    ports = {
        "SSH honeypot": 2222,
        "FTP honeypot": 2121,
        "HTTP honeypot": 8080,
        "Dashboard": 5050,
        "Backend": 5000,
        "Frontend": 5173,
        "n8n": 5678,
    }
    closed = [name for name, port in ports.items() if not _tcp_open("127.0.0.1", port)]
    if closed:
        raise ConnectionError("services not reachable: " + ", ".join(closed))
    return "all seven required local ports are reachable"


def _http_status(url: str, *, timeout: float = 3.0) -> int:
    request = urllib.request.Request(url, headers={"Accept": "application/json,text/html"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(256)
            return int(response.getcode())
    except urllib.error.HTTPError as error:
        error.read(256)
        return int(error.code)


def _check_runtime_http() -> str:
    expectations = {
        "http://127.0.0.1:8080/": {200},
        "http://127.0.0.1:5050/": {200},
        "http://127.0.0.1:5050/api/auth/session": {200, 401},
        "http://127.0.0.1:5000/": {200},
        "http://127.0.0.1:5000/api/ips/safety": {200},
        "http://127.0.0.1:5173/": {200},
        "http://127.0.0.1:5678/healthz": {200},
    }
    failed = []
    for url, allowed in expectations.items():
        try:
            status = _http_status(url)
        except Exception as error:
            failed.append(f"{url}: {error}")
            continue
        if status not in allowed:
            failed.append(f"{url}: HTTP {status}")
    if failed:
        raise RuntimeError("; ".join(failed))
    return "honeypot, dashboards, backend safety endpoint, frontend and n8n are healthy"


def _read_jsonl_after(path: Path, offset: int) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        handle.seek(min(offset, path.stat().st_size))
        for line in handle:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                records.append(value)
    return records


def _validate_ids_result(record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if record.get("prediction") not in {"normal", "attack"}:
        errors.append("prediction")
    if record.get("threat_level") not in FINAL_THREAT_LEVELS:
        errors.append("threat_level")
    if not isinstance(record.get("confidence"), (int, float, type(None))):
        errors.append("confidence")
    xai = record.get("xai")
    if not isinstance(xai, Mapping):
        errors.append("xai")
    else:
        if not isinstance(xai.get("human_reason"), Mapping):
            errors.append("xai.human_reason")
        privacy = xai.get("privacy")
        if not isinstance(privacy, Mapping) or any(
            privacy.get(name) is not False
            for name in ("raw_payload_included", "source_ip_included", "credentials_included")
        ):
            errors.append("xai.privacy")
    agents = record.get("agents")
    if not isinstance(agents, Mapping) or agents.get("run_order") != AGENT_RUN_ORDER:
        errors.append("agents.run_order")
    else:
        for name in AGENT_RUN_ORDER:
            if agents.get(name, {}).get("status") != "completed":
                errors.append(f"agents.{name}")
        safety = agents.get("safety", {})
        if safety.get("host_firewall_changed") is not False:
            errors.append("agents.safety.host_firewall_changed")
    return errors


def _database_counts(event_ids: Sequence[str]) -> tuple[int, int]:
    if not DATABASE.is_file() or not event_ids:
        return 0, 0
    placeholders = ",".join("?" for _ in event_ids)
    connection = sqlite3.connect(f"file:{DATABASE.resolve()}?mode=ro", uri=True)
    try:
        events = connection.execute(
            f"SELECT COUNT(*) FROM honeypot_events WHERE event_id IN ({placeholders})",
            list(event_ids),
        ).fetchone()[0]
        ids = connection.execute(
            f"SELECT COUNT(*) FROM ids_results WHERE event_id IN ({placeholders})",
            list(event_ids),
        ).fetchone()[0]
    finally:
        connection.close()
    return int(events), int(ids)


def _exercise_attacks(timeout: float) -> str:
    raw_offset = RAW_LOG.stat().st_size if RAW_LOG.is_file() else 0
    ids_offset = IDS_LOG.stat().st_size if IDS_LOG.is_file() else 0

    sys.path.insert(0, str(PROJECT_ROOT))
    from simulation.simulate_attacks import run_all

    run_all(ssh_port=2222, ftp_port=2121, http_port=8080, delay=0.15)
    deadline = time.monotonic() + timeout
    raw_records: list[dict[str, Any]] = []
    ids_records: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        raw_records = _read_jsonl_after(RAW_LOG, raw_offset)
        ids_records = _read_jsonl_after(IDS_LOG, ids_offset)
        raw_types = {str(item.get("attack_type")) for item in raw_records}
        ids_event_ids = {str(item.get("event_id")) for item in ids_records}
        expected_event_ids = {
            str(item.get("event_id"))
            for item in raw_records
            if item.get("attack_type") in ATTACK_SCENARIOS
        }
        if EXPECTED_SCENARIOS <= raw_types and expected_event_ids <= ids_event_ids:
            break
        time.sleep(0.5)

    raw_types = {str(item.get("attack_type")) for item in raw_records}
    missing_raw = sorted(EXPECTED_SCENARIOS - raw_types)
    if missing_raw:
        raise RuntimeError("raw events missing scenarios: " + ", ".join(missing_raw))

    by_event_id = {str(item.get("event_id")): item for item in ids_records}
    attack_events = [
        item for item in raw_records if item.get("attack_type") in ATTACK_SCENARIOS
    ]
    missing_ids = [
        str(item.get("event_id"))
        for item in attack_events
        if str(item.get("event_id")) not in by_event_id
    ]
    if missing_ids:
        raise RuntimeError(f"IDS results missing for {len(missing_ids)} generated attacks")

    contract_errors = {
        event_id: errors
        for event_id, record in by_event_id.items()
        if event_id in {str(item.get("event_id")) for item in attack_events}
        and (errors := _validate_ids_result(record))
    }
    if contract_errors:
        raise RuntimeError("invalid IDS/XAI/agent contracts: " + json.dumps(contract_errors))

    event_ids = [str(item.get("event_id")) for item in attack_events]
    stored_events, stored_ids = _database_counts(event_ids)
    if stored_events < len(event_ids) or stored_ids < len(event_ids):
        raise RuntimeError(
            f"SQLite persistence incomplete: events={stored_events}/{len(event_ids)}, "
            f"ids={stored_ids}/{len(event_ids)}"
        )
    return (
        f"7 scenarios logged; {len(event_ids)} attack events received IDS, severity, "
        "XAI and six-agent output; SQLite persistence verified; host firewall unchanged"
    )


def _check_n8n_webhook() -> str:
    if not IDS_LOG.is_file():
        raise FileNotFoundError("IDS result log is missing")
    records = _read_jsonl_after(IDS_LOG, 0)
    eligible = [
        item
        for item in records
        if item.get("prediction") == "attack"
        and item.get("threat_level") in {"High", "Critical"}
    ]
    if not eligible:
        raise ValueError("no High/Critical IDS result is available for the n8n check")

    sys.path.insert(0, str(PROJECT_ROOT))
    from simulation.n8n import normalize_record

    payload = normalize_record(eligible[-1], source="ids")
    request = urllib.request.Request(
        "http://127.0.0.1:5678/webhook/honeypot-alert",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5.0) as response:
        status = int(response.getcode())
    if not 200 <= status < 300:
        raise RuntimeError(f"n8n webhook returned HTTP {status}")
    return "enriched High/Critical IDS payload accepted by n8n; confirm Telegram receipt"


def _write_report(checks: Sequence[Check], arguments: argparse.Namespace) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "report_version": "1.0",
        "generated_at_utc": _utc_iso(),
        "mode": {
            "runtime": bool(arguments.runtime),
            "simulate_attacks": bool(arguments.simulate_attacks),
            "n8n_check": bool(arguments.n8n_check),
        },
        "checks": [asdict(check) for check in checks],
        "summary": {
            status: sum(1 for check in checks if check.status == status)
            for status in ("PASS", "WARN", "FAIL")
        },
        "overall": "PASS" if all(check.status != "FAIL" for check in checks) else "FAIL",
        "safety": {
            "controlled_local_simulation_only": True,
            "automatic_host_blocking": False,
            "host_firewall_changed": False,
        },
    }
    temporary = REPORT_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, REPORT_PATH)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", action="store_true", help="check running services")
    parser.add_argument(
        "--simulate-attacks",
        action="store_true",
        help="generate and verify controlled local attacks; requires --runtime",
    )
    parser.add_argument(
        "--n8n-check",
        action="store_true",
        help="send one existing enriched IDS alert to the active n8n webhook",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--skip-python-tests", action="store_true")
    parser.add_argument("--skip-node-tests", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.simulate_attacks and not args.runtime:
        raise ValueError("--simulate-attacks requires --runtime")
    if args.timeout <= 0:
        raise ValueError("timeout must be positive")

    checks = [
        _run_check("project_contract", _check_project_contract),
        _run_check("active_model_artifacts", _check_active_artifacts),
    ]
    if not args.skip_python_tests:
        checks.append(_run_check("python_test_suite", _python_tests))
    if not args.skip_node_tests:
        checks.extend(
            [
                _run_check("backend_test_suite", _backend_tests),
                _run_check("frontend_production_build", _frontend_build),
            ]
        )
    if args.runtime:
        checks.extend(
            [
                _run_check("runtime_ports", _check_runtime_ports),
                _run_check("runtime_http", _check_runtime_http),
            ]
        )
    if args.simulate_attacks:
        checks.append(
            _run_check("end_to_end_attack_workflow", lambda: _exercise_attacks(args.timeout))
        )
    if args.n8n_check:
        checks.append(_run_check("n8n_telegram_delivery", _check_n8n_webhook))

    _write_report(checks, args)
    print("\nFINAL SYSTEM TEST")
    print("=" * 90)
    for check in checks:
        print(f"[{check.status:<4}] {check.name:<30} {check.detail}")
    failures = sum(1 for check in checks if check.status == "FAIL")
    warnings = sum(1 for check in checks if check.status == "WARN")
    print("=" * 90)
    print(f"PASS={len(checks) - failures - warnings} WARN={warnings} FAIL={failures}")
    print(f"Report: {REPORT_PATH}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
