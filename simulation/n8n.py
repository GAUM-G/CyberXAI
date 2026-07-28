from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LOCAL_WEBHOOK_URL = "http://localhost:5678/webhook/honeypot-alert"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_FILE = PROJECT_ROOT / "data" / "raw_logs" / "honeypot_events.jsonl"
DEFAULT_IDS_LOG_FILE = (
    PROJECT_ROOT / "data" / "detections" / "hybrid_ids_results.jsonl"
)


@dataclass
class AppConfig:
    webhook_url: str
    log_file: Path
    source: str
    poll_interval_seconds: float
    critical_only: bool
    timeout_seconds: float
    from_start: bool
    once: bool


def normalize_ids_result(record: dict[str, Any]) -> dict[str, Any]:
    """Adapt a final Step 16 IDS result to the existing webhook contract."""

    service = record.get("service") or "unknown"
    threat_level = str(record.get("threat_level", "Low"))
    severity = {
        "Critical": "critical",
        "High": "warning",
        "Medium": "warning",
        "Low": "info",
    }.get(threat_level, "info")
    target = (
        record.get("request_path")
        or (
            f"port {record.get('destination_port')}"
            if record.get("destination_port") is not None
            else None
        )
        or record.get("event")
        or "n/a"
    )
    xai = record.get("xai") if isinstance(record.get("xai"), dict) else {}
    human_reason = (
        xai.get("human_reason")
        if isinstance(xai.get("human_reason"), dict)
        else {}
    )

    return {
        "severity": severity,
        "ip": record.get("source_ip", "unknown"),
        "type": service,
        "attack_type": record.get("attack_type", "unknown"),
        "target": target,
        "timestamp": record.get("timestamp"),
        "service": service,
        "event": record.get("event"),
        "source": "hybrid_ids_result",
        "prediction": record.get("prediction"),
        "confidence": record.get("confidence"),
        "model_used": record.get("model_used"),
        "threat_level": threat_level,
        "threat_score": record.get("threat_score"),
        "xai_summary": human_reason.get("summary", ""),
        "record": record,
        "analysis": {
            "target": target,
            "ids": {
                "prediction": record.get("prediction"),
                "confidence": record.get("confidence"),
                "anomaly_score": record.get("anomaly_score"),
                "model_used": record.get("model_used"),
                "threat_level": threat_level,
                "threat_score": record.get("threat_score"),
            },
            "explanation": human_reason.get("summary", ""),
        },
    }


def normalize_record(
    record: dict[str, Any],
    *,
    source: str = "raw",
) -> dict[str, Any]:
    if source == "ids":
        return normalize_ids_result(record)
    if source != "raw":
        raise ValueError("source must be raw or ids")

    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    payload_value = record.get("payload")
    service = record.get("service") or "unknown"
    normalized_record = {**record, "service": service, "type": service}

    target = metadata.get("path") or metadata.get("route") or metadata.get("target")
    if not target and isinstance(payload_value, str):
        target = payload_value[:200]

    username = None
    password = None
    if isinstance(payload_value, dict):
        username = payload_value.get("username") or payload_value.get("user")
        password = payload_value.get("password") or payload_value.get("pass")
    elif isinstance(payload_value, str) and "username=" in payload_value:
        parts = dict(part.split("=", 1) for part in payload_value.split("&") if "=" in part)
        username = parts.get("username")
        password = parts.get("password")

    request_context = {
        "method": metadata.get("method"),
        "status": metadata.get("status"),
        "durationMs": metadata.get("durationMs"),
        "query": metadata.get("query"),
        "body": metadata.get("body"),
        "headers": metadata.get("headers"),
        "userAgent": metadata.get("userAgent"),
        "referer": metadata.get("referer"),
        "origin": metadata.get("origin"),
        "host": metadata.get("host"),
        "remote_port": metadata.get("remote_port"),
        "source_port": metadata.get("source_port"),
        "command": metadata.get("command"),
        "argument": metadata.get("argument"),
        "query_length": metadata.get("query_length"),
        "filename": metadata.get("filename"),
        "attempt_count": metadata.get("attempt_count"),
        "failed_attempts": metadata.get("failed_attempts"),
        "threshold": metadata.get("threshold"),
    }

    indicators = {
        "username": username or metadata.get("username") or metadata.get("user"),
        "password": password or metadata.get("password") or metadata.get("pass"),
        "findings": metadata.get("findings"),
        "attacks_detected": metadata.get("attacks_detected"),
        "event_path": metadata.get("path") or metadata.get("route"),
    }

    return {
        "severity": record.get("severity", "info"),
        "ip": record.get("source_ip", "unknown"),
        # Compatibility alias used by the existing Telegram message template.
        "type": service,
        "attack_type": record.get("attack_type", "unknown"),
        "target": target or "n/a",
        "timestamp": record.get("timestamp"),
        "service": service,
        "event": record.get("event"),
        "metadata": metadata,
        "payload": payload_value,
        "record": normalized_record,
        "analysis": {
            "target": target or "n/a",
            "request_context": {k: v for k, v in request_context.items() if v is not None},
            "indicators": {k: v for k, v in indicators.items() if v not in (None, "")},
        },
    }


def create_session() -> Any:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    retry = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=0.5,
        status_forcelist=(408, 429, 500, 502, 503, 504),
        allowed_methods=frozenset(["POST"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)

    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def send_alert(session: Any, cfg: AppConfig, payload: dict[str, Any]) -> None:
    import requests

    if cfg.critical_only and payload.get("severity") != "critical":
        print(
            f"[SKIP] severity={payload.get('severity')} ip={payload.get('ip')} "
            f"attack={payload.get('attack_type')}"
        )
        return

    try:
        response = session.post(cfg.webhook_url, json=payload, timeout=cfg.timeout_seconds)
        print(
            f"[POST] status={response.status_code} ip={payload['ip']} "
            f"attack={payload['attack_type']} target={payload['target']}"
        )
        if response.text:
            print(f"[POST] response={response.text.strip()[:300]}")
    except requests.RequestException as exc:
        print(f"[ERROR] failed to send alert: {exc}")


def resolve_webhook_url(mode: str, ngrok_url: str | None) -> str:
    if mode == "local":
        return LOCAL_WEBHOOK_URL

    if not ngrok_url:
        raise ValueError("--ngrok-url is required when --mode ngrok")

    ngrok_url = ngrok_url.rstrip("/")
    return f"{ngrok_url}/webhook/honeypot-alert"


def wait_for_log_file(log_file: Path, poll_interval: float) -> None:
    while not log_file.exists():
        print(f"[WAIT] log file not found: {log_file}")
        time.sleep(poll_interval)


def iter_new_jsonl_records(log_file: Path, from_start: bool, poll_interval: float):
    with log_file.open("r", encoding="utf-8") as f:
        if not from_start:
            f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue

            line = line.strip()
            if not line:
                continue

            # PowerShell-created UTF-8 files may include BOM on first line.
            line = line.lstrip("\ufeff")

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                print("[WARN] skipping invalid JSON line")
                continue

            if isinstance(record, dict):
                yield record


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Watch honeypot JSONL logs and forward new events to n8n production webhook"
    )
    parser.add_argument(
        "--mode",
        choices=["local", "ngrok"],
        default="local",
        help="Use local n8n URL or ngrok URL",
    )
    parser.add_argument(
        "--ngrok-url",
        default=None,
        help="Example: https://abc123.ngrok-free.app (without /webhook path)",
    )
    parser.add_argument(
        "--webhook-url",
        default=None,
        help="Optional explicit webhook URL. Overrides mode/ngrok calculation.",
    )
    parser.add_argument(
        "--source",
        choices=["raw", "ids"],
        default="raw",
        help="Forward raw common events or final Hybrid IDS results",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Optional JSONL path; defaults to the selected source file",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Seconds between checks for newly appended log lines",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP timeout in seconds",
    )
    parser.add_argument(
        "--critical-only",
        action="store_true",
        help="Forward only critical severity (default forwards warning/info too)",
    )
    parser.add_argument(
        "--all-severity",
        action="store_true",
        help="Legacy flag: keeps forwarding all severities",
    )
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Read existing lines from start of file; default is tail-only (new lines)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Send one matching event and exit",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    webhook_url = args.webhook_url or resolve_webhook_url(args.mode, args.ngrok_url)
    default_log_file = (
        DEFAULT_IDS_LOG_FILE if args.source == "ids" else DEFAULT_LOG_FILE
    )
    log_file_arg = Path(args.log_file) if args.log_file else default_log_file
    log_file = log_file_arg if log_file_arg.is_absolute() else (PROJECT_ROOT / log_file_arg)
    log_file = log_file.resolve()
    cfg = AppConfig(
        webhook_url=webhook_url,
        log_file=log_file,
        source=args.source,
        poll_interval_seconds=max(0.2, args.poll_interval),
        critical_only=args.critical_only and not args.all_severity,
        timeout_seconds=max(1.0, args.timeout),
        from_start=args.from_start,
        once=args.once,
    )

    print("[START] Honeypot log forwarder")
    print(f"[CONFIG] webhook={cfg.webhook_url}")
    print(f"[CONFIG] source={cfg.source}")
    print(f"[CONFIG] log_file={cfg.log_file}")
    print(f"[CONFIG] poll_interval={cfg.poll_interval_seconds}s timeout={cfg.timeout_seconds}s")
    print(f"[CONFIG] critical_only={cfg.critical_only}")
    print(f"[CONFIG] from_start={cfg.from_start}")

    session = create_session()
    wait_for_log_file(cfg.log_file, cfg.poll_interval_seconds)

    try:
        for record in iter_new_jsonl_records(cfg.log_file, cfg.from_start, cfg.poll_interval_seconds):
            payload = normalize_record(record, source=cfg.source)
            send_alert(session, cfg, payload)

            if cfg.once:
                print("[DONE] Sent one matching event")
                break
    except KeyboardInterrupt:
        print("\n[STOP] Log forwarder stopped by user")


if __name__ == "__main__":
    main()
