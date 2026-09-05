from __future__ import annotations

import argparse
import json
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


LOCAL_WEBHOOK_URL = "http://localhost:5678/webhook/honeypot-alert"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_FILE = PROJECT_ROOT / "data" / "raw_logs" / "honeypot_events.jsonl"
DEFAULT_IDS_LOG_FILE = (
    PROJECT_ROOT / "data" / "detections" / "hybrid_ids_results.jsonl"
)
IMMEDIATE_THREAT_LEVELS = frozenset({"High", "Critical"})
PORTAL_DESTINATION_PORT = 5173
PORTAL_IMMEDIATE_ATTACK_TYPES = frozenset(
    {"sql_injection", "xss", "directory_scanning", "http_bruteforce"}
)
SENSITIVE_ALERT_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "credentials",
        "metadata",
        "password",
        "payload",
        "secret",
        "token",
        "username",
    }
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


@dataclass
class AlertDeduplicator:
    """Suppress repeated eligible IDS alerts before concurrent n8n executions."""

    window_seconds: float = 300.0
    _seen: dict[tuple[str, str, str, str], float] = field(default_factory=dict)

    @staticmethod
    def key(payload: dict[str, Any]) -> tuple[str, str, str, str]:
        values = (
            payload.get("source_ip") or payload.get("ip") or "unknown",
            payload.get("attack_type") or "unknown",
            payload.get("target_service")
            or payload.get("service")
            or payload.get("type")
            or "unknown",
            payload.get("target") or "n/a",
        )
        return tuple(str(value).strip().lower() for value in values)

    def is_duplicate(
        self,
        payload: dict[str, Any],
        *,
        now: float | None = None,
    ) -> bool:
        if payload.get("alert_eligible") is not True:
            return False

        observed_at = time.monotonic() if now is None else now
        self._seen = {
            key: seen_at
            for key, seen_at in self._seen.items()
            if observed_at - seen_at < self.window_seconds
        }
        return self.key(payload) in self._seen

    def mark_sent(
        self,
        payload: dict[str, Any],
        *,
        now: float | None = None,
    ) -> None:
        if payload.get("alert_eligible") is not True:
            return

        observed_at = time.monotonic() if now is None else now
        self._seen[self.key(payload)] = observed_at


def _safe_alert_value(value: Any) -> Any:
    """Copy IDS context while removing raw or credential-bearing fields."""

    if isinstance(value, dict):
        return {
            key: _safe_alert_value(item)
            for key, item in value.items()
            if str(key).strip().lower() not in SENSITIVE_ALERT_KEYS
        }
    if isinstance(value, list):
        return [_safe_alert_value(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_alert_value(item) for item in value]
    return value


def _confidence_percent(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
        return None
    return round(confidence * 100.0, 2)


def _recommended_action(attack_type: str, service: str) -> str:
    attack = attack_type.strip().lower()
    service_name = service.strip().upper() or "TARGET"

    if attack in {"ssh_bruteforce", "ftp_bruteforce"}:
        return (
            f"Temporarily block or rate-limit the source IP and review "
            f"{service_name} authentication logs."
        )
    if attack == "sql_injection":
        return (
            "Temporarily block the source IP and review the affected web route "
            "and database-facing input controls."
        )
    if attack == "xss":
        return (
            "Temporarily block the source IP and review the affected web route, "
            "output encoding, and content security policy."
        )
    if attack == "directory_scanning":
        return (
            "Rate-limit or block the source IP and review requested paths for "
            "exposed files or directories."
        )
    if attack == "port_scanning":
        return (
            "Monitor or block the source IP at the perimeter and review the "
            "probed services and ports."
        )
    return (
        "Contain the source IP according to policy and review the sanitized IDS "
        "evidence for the affected service."
    )


def _ips_response_recommendation(threat_level: str) -> str:
    return {
        "Low": "Continue monitoring; no IPS intervention recommended.",
        "Medium": "Honeypot-level rate limiting recommended.",
        "High": "Simulation-only IP block recommended for analyst approval.",
        "Critical": (
            "Simulation-only IP block and honeypot-session termination review "
            "recommended."
        ),
    }.get(
        threat_level,
        "Review the event before selecting a simulation-only response.",
    )


def _detection_reason(record: dict[str, Any], human_reason: dict[str, Any]) -> str:
    summary = human_reason.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary.strip()

    fusion_reason = record.get("fusion_reason")
    if isinstance(fusion_reason, str) and fusion_reason.strip():
        return fusion_reason.strip()

    prediction = str(record.get("prediction") or "unknown")
    threat_level = str(record.get("threat_level") or "unknown")
    return (
        f"Hybrid IDS classified the event as {prediction} with "
        f"{threat_level} threat level."
    )


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
    attack_type = str(record.get("attack_type") or "unknown")
    prediction = str(record.get("prediction") or "unknown")
    source_ip = record.get("source_ip") or "unknown"
    confidence = record.get("confidence")
    detection_reason = _detection_reason(record, human_reason)
    recommended_action = _recommended_action(attack_type, str(service))
    ips_response_recommendation = _ips_response_recommendation(threat_level)
    alert_eligible = (
        prediction.strip().lower() == "attack"
        and threat_level in IMMEDIATE_THREAT_LEVELS
    )
    try:
        destination_port = int(record.get("destination_port"))
    except (TypeError, ValueError):
        destination_port = None
    if destination_port == PORTAL_DESTINATION_PORT:
        event_name = str(record.get("event") or "").strip().lower()
        model_used = str(record.get("model_used") or "").strip().lower()
        portal_evidence = (
            attack_type in PORTAL_IMMEDIATE_ATTACK_TYPES
            and (
                model_used == "rules"
                or event_name.endswith(f"_{attack_type}")
            )
        )
        alert_eligible = alert_eligible and portal_evidence

    return {
        "alert_schema_version": "1.0",
        "alert_eligible": alert_eligible,
        "event_id": record.get("event_id"),
        "severity": severity,
        "severity_label": threat_level,
        "ip": source_ip,
        "source_ip": source_ip,
        "type": service,
        "target_service": service,
        "attack_type": attack_type,
        "target": target,
        "timestamp": record.get("timestamp"),
        "service": service,
        "event": record.get("event"),
        "source": "hybrid_ids_result",
        "prediction": prediction,
        "confidence": confidence,
        "confidence_percent": _confidence_percent(confidence),
        "model_used": record.get("model_used"),
        "threat_level": threat_level,
        "threat_score": record.get("threat_score"),
        "xai_summary": detection_reason,
        "detection_reason": detection_reason,
        "recommended_action": recommended_action,
        "response_recommendation": ips_response_recommendation,
        "ips_mode": "simulation",
        "automatic_host_blocking": False,
        "host_firewall_changed": False,
        "record": _safe_alert_value(record),
        "privacy": {
            "raw_payload_included": False,
            "credentials_included": False,
        },
        "ips": {
            "mode": "simulation",
            "response_recommendation": ips_response_recommendation,
            "automatic_host_blocking": False,
            "host_firewall_changed": False,
        },
        "analysis": {
            "target": target,
            "ids": {
                "prediction": prediction,
                "confidence": confidence,
                "confidence_percent": _confidence_percent(confidence),
                "anomaly_score": record.get("anomaly_score"),
                "model_used": record.get("model_used"),
                "threat_level": threat_level,
                "threat_score": record.get("threat_score"),
            },
            "explanation": detection_reason,
            "recommended_action": recommended_action,
            "ips_response": ips_response_recommendation,
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


def send_alert(session: Any, cfg: AppConfig, payload: dict[str, Any]) -> bool:
    import requests

    if cfg.critical_only and payload.get("severity") != "critical":
        print(
            f"[SKIP] severity={payload.get('severity')} ip={payload.get('ip')} "
            f"attack={payload.get('attack_type')}"
        )
        return False

    try:
        response = session.post(cfg.webhook_url, json=payload, timeout=cfg.timeout_seconds)
        print(
            f"[POST] status={response.status_code} ip={payload['ip']} "
            f"attack={payload['attack_type']} target={payload['target']}"
        )
        if response.text:
            print(f"[POST] response={response.text.strip()[:300]}")
        return 200 <= response.status_code < 300
    except requests.RequestException as exc:
        print(f"[ERROR] failed to send alert: {exc}")
        return False


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
    deduplicator = AlertDeduplicator()
    wait_for_log_file(cfg.log_file, cfg.poll_interval_seconds)

    try:
        for record in iter_new_jsonl_records(cfg.log_file, cfg.from_start, cfg.poll_interval_seconds):
            payload = normalize_record(record, source=cfg.source)
            if cfg.source == "ids" and payload.get("alert_eligible") is not True:
                print(
                    "[SKIP] not_alert_eligible "
                    f"ip={payload.get('ip')} "
                    f"attack={payload.get('attack_type')} "
                    f"target={payload.get('target')}"
                )
                continue
            if cfg.source == "ids" and deduplicator.is_duplicate(payload):
                print(
                    "[SKIP] duplicate_alert window=300s "
                    f"ip={payload.get('ip')} "
                    f"attack={payload.get('attack_type')} "
                    f"service={payload.get('target_service')}"
                )
                continue

            sent = send_alert(session, cfg, payload)
            if sent and cfg.source == "ids":
                deduplicator.mark_sent(payload)

            if cfg.once and sent:
                print("[DONE] Sent one matching event")
                break
    except KeyboardInterrupt:
        print("\n[STOP] Log forwarder stopped by user")


if __name__ == "__main__":
    main()
