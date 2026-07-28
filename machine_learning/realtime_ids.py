"""Automatically process live honeypot events with the protected Hybrid IDS.

Step 16 keeps the Step 12 model artifacts and the Step 15 inference engine
unchanged.  This module adds orchestration only:

common-event JSONL -> HybridIDSEngine -> integrated result JSONL -> backend API

The local result file is written before backend delivery is attempted, so a
temporarily unavailable backend does not interrupt honeypot collection.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import queue
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if TYPE_CHECKING:
    from machine_learning.hybrid_ids import HybridIDSEngine


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_PATH = PROJECT_ROOT / "data" / "raw_logs" / "honeypot_events.jsonl"
DEFAULT_OUTPUT_PATH = (
    PROJECT_ROOT / "data" / "detections" / "hybrid_ids_results.jsonl"
)
DEFAULT_INPUT_DIR = PROJECT_ROOT / "data" / "ml_ready"
DEFAULT_MODEL_DIR = DEFAULT_INPUT_DIR / "models"
DEFAULT_SELECTION_PATH = (
    DEFAULT_INPUT_DIR / "evaluation" / "model_selection.json"
)
DEFAULT_BACKEND_URL = os.environ.get(
    "IDS_RESULT_COLLECTOR_URL",
    "http://127.0.0.1:5000/api/ids-results",
).strip()
IDS_RESULT_SCHEMA_VERSION = "1.0"

DeliveryFunction = Callable[[dict[str, Any]], str]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_integrated_result(
    event: Mapping[str, Any],
    ids_result: Mapping[str, Any],
    *,
    processed_at: str | None = None,
) -> dict[str, Any]:
    """Add the minimum live-system context without copying raw secrets."""

    if not isinstance(event, Mapping) or not isinstance(ids_result, Mapping):
        raise ValueError("event and IDS result must be mappings")

    event_id = str(event.get("event_id", "")).strip().lower()
    result_event_id = str(ids_result.get("event_id", "")).strip().lower()
    if not event_id or result_event_id != event_id:
        raise ValueError("IDS result event_id must match the source event")

    result = copy.deepcopy(dict(ids_result))
    result.update(
        {
            "ids_result_schema_version": IDS_RESULT_SCHEMA_VERSION,
            "processed_at": processed_at or _utc_now(),
            "source_ip": str(event.get("source_ip", "unknown")),
            "destination_port": event.get("destination_port"),
            "event_type": str(event.get("event_type", "unknown")),
            "event": str(event.get("event", "unknown")),
            "status": str(event.get("status", "unknown")),
            "request_method": event.get("request_method"),
            "request_path": event.get("request_path"),
            "integration": {
                "source": "live_common_event",
                "raw_payload_included": False,
                "credentials_included": False,
                "producer_attack_type_used_as_prediction": False,
            },
        }
    )

    # The source payload, metadata and credentials are intentionally excluded.
    result.pop("payload", None)
    result.pop("metadata", None)
    result.pop("username", None)
    return result


def _append_jsonl(
    path: Path,
    record: Mapping[str, Any],
    *,
    lock: threading.Lock,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, sort_keys=True)
    with lock:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line)
            handle.write("\n")


def post_result_to_backend(
    backend_url: str,
    record: Mapping[str, Any],
    *,
    timeout_seconds: float,
) -> str:
    """Return success, retry or drop without raising into the IDS loop."""

    if not backend_url:
        return "drop"

    request = urllib.request.Request(
        backend_url,
        data=json.dumps(record, ensure_ascii=True).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return "success" if 200 <= response.getcode() < 300 else "retry"
    except urllib.error.HTTPError as exc:
        if 400 <= exc.code < 500 and exc.code not in (408, 429):
            return "drop"
        return "retry"
    except (urllib.error.URLError, TimeoutError, OSError):
        return "retry"


class RealtimeIDSService:
    """Tail common events and persist/deliver final explainable IDS results."""

    def __init__(
        self,
        engine: "HybridIDSEngine",
        *,
        log_path: Path = DEFAULT_LOG_PATH,
        output_path: Path = DEFAULT_OUTPUT_PATH,
        backend_url: str = DEFAULT_BACKEND_URL,
        poll_seconds: float = 0.25,
        replay_existing: bool = False,
        backend_timeout_seconds: float = 2.0,
        backend_retry_seconds: float = 2.0,
        delivery_queue_size: int = 5000,
        delivery_function: DeliveryFunction | None = None,
    ) -> None:
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        if backend_timeout_seconds <= 0 or backend_retry_seconds <= 0:
            raise ValueError("backend timing values must be positive")
        if delivery_queue_size < 1:
            raise ValueError("delivery_queue_size must be positive")

        self.engine = engine
        self.log_path = Path(log_path).resolve()
        self.output_path = Path(output_path).resolve()
        self.backend_url = str(backend_url).strip()
        self.poll_seconds = float(poll_seconds)
        self.replay_existing = bool(replay_existing)
        self.backend_timeout_seconds = float(backend_timeout_seconds)
        self.backend_retry_seconds = float(backend_retry_seconds)
        self._delivery_function = delivery_function
        self._delivery_queue: queue.Queue[dict[str, Any]] = queue.Queue(
            maxsize=delivery_queue_size
        )
        self._write_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._delivery_thread: threading.Thread | None = None
        self.processed_count = 0
        self.skipped_count = 0

    def _deliver(self, record: dict[str, Any]) -> str:
        if self._delivery_function is not None:
            return self._delivery_function(record)
        return post_result_to_backend(
            self.backend_url,
            record,
            timeout_seconds=self.backend_timeout_seconds,
        )

    def _queue_backend_delivery(self, record: dict[str, Any]) -> None:
        if not self.backend_url and self._delivery_function is None:
            return
        try:
            self._delivery_queue.put_nowait(record)
        except queue.Full:
            print(
                "[REALTIME IDS] WARN: backend queue is full; "
                "the result remains available in JSONL.",
                file=sys.stderr,
            )

    def _delivery_worker(self) -> None:
        while not self._stop_event.is_set():
            try:
                record = self._delivery_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                while not self._stop_event.is_set():
                    outcome = self._deliver(record)
                    if outcome in {"success", "drop"}:
                        if outcome == "drop":
                            print(
                                "[REALTIME IDS] WARN: backend rejected an IDS "
                                f"result for event {record.get('event_id')}.",
                                file=sys.stderr,
                            )
                        break
                    self._stop_event.wait(self.backend_retry_seconds)
            finally:
                self._delivery_queue.task_done()

    def _start_delivery_worker(self) -> None:
        if not self.backend_url and self._delivery_function is None:
            return
        if self._delivery_thread is not None and self._delivery_thread.is_alive():
            return
        self._delivery_thread = threading.Thread(
            target=self._delivery_worker,
            name="ids-backend-delivery",
            daemon=True,
        )
        self._delivery_thread.start()

    def process_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        ids_result = self.engine.process_event(event)
        integrated = build_integrated_result(event, ids_result)
        _append_jsonl(
            self.output_path,
            integrated,
            lock=self._write_lock,
        )
        self._queue_backend_delivery(integrated)
        self.processed_count += 1
        return integrated

    def process_line(
        self,
        line: str,
        *,
        line_number: int | None = None,
    ) -> bool:
        try:
            value = json.loads(line)
            if not isinstance(value, Mapping):
                raise ValueError("JSON value is not an object")
            result = self.process_event(value)
        except (json.JSONDecodeError, ValueError, RuntimeError) as exc:
            location = f" line {line_number}" if line_number is not None else ""
            print(
                f"[REALTIME IDS] SKIP{location}: {exc}",
                file=sys.stderr,
            )
            self.skipped_count += 1
            return False

        print(
            "[REALTIME IDS] "
            f"{result['service']} | {result['attack_type']} | "
            f"{result['prediction']} | "
            f"threat={result['threat_level']}({result['threat_score']}) | "
            f"xai={result['xai']['shap']['status']}"
        )
        return True

    def process_existing(self) -> tuple[int, int]:
        if not self.log_path.is_file():
            raise FileNotFoundError(f"honeypot log not found: {self.log_path}")
        with self.log_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if line.strip():
                    self.process_line(line, line_number=line_number)
        return self.processed_count, self.skipped_count

    def _follow_log(self) -> None:
        print(f"[REALTIME IDS] Waiting for events in: {self.log_path}")
        while not self._stop_event.is_set() and not self.log_path.is_file():
            self._stop_event.wait(self.poll_seconds)
        if self._stop_event.is_set():
            return

        with self.log_path.open("r", encoding="utf-8") as handle:
            if not self.replay_existing:
                handle.seek(0, os.SEEK_END)
            line_number = 0
            while not self._stop_event.is_set():
                line = handle.readline()
                if not line:
                    self._stop_event.wait(self.poll_seconds)
                    continue
                line_number += 1
                if line.strip():
                    self.process_line(line, line_number=line_number)

    def run_forever(self) -> None:
        self._start_delivery_worker()
        try:
            self._follow_log()
        finally:
            self.engine.artifacts.verify_unchanged()
            print("[REALTIME IDS] PASS: Protected artifacts are unchanged.")

    def start(self) -> threading.Thread:
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("real-time IDS is already running")
        self._thread = threading.Thread(
            target=self.run_forever,
            name="realtime-hybrid-ids",
            daemon=True,
        )
        self._thread.start()
        return self._thread

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=max(0.0, timeout))
        if self._delivery_thread is not None:
            self._delivery_thread.join(timeout=max(0.0, timeout))


def create_realtime_ids_service(
    *,
    log_path: Path = DEFAULT_LOG_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    backend_url: str = DEFAULT_BACKEND_URL,
    replay_existing: bool = False,
    poll_seconds: float = 0.25,
    input_dir: Path = DEFAULT_INPUT_DIR,
    model_dir: Path = DEFAULT_MODEL_DIR,
    selection_path: Path = DEFAULT_SELECTION_PATH,
    device_name: str = "cpu",
) -> RealtimeIDSService:
    """Load protected artifacts once and construct the Step 16 service."""

    from machine_learning.hybrid_ids import (
        HybridIDSEngine,
        load_hybrid_artifacts,
    )

    artifacts = load_hybrid_artifacts(
        input_dir,
        model_dir,
        selection_path,
        device_name=device_name,
    )
    engine = HybridIDSEngine(artifacts)
    artifacts.verify_unchanged()
    print("[REALTIME IDS] PASS: Step 12 artifacts loaded without retraining.")
    print(
        "[REALTIME IDS] Models: rules + "
        f"{artifacts.tabular_model_name} + isolation_forest + lstm_classifier"
    )
    print(
        "[REALTIME IDS] Features/sequence: "
        f"{len(artifacts.feature_names)}/{artifacts.sequence_length}"
    )
    print(f"[REALTIME IDS] SHAP: {engine.xai_explainer.status}")
    return RealtimeIDSService(
        engine,
        log_path=log_path,
        output_path=output_path,
        backend_url=backend_url,
        replay_existing=replay_existing,
        poll_seconds=poll_seconds,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="load and verify protected inference artifacts, then exit",
    )
    mode.add_argument(
        "--once",
        action="store_true",
        help="process all currently stored common events, then exit",
    )
    parser.add_argument("--log-path", type=Path, default=DEFAULT_LOG_PATH)
    parser.add_argument("--output-path", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--no-backend", action="store_true")
    parser.add_argument("--replay-existing", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    service = create_realtime_ids_service(
        log_path=args.log_path,
        output_path=args.output_path,
        backend_url="" if args.no_backend else args.backend_url,
        replay_existing=args.replay_existing,
        poll_seconds=args.poll_seconds,
        device_name=args.device,
    )
    if args.check:
        service.engine.artifacts.verify_unchanged()
        print("[REALTIME IDS] PASS: Protected artifacts are unchanged.")
        return 0

    try:
        if args.once:
            service._start_delivery_worker()
            processed, skipped = service.process_existing()
            print(
                f"[REALTIME IDS] Completed: processed={processed}, "
                f"skipped={skipped}"
            )
            deadline = time.monotonic() + 5.0
            while (
                service._delivery_queue.unfinished_tasks
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)
            service.stop()
            service.engine.artifacts.verify_unchanged()
            print("[REALTIME IDS] PASS: Protected artifacts are unchanged.")
        else:
            service.run_forever()
    except KeyboardInterrupt:
        print("\n[REALTIME IDS] Stopped by user.")
        service.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
