"""Small stateful detectors that correlate events across honeypot services."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class PortScanFinding:
    """Evidence produced when one source reaches several destination ports."""

    source_ip: str
    observed_ports: tuple[int, ...]
    threshold: int
    window_seconds: float


class PortScanDetector:
    """Detect distinct destination-port probes inside a rolling time window."""

    def __init__(self, threshold: int = 3, window_seconds: float = 30.0) -> None:
        if threshold < 2:
            raise ValueError("threshold must be at least 2")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.threshold = threshold
        self.window_seconds = window_seconds
        self._observations: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._last_alerted_ports: dict[str, frozenset[int]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _normalize_port(destination_port: int | str | None) -> int | None:
        try:
            port = int(destination_port) if destination_port is not None else None
        except (TypeError, ValueError):
            return None
        return port if port is not None and 0 <= port <= 65535 else None

    def register(
        self,
        source_ip: str,
        destination_port: int | str | None,
        *,
        now: float | None = None,
    ) -> PortScanFinding | None:
        """Register one observation and return a new finding at the threshold."""

        normalized_ip = str(source_ip).strip()
        normalized_port = self._normalize_port(destination_port)
        if not normalized_ip or normalized_ip == "unknown" or normalized_port is None:
            return None

        observed_at = time.monotonic() if now is None else float(now)
        cutoff = observed_at - self.window_seconds

        with self._lock:
            history = self._observations[normalized_ip]
            while history and history[0][0] < cutoff:
                history.popleft()
            history.append((observed_at, normalized_port))

            ports = frozenset(port for _, port in history)
            if len(ports) < self.threshold:
                self._last_alerted_ports.pop(normalized_ip, None)
                return None

            previous_alert = self._last_alerted_ports.get(normalized_ip)
            if previous_alert is not None and ports.issubset(previous_alert):
                return None

            self._last_alerted_ports[normalized_ip] = ports
            return PortScanFinding(
                source_ip=normalized_ip,
                observed_ports=tuple(sorted(ports)),
                threshold=self.threshold,
                window_seconds=self.window_seconds,
            )

    def reset(self) -> None:
        """Clear observations; useful for isolated tests and fresh lab runs."""

        with self._lock:
            self._observations.clear()
            self._last_alerted_ports.clear()
