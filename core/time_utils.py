"""Runtime timestamp helpers for Indian Standard Time (UTC+05:30).

The IDS may normalize timestamps to UTC internally for comparisons and model
features.  Every timestamp recorded or returned by the live system is emitted
with the explicit IST offset so operators do not have to guess the timezone.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


IST = timezone(timedelta(hours=5, minutes=30), name="IST")
UTC = timezone.utc
IST_OFFSET = "+05:30"


def parse_datetime(value: Any, *, naive_timezone: timezone = UTC) -> datetime:
    """Parse an ISO timestamp and return an aware datetime."""

    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            raise ValueError("timestamp must not be empty")
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=naive_timezone)
    return parsed


def to_ist(value: Any) -> datetime:
    """Convert a datetime or ISO timestamp to IST."""

    return parse_datetime(value).astimezone(IST)


def to_ist_iso(value: Any, *, timespec: str = "microseconds") -> str:
    """Return an ISO-8601 timestamp ending in the explicit +05:30 offset."""

    return to_ist(value).isoformat(timespec=timespec)


def now_ist() -> datetime:
    """Return the current aware IST datetime."""

    return datetime.now(IST)


def now_ist_iso(*, timespec: str = "microseconds") -> str:
    """Return the current time as ISO-8601 with the IST offset."""

    return now_ist().isoformat(timespec=timespec)
