"""Private, untracked Gmail sender configuration for dashboard verification mail."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path


DEFAULT_MAIL_CONFIG = Path(__file__).resolve().parents[1] / "data" / "runtime" / "dashboard_mail.json"
_GMAIL_RE = re.compile(r"[a-z0-9][a-z0-9.+_-]{0,63}@gmail\.com\Z")


@dataclass(frozen=True)
class MailConfig:
    sender_gmail: str
    gmail_app_password: str


def mail_config_path() -> Path:
    return Path(os.environ.get("DASHBOARD_MAIL_CONFIG", str(DEFAULT_MAIL_CONFIG))).resolve()


def load_mail_config() -> MailConfig | None:
    path = mail_config_path()
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    sender = str(value.get("sender_gmail", "")).strip().lower()
    password = str(value.get("gmail_app_password", "")).replace(" ", "").strip()
    if (
        not _GMAIL_RE.fullmatch(sender)
        or not password
        or "replace" in sender
        or "replace" in password.lower()
    ):
        return None
    return MailConfig(sender, password)
