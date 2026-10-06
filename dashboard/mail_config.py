"""Private, untracked Gmail sender configuration for dashboard verification mail."""

from __future__ import annotations

import getpass
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


DEFAULT_MAIL_CONFIG = Path(__file__).resolve().parents[1] / "data" / "runtime" / "dashboard_mail.json"
_GMAIL_LOCAL_RE = re.compile(r"[a-z0-9.]+(?:\+[a-z0-9._-]+)?\Z")
_APP_PASSWORD_RE = re.compile(r"[A-Za-z0-9]{16}\Z")


@dataclass(frozen=True)
class MailConfig:
    sender_gmail: str
    gmail_app_password: str = field(repr=False)


def normalize_gmail_address(email: str) -> str:
    """Validate Gmail syntax and collapse aliases that reach the same inbox."""

    normalized = email.strip().lower()
    if normalized.count("@") != 1:
        raise ValueError("Enter a valid @gmail.com address")
    local, domain = normalized.split("@", 1)
    if (
        domain != "gmail.com"
        or not _GMAIL_LOCAL_RE.fullmatch(local)
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
    ):
        raise ValueError("Enter a valid @gmail.com address")
    canonical_local = local.split("+", 1)[0].replace(".", "")
    if not canonical_local or len(canonical_local) > 64:
        raise ValueError("Enter a valid @gmail.com address")
    return f"{canonical_local}@gmail.com"


def mail_config_path() -> Path:
    return Path(os.environ.get("DASHBOARD_MAIL_CONFIG", str(DEFAULT_MAIL_CONFIG))).resolve()


def _private_file_identity() -> str:
    try:
        result = subprocess.run(
            ["whoami"],
            check=False,
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        identity = result.stdout.strip()
        if result.returncode == 0 and identity:
            return identity
    except (OSError, subprocess.SubprocessError):
        pass
    username = os.environ.get("USERNAME", "").strip() or getpass.getuser()
    domain = os.environ.get("USERDOMAIN", "").strip()
    return f"{domain}\\{username}" if domain else username


@lru_cache(maxsize=32)
def _harden_private_file_cached(
    resolved_path: str, device: int, inode: int, modified_ns: int
) -> bool:
    del device, inode, modified_ns
    path = Path(resolved_path)
    try:
        if os.name == "nt":
            result = subprocess.run(
                [
                    "icacls",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{_private_file_identity()}:(F)",
                ],
                check=False,
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return result.returncode == 0
        os.chmod(path, 0o600)
        return stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
    except (OSError, subprocess.SubprocessError):
        return False


def harden_private_file_permissions(path: Path) -> bool:
    """Restrict a secret file to the current OS user, or report failure."""

    try:
        resolved = path.resolve(strict=True)
        details = resolved.stat()
    except OSError:
        return False
    return _harden_private_file_cached(
        str(resolved), details.st_dev, details.st_ino, details.st_mtime_ns
    )


def _validated_config(sender: object, password: object) -> MailConfig | None:
    try:
        normalized_sender = normalize_gmail_address(str(sender))
    except ValueError:
        return None
    normalized_password = str(password).replace(" ", "").strip()
    if (
        not _APP_PASSWORD_RE.fullmatch(normalized_password)
        or "replace" in str(sender).lower()
        or "replace" in normalized_password.lower()
    ):
        return None
    return MailConfig(normalized_sender, normalized_password)


def load_mail_config() -> MailConfig | None:
    env_sender = os.environ.get("DASHBOARD_SENDER_GMAIL", "").strip()
    env_password = os.environ.get("DASHBOARD_GMAIL_APP_PASSWORD", "").strip()
    if env_sender or env_password:
        if not env_sender or not env_password:
            return None
        return _validated_config(env_sender, env_password)

    path = mail_config_path()
    if not path.is_file() or not harden_private_file_permissions(path):
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    return _validated_config(value.get("sender_gmail", ""), value.get("gmail_app_password", ""))
