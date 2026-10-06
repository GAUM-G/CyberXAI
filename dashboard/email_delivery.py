"""Send dashboard signup codes through a configured Gmail SMTP sender."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from .mail_config import load_mail_config


def mail_is_configured() -> bool:
    return load_mail_config() is not None


def send_signup_code(recipient: str, code: str) -> None:
    config = load_mail_config()
    if config is None:
        raise RuntimeError("Gmail SMTP sender is not configured")
    message = EmailMessage()
    message["From"] = config.sender_gmail
    message["To"] = recipient
    message["Subject"] = "Your defender dashboard verification code"
    message.set_content(
        f"Your dashboard signup code is {code}.\n\n"
        "It expires in 10 minutes and can be used once. "
        "If you did not request it, ignore this email.\n"
    )
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl.create_default_context())
        smtp.ehlo()
        smtp.login(config.sender_gmail, config.gmail_app_password)
        smtp.send_message(message)
