"""
notifications.py — Fire-and-forget SMTP + Slack webhook notifications.

Controlled by env vars. All delivery happens on a background thread so route
handlers never block on email/webhook I/O.

Enable:
    NOTIFY_ENABLED=1

SMTP (optional — skipped if SMTP_HOST is unset):
    SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASSWORD,
    SMTP_FROM (defaults to SMTP_USER), SMTP_USE_TLS (default 1)

Slack (optional — skipped if SLACK_WEBHOOK_URL is unset):
    SLACK_WEBHOOK_URL
"""
import os, smtplib, threading
from email.message import EmailMessage

import requests


def _enabled() -> bool:
    return os.getenv("NOTIFY_ENABLED", "0") == "1"


def _send_email(to_addr: str, subject: str, body: str) -> None:
    host = os.getenv("SMTP_HOST")
    if not host or not to_addr:
        return
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASSWORD", "")
    from_addr = os.getenv("SMTP_FROM", user) or user
    use_tls = os.getenv("SMTP_USE_TLS", "1") == "1"

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            if use_tls:
                s.starttls()
            if user:
                s.login(user, password)
            s.send_message(msg)
    except Exception as e:
        print(f"[notify] SMTP send failed: {e}")


def _send_slack(text: str) -> None:
    url = os.getenv("SLACK_WEBHOOK_URL")
    if not url:
        return
    try:
        requests.post(url, json={"text": text}, timeout=10)
    except Exception as e:
        print(f"[notify] Slack post failed: {e}")


def _deliver(to_addr: str, subject: str, body: str) -> None:
    _send_email(to_addr, subject, body)
    _send_slack(f"*{subject}*\n{body}")


def notify(to_addr: str, subject: str, body: str) -> None:
    """Queue a notification on a daemon thread. No-op if disabled."""
    if not _enabled():
        return
    threading.Thread(
        target=_deliver, args=(to_addr, subject, body), daemon=True
    ).start()
