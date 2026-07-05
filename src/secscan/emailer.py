"""Send HTML report emails over SMTP with STARTTLS.

Provider presets cover Gmail and Office 365 (both accept authenticated
submission on port 587 with STARTTLS):

- gmail: smtp.gmail.com:587 — requires an app password
  (https://myaccount.google.com/apppasswords; normal account passwords are
  rejected when 2FA is on, which Google now requires).
- o365:  smtp.office365.com:587 — requires SMTP AUTH ("authenticated client
  submission") to be enabled for the mailbox/tenant.
- custom: any SMTP server via SMTP_HOST / SMTP_PORT.

Credentials come from the environment only (SMTP_USERNAME / SMTP_PASSWORD),
matching the rest of secscan: secrets are never written to disk.
"""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate

from .config import ConfigError, _env

_PRESETS: dict[str, tuple[str, int]] = {
    "gmail": ("smtp.gmail.com", 587),
    "o365": ("smtp.office365.com", 587),
}

EMAIL_PROVIDERS = (*_PRESETS, "custom")


@dataclass
class EmailConfig:
    """SMTP connection settings. The password is held in memory only."""

    host: str
    port: int
    username: str
    password: str
    from_addr: str

    @classmethod
    def from_env(
        cls,
        provider: str = "custom",
        host: str | None = None,
        port: int | None = None,
    ) -> "EmailConfig":
        if provider not in EMAIL_PROVIDERS:
            raise ConfigError(
                f"email provider must be one of {', '.join(EMAIL_PROVIDERS)}; got {provider!r}"
            )

        preset = _PRESETS.get(provider)
        resolved_host = host or _env("SMTP_HOST") or (preset[0] if preset else None)
        if not resolved_host:
            raise ConfigError("SMTP_HOST (or --smtp-host) is required for --email-provider custom")
        resolved_port = port or int(_env("SMTP_PORT") or (preset[1] if preset else 587))

        username = _env("SMTP_USERNAME")
        password = _env("SMTP_PASSWORD")
        if not username or not password:
            raise ConfigError("SMTP_USERNAME and SMTP_PASSWORD are required to send email")

        return cls(
            host=resolved_host,
            port=resolved_port,
            username=username,
            password=password,
            from_addr=_env("SMTP_FROM") or username,
        )


def build_message(
    cfg: EmailConfig, to: list[str], subject: str, html: str, text: str
) -> EmailMessage:
    """Build a multipart/alternative message: plain text plus an HTML part."""
    msg = EmailMessage()
    msg["From"] = cfg.from_addr
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    return msg


def send_email(cfg: EmailConfig, msg: EmailMessage, smtp_factory=None) -> None:
    """Deliver the message over SMTP + STARTTLS (port 587 style submission)."""
    factory = smtp_factory or smtplib.SMTP
    try:
        with factory(cfg.host, cfg.port, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            smtp.login(cfg.username, cfg.password)
            smtp.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise ConfigError(
            f"SMTP login failed for {cfg.username}@{cfg.host}: {exc.smtp_code} — "
            "Gmail requires an app password; O365 requires SMTP AUTH enabled for the mailbox."
        ) from exc
