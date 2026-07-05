import smtplib

import pytest

from secscan.config import ConfigError
from secscan.emailer import EmailConfig, build_message, send_email


class FakeSMTP:
    """Records the SMTP conversation instead of talking to a server."""

    instances: list["FakeSMTP"] = []
    login_error: Exception | None = None

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.calls = []
        self.sent = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.calls.append(("quit",))
        return False

    def ehlo(self):
        self.calls.append(("ehlo",))

    def starttls(self, context=None):
        self.calls.append(("starttls", context is not None))

    def login(self, username, password):
        if FakeSMTP.login_error:
            raise FakeSMTP.login_error
        self.calls.append(("login", username, password))

    def send_message(self, msg):
        self.calls.append(("send_message",))
        self.sent.append(msg)


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeSMTP.instances = []
    FakeSMTP.login_error = None


@pytest.fixture
def smtp_env(monkeypatch):
    monkeypatch.setenv("SMTP_USERNAME", "reports@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")
    for var in ("SMTP_HOST", "SMTP_PORT", "SMTP_FROM"):
        monkeypatch.delenv(var, raising=False)


def _cfg(**kw):
    defaults = dict(
        host="smtp.example.com",
        port=587,
        username="reports@example.com",
        password="pw",
        from_addr="reports@example.com",
    )
    defaults.update(kw)
    return EmailConfig(**defaults)


# -- EmailConfig.from_env ----------------------------------------------------------


def test_from_env_gmail_preset(smtp_env):
    cfg = EmailConfig.from_env("gmail")
    assert (cfg.host, cfg.port) == ("smtp.gmail.com", 587)


def test_from_env_o365_preset(smtp_env):
    cfg = EmailConfig.from_env("o365")
    assert (cfg.host, cfg.port) == ("smtp.office365.com", 587)


def test_from_env_custom_requires_host(smtp_env):
    with pytest.raises(ConfigError):
        EmailConfig.from_env("custom")


def test_from_env_custom_uses_env_host(smtp_env, monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "mail.internal")
    monkeypatch.setenv("SMTP_PORT", "2525")
    cfg = EmailConfig.from_env("custom")
    assert (cfg.host, cfg.port) == ("mail.internal", 2525)


def test_from_env_flag_host_overrides_preset(smtp_env):
    cfg = EmailConfig.from_env("gmail", host="relay.corp", port=25)
    assert (cfg.host, cfg.port) == ("relay.corp", 25)


def test_from_env_missing_credentials_raises(monkeypatch):
    for var in ("SMTP_USERNAME", "SMTP_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ConfigError):
        EmailConfig.from_env("gmail")


def test_from_env_unknown_provider_raises(smtp_env):
    with pytest.raises(ConfigError):
        EmailConfig.from_env("hotmail")


def test_from_addr_defaults_to_username(smtp_env):
    assert EmailConfig.from_env("gmail").from_addr == "reports@example.com"


def test_from_addr_env_override(smtp_env, monkeypatch):
    monkeypatch.setenv("SMTP_FROM", "noreply@example.com")
    assert EmailConfig.from_env("gmail").from_addr == "noreply@example.com"


# -- build_message ------------------------------------------------------------------


def test_message_is_multipart_alternative_with_html_and_text():
    msg = build_message(_cfg(), ["a@b.com", "c@d.com"], "subj", "<html>H</html>", "T")
    assert msg.get_content_type() == "multipart/alternative"
    parts = {p.get_content_type(): p for p in msg.iter_parts()}
    assert set(parts) == {"text/plain", "text/html"}
    assert "H" in parts["text/html"].get_content()
    assert parts["text/plain"].get_content().strip() == "T"
    assert msg["To"] == "a@b.com, c@d.com"
    assert msg["Subject"] == "subj"
    assert msg["From"] == "reports@example.com"
    assert msg["Date"]


# -- send_email ----------------------------------------------------------------------


def test_send_email_starttls_login_send_sequence():
    cfg = _cfg()
    msg = build_message(cfg, ["a@b.com"], "s", "<p>h</p>", "t")
    send_email(cfg, msg, smtp_factory=FakeSMTP)

    (smtp,) = FakeSMTP.instances
    assert (smtp.host, smtp.port) == ("smtp.example.com", 587)
    assert smtp.calls == [
        ("ehlo",),
        ("starttls", True),  # True: an SSL context was passed
        ("ehlo",),
        ("login", "reports@example.com", "pw"),
        ("send_message",),
        ("quit",),
    ]
    assert smtp.sent == [msg]


def test_send_email_auth_failure_becomes_config_error():
    FakeSMTP.login_error = smtplib.SMTPAuthenticationError(535, b"bad credentials")
    cfg = _cfg()
    msg = build_message(cfg, ["a@b.com"], "s", "<p>h</p>", "t")
    with pytest.raises(ConfigError, match="app password"):
        send_email(cfg, msg, smtp_factory=FakeSMTP)
