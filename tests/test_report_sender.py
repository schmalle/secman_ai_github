import pytest

import secscan.emailer as emailer
from secscan.config import ConfigError
from secscan.findings import Finding
from secscan.report_sender import send_scan_report
from secscan.state import StateStore


def _seed(tmp_path):
    store = StateStore(tmp_path / "secscan.sqlite3")
    store.record_result(
        "octo", "demo",
        critical=1, high=1, total=2,
        duration_s=3.0, cost_usd=0.1, reviewed_at="2026-07-01T00:00:00+00:00",
    )
    store.replace_findings(
        "octo", "demo",
        [
            Finding(severity="critical", title="SQLi", description="d"),
            Finding(severity="high", title="XSS", description="d"),
        ],
    )
    return store


def _smtp_env(monkeypatch):
    monkeypatch.setenv("SMTP_USERNAME", "reports@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "pw")


def test_send_scan_report_builds_and_sends(tmp_path, monkeypatch):
    store = _seed(tmp_path)
    _smtp_env(monkeypatch)
    sent = {}

    def fake_send(cfg, msg, smtp_factory=None):
        sent["cfg"] = cfg
        sent["msg"] = msg

    monkeypatch.setattr(emailer, "send_email", fake_send)

    n_repos, n_findings = send_scan_report(store, ["sec@example.com"], provider="gmail")

    assert (n_repos, n_findings) == (1, 2)
    msg = sent["msg"]
    assert msg["To"] == "sec@example.com"
    assert msg["Subject"] == "secscan report: 1 critical, 1 high across 1 repos"
    html = next(
        p.get_content() for p in msg.iter_parts() if p.get_content_type() == "text/html"
    )
    assert "octo/demo" in html and "SQLi" in html
    assert sent["cfg"].host == "smtp.gmail.com"


def test_send_scan_report_caps_findings(tmp_path, monkeypatch, capsys):
    store = _seed(tmp_path)
    _smtp_env(monkeypatch)
    monkeypatch.setattr(emailer, "send_email", lambda cfg, msg, smtp_factory=None: None)

    n_repos, n_findings = send_scan_report(store, ["sec@example.com"], provider="gmail", max_findings=1)

    assert n_findings == 1
    assert "Including 1 of 2 findings" in capsys.readouterr().out


def test_send_scan_report_custom_subject(tmp_path, monkeypatch):
    store = _seed(tmp_path)
    _smtp_env(monkeypatch)
    sent = {}
    monkeypatch.setattr(
        emailer, "send_email", lambda cfg, msg, smtp_factory=None: sent.update(msg=msg)
    )

    send_scan_report(store, ["sec@example.com"], provider="gmail", subject="custom subject")

    assert sent["msg"]["Subject"] == "custom subject"


def test_send_scan_report_missing_credentials_raises(tmp_path, monkeypatch):
    store = _seed(tmp_path)
    for var in ("SMTP_USERNAME", "SMTP_PASSWORD"):
        monkeypatch.delenv(var, raising=False)

    with pytest.raises(ConfigError):
        send_scan_report(store, ["sec@example.com"], provider="gmail")
