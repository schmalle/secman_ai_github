from typer.testing import CliRunner

import secscan.emailer as emailer
from secscan.cli import app
from secscan.findings import Finding
from secscan.state import StateStore

runner = CliRunner()


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
    store.close()


def _smtp_env(monkeypatch):
    monkeypatch.setenv("SMTP_USERNAME", "reports@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "pw")


def test_send_report_builds_and_sends(tmp_path, monkeypatch):
    _seed(tmp_path)
    _smtp_env(monkeypatch)
    sent = {}

    def fake_send(cfg, msg, smtp_factory=None):
        sent["cfg"] = cfg
        sent["msg"] = msg

    monkeypatch.setattr(emailer, "send_email", fake_send)

    result = runner.invoke(
        app,
        [
            "send-report",
            "--email-to", "sec@example.com",
            "--email-provider", "gmail",
            "--output-dir", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Sent report to sec@example.com" in result.output

    msg = sent["msg"]
    assert msg["To"] == "sec@example.com"
    assert msg["Subject"] == "secscan report: 1 critical, 1 high across 1 repos"
    html = next(
        p.get_content() for p in msg.iter_parts() if p.get_content_type() == "text/html"
    )
    assert "octo/demo" in html
    assert "SQLi" in html
    assert sent["cfg"].host == "smtp.gmail.com"


def test_send_report_max_findings_cap(tmp_path, monkeypatch):
    _seed(tmp_path)
    _smtp_env(monkeypatch)
    monkeypatch.setattr(emailer, "send_email", lambda cfg, msg, smtp_factory=None: None)

    result = runner.invoke(
        app,
        [
            "send-report",
            "--email-to", "sec@example.com",
            "--email-provider", "gmail",
            "--max-findings", "1",
            "--output-dir", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Including 1 of 2 findings" in result.output


def test_send_report_missing_credentials_exits_nonzero(tmp_path, monkeypatch):
    _seed(tmp_path)
    for var in ("SMTP_USERNAME", "SMTP_PASSWORD"):
        monkeypatch.delenv(var, raising=False)

    result = runner.invoke(
        app,
        ["send-report", "--email-to", "sec@example.com", "--email-provider", "gmail",
         "--output-dir", str(tmp_path)],
    )
    assert result.exit_code == 1
    assert "SMTP_USERNAME" in result.output
