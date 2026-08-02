from typer.testing import CliRunner

import secscan.secman_client as secman_client
from secscan.cli import app
from secscan.findings import Finding, fingerprint
from secscan.state import StateStore

runner = CliRunner()


def _seed(tmp_path):
    store = StateStore(tmp_path / "secscan.sqlite3")
    store.record_result(
        "octo", "demo",
        critical=1, high=1, total=3,
        duration_s=1.0, cost_usd=0.1, reviewed_at="2026-07-01T00:00:00+00:00",
    )
    store.replace_findings(
        "octo", "demo",
        [
            Finding(severity="critical", title="SQLi", description="d", file_path="a.py", category="CWE-89"),
            Finding(severity="high", title="XSS", description="d", file_path="b.py"),
            Finding(severity="medium", title="Weak crypto", description="d", file_path="c.py"),
        ],
    )
    store.close()


def _secman_env(monkeypatch):
    monkeypatch.setenv("SECMAN_URL", "https://secman.example.com")
    monkeypatch.setenv("SECMAN_USERNAME", "vulnbot")
    monkeypatch.setenv("SECMAN_PASSWORD", "pw")


def test_push_to_secman_pushes_only_high_critical(tmp_path, monkeypatch):
    _seed(tmp_path)
    _secman_env(monkeypatch)

    monkeypatch.setattr(secman_client, "login", lambda url, u, p: "tok")
    pushed = []

    def fake_push(url, token, *, hostname, cve, criticality, days_open):
        pushed.append((hostname, cve, criticality, days_open))
        return {"operation": "CREATED"}

    monkeypatch.setattr(secman_client, "push_vulnerability", fake_push)

    result = runner.invoke(app, ["push-to-secman", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert len(pushed) == 2  # only critical + high, not medium
    hostnames = {p[0] for p in pushed}
    assert hostnames == {"octo/demo"}
    criticalities = {p[2] for p in pushed}
    assert criticalities == {"CRITICAL", "HIGH"}
    assert "pushed 2" in result.output


def test_push_to_secman_dry_run_makes_no_calls(tmp_path, monkeypatch):
    _seed(tmp_path)
    _secman_env(monkeypatch)

    login_called = []
    monkeypatch.setattr(secman_client, "login", lambda url, u, p: login_called.append(1) or "tok")
    push_called = []
    monkeypatch.setattr(
        secman_client, "push_vulnerability",
        lambda *a, **kw: push_called.append(1) or {"operation": "CREATED"},
    )

    result = runner.invoke(app, ["push-to-secman", "--dry-run", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert login_called == []
    assert push_called == []
    assert "would push 2" in result.output


def test_push_to_secman_missing_credentials_fails_clearly(tmp_path, monkeypatch):
    _seed(tmp_path)
    for var in ("SECMAN_URL", "SECMAN_USERNAME", "SECMAN_PASSWORD"):
        monkeypatch.delenv(var, raising=False)

    result = runner.invoke(app, ["push-to-secman", "--output-dir", str(tmp_path)])

    assert result.exit_code != 0
    assert "secman" in result.output.lower()


def test_push_to_secman_one_failure_does_not_abort_run(tmp_path, monkeypatch):
    _seed(tmp_path)
    _secman_env(monkeypatch)
    monkeypatch.setattr(secman_client, "login", lambda url, u, p: "tok")

    calls = []

    def fake_push(url, token, *, hostname, cve, criticality, days_open):
        calls.append(cve)
        if len(calls) == 1:
            raise secman_client.SecmanPushError("400 bad request")
        return {"operation": "CREATED"}

    monkeypatch.setattr(secman_client, "push_vulnerability", fake_push)

    result = runner.invoke(app, ["push-to-secman", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert len(calls) == 2  # both findings attempted despite the first failing
    assert "failed 1" in result.output


def test_push_to_secman_cve_format_and_days_open_default_zero(tmp_path, monkeypatch):
    _seed(tmp_path)
    _secman_env(monkeypatch)
    monkeypatch.setattr(secman_client, "login", lambda url, u, p: "tok")

    pushed = []
    monkeypatch.setattr(
        secman_client, "push_vulnerability",
        lambda url, token, **kw: pushed.append(kw) or {"operation": "CREATED"},
    )

    runner.invoke(app, ["push-to-secman", "--output-dir", str(tmp_path)])

    sqli = next(p for p in pushed if p["hostname"] == "octo/demo" and p["criticality"] == "CRITICAL")
    assert sqli["cve"].startswith("SECSCAN:CWE-89:")
    assert sqli["days_open"] == 0  # no issue_tracking row exists for this finding


def test_push_to_secman_long_category_is_truncated(tmp_path, monkeypatch):
    """row['category'] is LLM output about untrusted repository content; a
    prompt-injection payload could try to make secscan push an arbitrarily
    long attacker-chosen string as the 'cve' identifier into secman. It must
    be capped before it reaches secman_client.push_vulnerability, mirroring
    the GitHub-issue path's field caps (test_issues.py)."""
    store = StateStore(tmp_path / "secscan.sqlite3")
    store.record_result(
        "octo", "demo",
        critical=1, high=0, total=1,
        duration_s=1.0, cost_usd=0.1, reviewed_at="2026-07-01T00:00:00+00:00",
    )
    store.replace_findings(
        "octo", "demo",
        [
            Finding(
                severity="critical", title="Injected", description="d", file_path="a.py",
                category="D" * 1000,
            ),
        ],
    )
    store.close()
    _secman_env(monkeypatch)

    monkeypatch.setattr(secman_client, "login", lambda url, u, p: "tok")
    pushed = []
    monkeypatch.setattr(
        secman_client, "push_vulnerability",
        lambda url, token, **kw: pushed.append(kw) or {"operation": "CREATED"},
def test_push_to_secman_dry_run_via_env(tmp_path, monkeypatch):
    _seed(tmp_path)
    _secman_env(monkeypatch)
    monkeypatch.setenv("SECSCAN_DRY_RUN", "true")

    monkeypatch.setattr(secman_client, "login", lambda url, u, p: "tok")
    monkeypatch.setattr(
        secman_client, "push_vulnerability",
        lambda *a, **kw: {"operation": "CREATED"},
    )

    result = runner.invoke(app, ["push-to-secman", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert len(pushed) == 1
    cve = pushed[0]["cve"]
    assert "D" * 1000 not in cve
    assert len(cve) < 300
    assert "would push 2" in result.output


def test_push_to_secman_dry_run_needs_no_credentials(tmp_path, monkeypatch):
    """Nothing is contacted, so missing secman credentials must not block a preview."""
    _seed(tmp_path)
    for var in ("SECMAN_URL", "SECMAN_USERNAME", "SECMAN_PASSWORD"):
        monkeypatch.delenv(var, raising=False)

    result = runner.invoke(app, ["push-to-secman", "--dry-run", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "would push 2" in result.output


def test_push_to_secman_dry_run_arms_the_guard(tmp_path, monkeypatch):
    """The real client (not a stub) must refuse to talk to secman during a dry run."""
    from secscan import dryrun

    _seed(tmp_path)
    _secman_env(monkeypatch)

    result = runner.invoke(app, ["push-to-secman", "--dry-run", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert dryrun.is_active() is True
    import pytest

    with pytest.raises(dryrun.DryRunViolation):
        secman_client.login("https://secman.example.com", "u", "p")
