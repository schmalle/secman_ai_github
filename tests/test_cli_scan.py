from typer.testing import CliRunner

from secscan.cli import app

runner = CliRunner()


def test_scan_rejects_bad_name(tmp_path):
    for bad in ("noslash", "a/b/c", "/name", "owner/"):
        result = runner.invoke(app, ["scan", bad, "--output-dir", str(tmp_path)])
        assert result.exit_code != 0, bad


def test_scan_no_db_and_create_issues_reports_clean_error_not_traceback(tmp_path):
    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path), "--no-db", "--create-issues"],
    )

    assert result.exit_code != 0
    # A clean ConfigError message via typer.Exit(1), not an unhandled traceback.
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "no-db" in result.output and "create-issues" in result.output


def test_run_no_db_and_create_issues_reports_clean_error_not_traceback(tmp_path):
    result = runner.invoke(
        app,
        ["run", "--output-dir", str(tmp_path), "--no-db", "--create-issues"],
    )

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "no-db" in result.output and "create-issues" in result.output


def test_scan_branch_flag_reaches_config(tmp_path, monkeypatch):
    import secscan.orchestrator

    captured = {}

    async def fake_scan_repo(cfg, owner, name):
        captured["cfg"] = cfg
        captured["target"] = (owner, name)

    monkeypatch.setattr(secscan.orchestrator, "scan_repo", fake_scan_repo)

    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path), "--branch", "dev"],
    )

    assert result.exit_code == 0
    assert captured["cfg"].branch == "dev"
    assert captured["target"] == ("octo", "demo")


def test_scan_branch_defaults_to_none(tmp_path, monkeypatch):
    import secscan.orchestrator

    captured = {}

    async def fake_scan_repo(cfg, owner, name):
        captured["cfg"] = cfg

    monkeypatch.setattr(secscan.orchestrator, "scan_repo", fake_scan_repo)

    result = runner.invoke(app, ["scan", "octo/demo", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0
    assert captured["cfg"].branch is None


def test_scan_no_db_and_email_to_reports_clean_error(tmp_path):
    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path),
         "--no-db", "--email-to", "sec@example.com"],
    )

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "no-db" in result.output and "email-to" in result.output


def test_run_no_db_and_email_to_reports_clean_error(tmp_path):
    result = runner.invoke(
        app,
        ["run", "--output-dir", str(tmp_path), "--no-db", "--email-to", "sec@example.com"],
    )

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "no-db" in result.output and "email-to" in result.output


def test_run_email_to_missing_smtp_creds_fails_fast(tmp_path, monkeypatch):
    import secscan.orchestrator

    for var in ("SMTP_USERNAME", "SMTP_PASSWORD"):
        monkeypatch.delenv(var, raising=False)

    called = []

    async def fake_run_scan(cfg, **kwargs):
        called.append(1)

    monkeypatch.setattr(secscan.orchestrator, "run_scan", fake_run_scan)

    result = runner.invoke(
        app,
        ["run", "--output-dir", str(tmp_path),
         "--email-to", "sec@example.com", "--email-provider", "gmail"],
    )

    assert result.exit_code == 1
    assert "SMTP_USERNAME" in result.output
    assert called == []  # scan never started


def test_scan_email_flags_reach_config(tmp_path, monkeypatch):
    import secscan.orchestrator

    monkeypatch.setenv("SMTP_USERNAME", "reports@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "pw")

    captured = {}

    async def fake_scan_repo(cfg, owner, name):
        captured["cfg"] = cfg

    monkeypatch.setattr(secscan.orchestrator, "scan_repo", fake_scan_repo)

    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path),
         "--email-to", "a@x.com", "--email-to", "b@y.com",
         "--email-provider", "gmail", "--subject", "weekly scan"],
    )

    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.email_to == ["a@x.com", "b@y.com"]
    assert cfg.email_provider == "gmail"
    assert cfg.email_subject == "weekly scan"
