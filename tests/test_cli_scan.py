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
