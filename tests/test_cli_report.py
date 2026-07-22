from typer.testing import CliRunner

from secscan.cli import app
from secscan.state import StateStore

runner = CliRunner()


def _seed(tmp_path):
    store = StateStore(tmp_path / "secscan.sqlite3")
    store.record_result(
        "octo", "demo",
        critical=1, high=0, total=1,
        duration_s=1.0, cost_usd=0.1, reviewed_at="2026-07-01T00:00:00+00:00",
    )
    store.close()


def test_report_writes_summary_csv(tmp_path):
    _seed(tmp_path)
    result = runner.invoke(app, ["report", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Wrote" in result.output
    assert (tmp_path / "summary.csv").exists()


def test_report_dry_run_writes_nothing(tmp_path):
    _seed(tmp_path)
    result = runner.invoke(app, ["report", "--dry-run", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "would write" in result.output
    assert "1 repos" in result.output
    assert not (tmp_path / "summary.csv").exists()
