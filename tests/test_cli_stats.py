import csv
import json

from typer.testing import CliRunner

from secscan.cli import app
from secscan.findings import Finding
from secscan.state import StateStore

runner = CliRunner()


def _seed(tmp_path):
    store = StateStore(tmp_path / "secscan.sqlite3")
    store.record_result(
        "octo", "big",
        critical=2, high=1, total=5,
        duration_s=10.0, cost_usd=0.50, reviewed_at="2026-07-02T00:00:00+00:00",
    )
    store.replace_findings(
        "octo", "big",
        [
            Finding(severity="critical", title="SQLi", description="d"),
            Finding(severity="critical", title="RCE", description="d"),
            Finding(severity="high", title="XSS", description="d"),
            Finding(severity="medium", title="CSRF", description="d"),
        ],
    )
    store.record_result(
        "octo", "small",
        critical=0, high=1, total=1,
        duration_s=5.0, cost_usd=0.25, reviewed_at="2026-07-01T00:00:00+00:00",
    )
    store.record_failure("octo", "broken", "clone failed")
    store.record_issue_created(
        "octo", "big", "fp1", 7, "https://github.com/octo/big/issues/7", "now"
    )
    store.close()


def test_stats_table_default(tmp_path):
    _seed(tmp_path)
    result = runner.invoke(app, ["stats", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "octo/big" in result.output
    assert "2 critical, 2 high" in result.output  # totals across repos
    assert "critical  2" in result.output  # severity breakdown
    assert "medium    1" in result.output
    assert "Issues tracked: 1" in result.output
    assert "Last review:    2026-07-02T00:00:00+00:00" in result.output


def test_stats_json(tmp_path):
    _seed(tmp_path)
    result = runner.invoke(app, ["stats", "--output-dir", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["repos"]["total"] == 3
    assert payload["repos"]["by_status"] == {"done": 2, "failed": 1}
    assert payload["findings"]["by_severity"] == {"critical": 2, "high": 1, "medium": 1}
    assert payload["totals"]["critical"] == 2
    assert payload["totals"]["failed"] == 1
    assert payload["issues_tracked"] == 1
    assert payload["top_repos"][0]["repo"] == "octo/big"


def test_stats_csv_to_file(tmp_path):
    _seed(tmp_path)
    out = tmp_path / "stats.csv"
    result = runner.invoke(
        app,
        ["stats", "--output-dir", str(tmp_path), "--format", "csv", "--output", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    rows = list(csv.DictReader(out.open()))
    assert len(rows) == 3
    assert rows[0]["repo"] == "octo/big"
    assert rows[0]["critical"] == "2"


def test_stats_dry_run_writes_nothing(tmp_path):
    _seed(tmp_path)
    out = tmp_path / "stats.csv"
    result = runner.invoke(
        app,
        [
            "stats", "--output-dir", str(tmp_path), "--format", "csv",
            "--output", str(out), "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "would write" in result.output
    assert not out.exists()


def test_stats_top_limits_repo_rows(tmp_path):
    _seed(tmp_path)
    result = runner.invoke(
        app, ["stats", "--output-dir", str(tmp_path), "--format", "json", "--top", "1"]
    )
    payload = json.loads(result.output)
    assert [r["repo"] for r in payload["top_repos"]] == ["octo/big"]


def test_stats_rejects_bogus_format(tmp_path):
    _seed(tmp_path)
    result = runner.invoke(
        app, ["stats", "--output-dir", str(tmp_path), "--format", "bogus"]
    )
    assert result.exit_code != 0


def test_stats_empty_db_is_sane(tmp_path):
    result = runner.invoke(app, ["stats", "--output-dir", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["repos"]["total"] == 0
    assert payload["findings"]["total"] == 0
    assert payload["last_reviewed_at"] == ""
    assert payload["top_repos"] == []
