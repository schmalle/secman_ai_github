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


def test_stats_reset_clears_stats_but_keeps_targets_and_issues(tmp_path):
    _seed(tmp_path)
    store = StateStore(tmp_path / "secscan.sqlite3")
    store.add_target("octo", "big")
    store.close()

    result = runner.invoke(app, ["stats", "reset", "--output-dir", str(tmp_path), "--yes"])

    assert result.exit_code == 0, result.output
    assert "3 repo records" in result.output and "4 findings" in result.output

    store = StateStore(tmp_path / "secscan.sqlite3")
    assert store.all_records() == []
    assert store.severity_counts() == {}
    assert store.list_targets() == [("octo", "big")]
    assert store.issue_count() == 1


def test_stats_reset_declined_changes_nothing(tmp_path):
    _seed(tmp_path)

    result = runner.invoke(
        app, ["stats", "reset", "--output-dir", str(tmp_path)], input="n\n"
    )

    assert result.exit_code != 0
    store = StateStore(tmp_path / "secscan.sqlite3")
    assert len(store.all_records()) == 3


def test_stats_reset_include_csv_removes_generated_csvs_only(tmp_path):
    _seed(tmp_path)
    (tmp_path / "summary.csv").write_text("repo\n")
    repo_dir = tmp_path / "octo__big"
    repo_dir.mkdir()
    (repo_dir / "findings.csv").write_text("repo\n")
    (tmp_path / "notes.txt").write_text("keep me\n")

    result = runner.invoke(
        app, ["stats", "reset", "--output-dir", str(tmp_path), "--yes", "--include-csv"]
    )

    assert result.exit_code == 0, result.output
    assert "2 CSV files" in result.output
    assert not (tmp_path / "summary.csv").exists()
    assert not repo_dir.exists()  # emptied, so removed
    assert (tmp_path / "notes.txt").exists()
    assert (tmp_path / "secscan.sqlite3").exists()


def test_stats_reset_leaves_csvs_alone_by_default(tmp_path):
    _seed(tmp_path)
    (tmp_path / "summary.csv").write_text("repo\n")

    result = runner.invoke(app, ["stats", "reset", "--output-dir", str(tmp_path), "--yes"])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "summary.csv").exists()


def test_stats_empty_db_is_sane(tmp_path):
    result = runner.invoke(app, ["stats", "--output-dir", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["repos"]["total"] == 0
    assert payload["findings"]["total"] == 0
    assert payload["last_reviewed_at"] == ""
    assert payload["top_repos"] == []


def test_stats_reports_fix_prs(tmp_path):
    import json

    from secscan.state import StateStore

    store = StateStore(tmp_path / "secscan.sqlite3")
    store.record_fix_pr("octo", "demo", "k" * 64, 7, "https://github.com/octo/demo/pull/7", "secscan/fix-k", "now")
    store.close()
    result = runner.invoke(app, ["stats", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Fix PRs opened: 1" in result.output
    result = runner.invoke(app, ["stats", "--format", "json", "--output-dir", str(tmp_path)])
    assert json.loads(result.output)["fix_prs_tracked"] == 1
