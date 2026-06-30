import csv

from secscan.findings import (
    Finding,
    Severity,
    filter_high_critical,
    parse_findings,
    write_findings_csv,
    write_summary_csv,
)


def test_finding_coerces_severity_case_insensitively():
    f = Finding.model_validate(
        {
            "severity": "Critical",
            "title": "SQL injection in login",
            "description": "user input concatenated into query",
            "file_path": "app/db.py",
            "line_range": "42-58",
        }
    )
    assert f.severity is Severity.CRITICAL
    assert f.confidence  # defaulted


def test_parse_findings_from_dict_with_findings_key():
    data = {
        "findings": [
            {"severity": "high", "title": "A", "description": "d", "file_path": "x.py"},
            {"severity": "low", "title": "B", "description": "d", "file_path": "y.py"},
        ]
    }
    findings = parse_findings(data)
    assert len(findings) == 2


def test_parse_findings_from_text_with_fenced_json():
    text = (
        "Here is my analysis.\n\n```json\n"
        '{"findings": [{"severity": "critical", "title": "RCE", '
        '"description": "eval of user input", "file_path": "h.py", "line_range": "9"}]}'
        "\n```\nDone."
    )
    findings = parse_findings(text)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


def test_parse_findings_discards_malformed_entries():
    data = {
        "findings": [
            {"severity": "high", "title": "ok", "description": "d", "file_path": "a.py"},
            {"severity": "not-a-severity", "title": "bad"},  # invalid -> dropped
            {"title": "missing severity"},  # invalid -> dropped
        ]
    }
    findings = parse_findings(data)
    assert len(findings) == 1
    assert findings[0].title == "ok"


def test_parse_findings_empty_on_garbage():
    assert parse_findings("no json here at all") == []
    assert parse_findings({"unexpected": True}) == []


def test_filter_high_critical():
    findings = [
        Finding(severity=Severity.CRITICAL, title="c", description="d", file_path="a"),
        Finding(severity=Severity.HIGH, title="h", description="d", file_path="b"),
        Finding(severity=Severity.MEDIUM, title="m", description="d", file_path="c"),
        Finding(severity=Severity.LOW, title="l", description="d", file_path="d"),
    ]
    kept = filter_high_critical(findings)
    assert {f.severity for f in kept} == {Severity.CRITICAL, Severity.HIGH}


def test_write_findings_csv_roundtrip(tmp_path):
    findings = [
        Finding(
            severity=Severity.CRITICAL,
            title="SQLi",
            category="CWE-89",
            file_path="app/db.py",
            line_range="42-58",
            description="concatenated query",
            recommendation="use params",
            confidence="high",
        )
    ]
    out = write_findings_csv(tmp_path / "findings.csv", "octo/repo", findings)
    assert out.exists()
    with out.open() as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    assert rows[0]["severity"] == "critical"
    assert rows[0]["repo"] == "octo/repo"
    assert rows[0]["file_path"] == "app/db.py"


def test_write_findings_csv_writes_header_even_when_empty(tmp_path):
    out = write_findings_csv(tmp_path / "findings.csv", "octo/repo", [])
    assert out.exists()
    with out.open() as fh:
        rows = list(csv.reader(fh))
    assert rows and rows[0][0] == "repo"  # header present
    assert len(rows) == 1  # header only


def test_write_summary_csv(tmp_path):
    rows = [
        {
            "owner": "octo",
            "repo": "repo",
            "status": "done",
            "critical_count": 1,
            "high_count": 2,
            "total_findings": 3,
            "duration_s": 12.5,
            "cost_usd": 0.42,
            "reviewed_at": "2026-06-30T00:00:00Z",
            "error": "",
        }
    ]
    out = write_summary_csv(tmp_path / "summary.csv", rows)
    assert out.exists()
    with out.open() as fh:
        parsed = list(csv.DictReader(fh))
    assert parsed[0]["repo"] == "repo"
    assert parsed[0]["critical_count"] == "1"
