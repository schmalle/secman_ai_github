import csv

from secscan.findings import (
    Finding,
    Severity,
    filter_high_critical,
    fingerprint,
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


def test_write_findings_csv_neutralizes_formula_leaders(tmp_path):
    """A repo can name a vulnerable file '=cmd|...'!A0.py' with no LLM
    involvement at all; the real finding secscan makes about it must not turn
    into an executable formula when the operator opens findings.csv."""
    findings = [
        Finding(
            severity=Severity.HIGH,
            title="=HYPERLINK(\"http://evil/\",\"steal\")",
            category="+cmd|'/C calc'!A0",
            file_path="=cmd|'/C calc'!A0.py",
            line_range="1-1",
            description="@SUM(1,1)",
            recommendation="-2+3",
            confidence="high",
        )
    ]
    out = write_findings_csv(tmp_path / "findings.csv", "=octo/repo", findings)
    with out.open() as fh:
        rows = list(csv.DictReader(fh))
    row = rows[0]
    for field in ("repo", "title", "category", "file_path", "description", "recommendation"):
        assert row[field].startswith("'"), f"{field} not neutralized: {row[field]!r}"


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


def test_write_summary_csv_neutralizes_formula_leaders(tmp_path):
    rows = [
        {
            "owner": "octo",
            "repo": "repo",
            "status": "error",
            "critical_count": 0,
            "high_count": 0,
            "total_findings": 0,
            "duration_s": 1.0,
            "cost_usd": 0.0,
            "reviewed_at": "2026-06-30T00:00:00Z",
            "error": "=cmd|'/C calc'!A0",
        }
    ]
    out = write_summary_csv(tmp_path / "summary.csv", rows)
    with out.open() as fh:
        parsed = list(csv.DictReader(fh))
    assert parsed[0]["error"].startswith("'")


def test_fingerprint_stable_across_line_range_changes():
    a = Finding(severity="high", title="SQLi", description="d", file_path="x.py", line_range="10-12", category="CWE-89")
    b = Finding(severity="high", title="SQLi", description="d", file_path="x.py", line_range="99-101", category="CWE-89")
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_differs_on_title():
    a = Finding(severity="high", title="SQLi", description="d", file_path="x.py")
    b = Finding(severity="high", title="XSS", description="d", file_path="x.py")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_differs_on_severity():
    a = Finding(severity="high", title="SQLi", description="d", file_path="x.py")
    b = Finding(severity="critical", title="SQLi", description="d", file_path="x.py")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_is_hex_sha256():
    f = Finding(severity="high", title="SQLi", description="d", file_path="x.py")
    fp = fingerprint(f)
    assert len(fp) == 64
    int(fp, 16)  # raises ValueError if not hex


def test_fingerprint_stable_across_description_changes():
    a = Finding(severity="high", title="SQLi", description="one description", file_path="x.py")
    b = Finding(severity="high", title="SQLi", description="a totally different description", file_path="x.py")
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_differs_on_category():
    a = Finding(severity="high", title="SQLi", description="d", file_path="x.py", category="CWE-89")
    b = Finding(severity="high", title="SQLi", description="d", file_path="x.py", category="CWE-79")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_differs_on_file_path():
    a = Finding(severity="high", title="SQLi", description="d", file_path="x.py")
    b = Finding(severity="high", title="SQLi", description="d", file_path="y.py")
    assert fingerprint(a) != fingerprint(b)
