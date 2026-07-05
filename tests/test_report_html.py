from html.parser import HTMLParser

from secscan.report_html import (
    build_report_html,
    build_report_text,
    default_subject,
    severity_sort_key,
)
from secscan.state import RepoRecord, Status

_VOID_TAGS = {"meta", "br", "hr", "img", "input", "link"}


class _BalanceChecker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag not in _VOID_TAGS:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            self.errors.append(f"unbalanced </{tag}>")


def _rec(owner="octo", repo="demo", critical=1, high=2):
    return RepoRecord(
        owner=owner,
        repo=repo,
        status=Status.DONE,
        critical_count=critical,
        high_count=high,
        total_findings=critical + high,
        cost_usd=0.5,
        reviewed_at="2026-07-01T00:00:00+00:00",
    )


def _finding(severity="critical", title="SQL injection", **kw):
    row = {
        "severity": severity,
        "title": title,
        "description": "user input concatenated into a query",
        "file_path": "app.py",
        "line_range": "10-12",
        "category": "CWE-89",
        "recommendation": "use parameterized queries",
        "repo_full_name": "octo/demo",
    }
    row.update(kw)
    return row


def test_html_is_wellformed_and_escapes_untrusted_strings():
    evil = _finding(title='<script>alert("xss")</script>', description="<img src=x>")
    html = build_report_html([_rec()], [evil], "2026-07-01T00:00:00+00:00")
    checker = _BalanceChecker()
    checker.feed(html)
    assert checker.errors == []
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x>" not in html


def test_html_contains_summary_rows_and_findings():
    html = build_report_html([_rec()], [_finding()], "2026-07-01T00:00:00+00:00")
    assert "octo/demo" in html
    assert "SQL injection" in html
    assert "CWE-89" in html
    assert "app.py:10-12" in html
    assert "use parameterized queries" in html
    assert html.lstrip().startswith("<!DOCTYPE html>")


def test_html_styles_are_inline_not_head_css():
    html = build_report_html([_rec()], [_finding()], "t")
    assert "<style" not in html  # email clients strip <head> CSS
    assert 'style="' in html


def test_text_alternative_mentions_counts_and_findings():
    text = build_report_text([_rec(critical=3, high=4)], [_finding()], "t")
    assert "3 critical" in text
    assert "4 high" in text
    assert "[CRITICAL] SQL injection" in text


def test_findings_sorted_critical_first():
    rows = [
        _finding(severity="low", title="c"),
        _finding(severity="critical", title="a"),
        _finding(severity="high", title="b"),
    ]
    rows.sort(key=severity_sort_key)
    assert [r["severity"] for r in rows] == ["critical", "high", "low"]


def test_default_subject_totals():
    subject = default_subject([_rec(critical=1, high=2), _rec(repo="two", critical=0, high=1)])
    assert subject == "secscan report: 1 critical, 3 high across 2 repos"


def test_empty_report_renders():
    html = build_report_html([], [], "t")
    assert "No high or critical findings" in html
    text = build_report_text([], [], "t")
    assert "no high or critical findings" in text
