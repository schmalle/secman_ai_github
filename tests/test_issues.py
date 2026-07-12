from secscan.findings import Finding, fingerprint
from secscan.issues import process_finding
from secscan.state import StateStore


class _FakeIssue:
    def __init__(self, number, html_url):
        self.number = number
        self.html_url = html_url


class _FakeGhRepo:
    def __init__(self):
        self.created = []

    def create_issue(self, title, body, labels):
        issue = _FakeIssue(len(self.created) + 1, f"https://github.com/octo/repo/issues/{len(self.created) + 1}")
        self.created.append((title, body, labels))
        return issue


def _finding(**overrides):
    defaults = dict(
        severity="high", title="SQLi", description="Unsanitized input", file_path="app.py",
        line_range="10-12", category="CWE-89", recommendation="Use parameterized queries", confidence="high",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_new_finding_creates_issue_and_records_tracking(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    gh_repo = _FakeGhRepo()
    finding = _finding()

    outcome = process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-12T00:00:00+00:00", dry_run=False)

    assert outcome.action == "created"
    assert len(gh_repo.created) == 1
    title, body, labels = gh_repo.created[0]
    assert title == "[secscan] high: SQLi (app.py)"
    assert labels == ["secscan"]
    assert "Unsanitized input" in body
    assert "Use parameterized queries" in body

    tracked = store.find_issue("octo", "repo", fingerprint(finding))
    assert tracked is not None
    assert tracked.issue_number == 1


def test_repeated_finding_skips_and_touches_last_seen(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    gh_repo = _FakeGhRepo()
    finding = _finding()

    process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-01T00:00:00+00:00", dry_run=False)
    outcome = process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-12T00:00:00+00:00", dry_run=False)

    assert outcome.action == "skipped"
    assert len(gh_repo.created) == 1  # no second issue

    tracked = store.find_issue("octo", "repo", fingerprint(finding))
    assert tracked.first_seen_at == "2026-07-01T00:00:00+00:00"
    assert tracked.last_seen_at == "2026-07-12T00:00:00+00:00"


def test_dry_run_new_finding_makes_no_calls_or_writes(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    gh_repo = _FakeGhRepo()
    finding = _finding()

    outcome = process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-12T00:00:00+00:00", dry_run=True)

    assert outcome.action == "would_create"
    assert gh_repo.created == []
    assert store.find_issue("octo", "repo", fingerprint(finding)) is None


def test_dry_run_repeated_finding_reports_skip_without_touching(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    gh_repo = _FakeGhRepo()
    finding = _finding()

    process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-01T00:00:00+00:00", dry_run=False)
    outcome = process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-12T00:00:00+00:00", dry_run=True)

    assert outcome.action == "skipped"
    tracked = store.find_issue("octo", "repo", fingerprint(finding))
    assert tracked.last_seen_at == "2026-07-01T00:00:00+00:00"  # NOT bumped in dry-run
