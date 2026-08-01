"""Open one GitHub issue per High/Critical finding, deduped by content fingerprint.

Mirrors emailer.py's style: a thin function, no framework. The caller resolves
GitHub auth and passes an already-authenticated PyGithub Repository object, so
this module has no credential knowledge and is trivial to test with a fake.
"""

from __future__ import annotations

from dataclasses import dataclass

from .findings import Finding, fingerprint
from .state import StateStore

DEFAULT_ISSUE_PREFIX = "secscan:"

# finding.* fields are LLM output about untrusted repository content, not
# reviewer-authored text. Unlike the emailed report (report_html._truncate,
# capped at 500 chars), this path had no cap at all, so a successful prompt
# injection could make secscan author and publish arbitrary-length attacker
# text as a public, secscan-labeled GitHub issue. Cap every field before it
# reaches the issue body/title; matches the email path's 500-char budget for
# the free-form fields and gives short structural ones (title/category/file
# path) a tighter bound of their own.
_TITLE_MAX = 200
_FIELD_MAX = 120
_BODY_FIELD_MAX = 500


def _truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class IssueOutcome:
    action: str  # "created" | "skipped" | "would_create"
    finding_title: str
    issue_url: str = ""


def _issue_title(finding: Finding, prefix: str) -> str:
    base = (
        f"{finding.severity.value}: {_truncate(finding.title, _TITLE_MAX)} "
        f"({_truncate(finding.file_path, _FIELD_MAX)})"
    )
    return f"{prefix} {base}" if prefix else base


def _issue_body(finding: Finding, fp: str) -> str:
    return (
        f"**Category:** {_truncate(finding.category, _FIELD_MAX) or '(none)'}\n"
        f"**Confidence:** {finding.confidence}\n"
        f"**File:** {_truncate(finding.file_path, _FIELD_MAX)} "
        f"({_truncate(finding.line_range, _FIELD_MAX) or 'line range unknown'})\n\n"
        f"{_truncate(finding.description, _BODY_FIELD_MAX)}\n\n"
        f"**Recommendation:**\n{_truncate(finding.recommendation, _BODY_FIELD_MAX)}\n\n"
        f"---\n_Opened automatically by secscan. Fingerprint: `{fp}`_"
    )


def process_finding(
    gh_repo,
    store: StateStore,
    owner: str,
    repo: str,
    finding: Finding,
    *,
    seen_at: str,
    dry_run: bool,
    prefix: str = DEFAULT_ISSUE_PREFIX,
) -> IssueOutcome:
    fp = fingerprint(finding)
    existing = store.find_issue(owner, repo, fp)

    if existing:
        if not dry_run:
            store.touch_issue_seen(owner, repo, fp, seen_at)
        return IssueOutcome(action="skipped", finding_title=finding.title, issue_url=existing.issue_url)

    if dry_run:
        return IssueOutcome(action="would_create", finding_title=finding.title)

    issue = gh_repo.create_issue(
        title=_issue_title(finding, prefix), body=_issue_body(finding, fp), labels=["secscan"]
    )
    store.record_issue_created(owner, repo, fp, issue.number, issue.html_url, seen_at)
    return IssueOutcome(action="created", finding_title=finding.title, issue_url=issue.html_url)
