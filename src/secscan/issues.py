"""Open one GitHub issue per High/Critical finding, deduped by content fingerprint.

Mirrors emailer.py's style: a thin function, no framework. The caller resolves
GitHub auth and passes an already-authenticated PyGithub Repository object, so
this module has no credential knowledge and is trivial to test with a fake.
"""

from __future__ import annotations

from dataclasses import dataclass

from .findings import Finding, fingerprint
from .state import StateStore


@dataclass
class IssueOutcome:
    action: str  # "created" | "skipped" | "would_create"
    finding_title: str
    issue_url: str = ""


DEFAULT_TITLE_PREFIX = "[secscan]"


def _issue_title(finding: Finding, title_prefix: str) -> str:
    return f"{title_prefix} {finding.severity.value}: {finding.title} ({finding.file_path})"


def _issue_body(finding: Finding, fp: str) -> str:
    return (
        f"**Category:** {finding.category or '(none)'}\n"
        f"**Confidence:** {finding.confidence}\n"
        f"**File:** {finding.file_path} ({finding.line_range or 'line range unknown'})\n\n"
        f"{finding.description}\n\n"
        f"**Recommendation:**\n{finding.recommendation}\n\n"
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
    title_prefix: str = DEFAULT_TITLE_PREFIX,
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
        title=_issue_title(finding, title_prefix), body=_issue_body(finding, fp), labels=["secscan"]
    )
    store.record_issue_created(owner, repo, fp, issue.number, issue.html_url, seen_at)
    return IssueOutcome(action="created", finding_title=finding.title, issue_url=issue.html_url)
