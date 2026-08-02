"""Push High/Critical findings from the state store into secman.

Shared by the `push-to-secman` command (which pushes every record in the state
DB) and by `scan` / `run` with `--push-to-secman` (which push only the repos
that invocation reviewed). The HTTP details live in `secman_client`.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import typer

from . import secman_client
from .findings import fingerprint
from .issues import _FIELD_MAX, _truncate


def resolve_credentials(
    url: str | None, username: str | None, password: str | None
) -> tuple[str | None, str | None, str | None]:
    """Explicit value first, then SECMAN_URL / SECMAN_USERNAME / SECMAN_PASSWORD."""
    return (
        url or os.environ.get("SECMAN_URL") or None,
        username or os.environ.get("SECMAN_USERNAME") or None,
        password or os.environ.get("SECMAN_PASSWORD") or None,
    )


def _cve_and_days_open(store, owner: str, repo: str, row) -> tuple[str, int]:
    class _RowFinding:
        severity = type("S", (), {"value": row["severity"]})()
        category = row["category"]
        title = row["title"]
        file_path = row["file_path"]

    fp = fingerprint(_RowFinding())
    issue = store.find_issue(owner, repo, fp)
    days_open = 0
    if issue is not None:
        first_seen = datetime.fromisoformat(issue.first_seen_at)
        days_open = max(0, (datetime.now(timezone.utc) - first_seen).days)
    # row["category"] is LLM output about untrusted repository content (see
    # issues.py's _issue_body for the same concern on the GitHub issue path);
    # cap it before it becomes part of the identifier pushed to secman's
    # vulnerability tracker.
    cve = f"SECSCAN:{_truncate(row['category'], _FIELD_MAX) or 'FINDING'}:{fp[:12]}"
    return cve, days_open


def push_records(
    store,
    records,
    *,
    url: str | None,
    username: str | None,
    password: str | None,
    dry_run: bool,
) -> tuple[int, int]:
    """Push each record's High/Critical findings; return (pushed, failed).

    Logs in once. A login failure raises SecmanPushError for the caller to act on;
    a single rejected finding is reported and counted, and the rest still push.
    A dry run makes no calls at all and needs no credentials.
    """
    token = None
    if not dry_run:
        token = secman_client.login(url, username, password)

    pushed = failed = 0
    for rec in records:
        for row in store.get_findings(rec.owner, rec.repo):
            if row["severity"] not in ("critical", "high"):
                continue

            cve, days_open = _cve_and_days_open(store, rec.owner, rec.repo, row)
            hostname = rec.full_name

            if dry_run:
                typer.echo(f"would push {hostname} {cve} {row['severity'].upper()}")
                pushed += 1
                continue

            try:
                secman_client.push_vulnerability(
                    url, token,
                    hostname=hostname, cve=cve,
                    criticality=row["severity"].upper(), days_open=days_open,
                )
                pushed += 1
            except secman_client.SecmanPushError as exc:
                typer.echo(f"failed: {hostname} {cve}: {exc}", err=True)
                failed += 1

    return pushed, failed
