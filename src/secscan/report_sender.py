"""Assemble the findings report from the state DB and email it.

Shared by the `send-report` command and the end-of-run auto-email
(`run`/`scan --email-to`). Raises ConfigError for SMTP misconfiguration;
callers decide whether that is fatal.
"""

from __future__ import annotations

from datetime import datetime, timezone

import typer

from .report_html import (
    build_report_html,
    build_report_text,
    default_subject,
    severity_sort_key,
)
from .state import StateStore


def send_scan_report(
    store: StateStore,
    email_to: list[str],
    *,
    provider: str = "custom",
    host: str | None = None,
    port: int | None = None,
    subject: str | None = None,
    max_findings: int = 50,
) -> tuple[int, int]:
    """Email the latest results from `store`; returns (repos, findings included)."""
    from . import emailer  # module attribute so tests can monkeypatch emailer.send_email

    records = store.all_records()

    findings: list[dict] = []
    for rec in records:
        for row in store.get_findings(rec.owner, rec.repo):
            row["repo_full_name"] = rec.full_name
            findings.append(row)
    findings.sort(key=severity_sort_key)
    total_findings = len(findings)
    findings = findings[:max_findings]
    if total_findings > max_findings:
        typer.echo(
            f"Including {max_findings} of {total_findings} findings (raise --max-findings for more)."
        )

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    html = build_report_html(records, findings, generated_at)
    text = build_report_text(records, findings, generated_at)

    cfg = emailer.EmailConfig.from_env(provider, host=host, port=port)
    msg = emailer.build_message(cfg, email_to, subject or default_subject(records), html, text)
    emailer.send_email(cfg, msg)
    return len(records), len(findings)
