"""Command-line interface for secscan.

Commands:
  run         enumerate + clone + review reachable repos, write CSVs
  scan        clone + review a single remote repo by 'owner/name'
  list-repos  enumerate + filter only (no review) — show what would be scanned
  review      review a single local repo directory (dev/test loop, no GitHub)
  report      rebuild the aggregate summary.csv from the state DB
  repo        manage explicitly-added scan targets (add / list / remove)
  send-report email the latest results as an HTML report (Gmail / O365 / custom SMTP)
"""

from __future__ import annotations

from pathlib import Path

import typer

from .config import Filters, RunConfig

app = typer.Typer(
    add_completion=False,
    help="Run autonomous Claude Code security reviews across GitHub App repositories.",
)


repo_app = typer.Typer(
    add_completion=False,
    help="Manage explicitly-added scan targets (stored in the state DB).",
)
app.add_typer(repo_app, name="repo")


def _resolve_db_url(db_url: str | None) -> str | None:
    import os

    return db_url or os.environ.get("SECSCAN_DB_URL") or None


def _split_full_name(value: str) -> tuple[str, str]:
    parts = value.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise typer.BadParameter(f"expected 'owner/name', got {value!r}")
    return parts[0], parts[1]


def _open_store(output_dir: Path, db_url: str | None):
    from .state import StateStore

    return StateStore(_resolve_db_url(db_url) or (output_dir / "secscan.sqlite3"))


def _run_config(
    output_dir: Path,
    concurrency: int,
    model: str,
    max_turns: int,
    max_cost_usd: float | None,
    include_archived: bool,
    include_forks: bool,
    max_size_mb: int,
    keep_clones: bool,
    resume: bool,
    limit: int | None,
    db_url: str | None = None,
    provider: str = "auto",
) -> RunConfig:
    return RunConfig(
        output_dir=output_dir,
        state_db=output_dir / "secscan.sqlite3",
        db_url=db_url,
        filters=Filters(
            include_archived=include_archived,
            include_forks=include_forks,
            max_size_mb=max_size_mb,
        ),
        concurrency=concurrency,
        model=model,
        provider=provider,
        max_turns=max_turns,
        max_cost_usd=max_cost_usd,
        keep_clones=keep_clones,
        resume=resume,
        limit=limit,
    )


@app.command()
def run(
    org: str = typer.Option(None, help="Limit to a single org/owner login."),
    repos_file: Path = typer.Option(None, help="Allowlist file, one 'owner/repo' per line."),
    targets_only: bool = typer.Option(
        False,
        "--targets-only",
        help=(
            "Skip GitHub App enumeration; scan only 'secscan repo add' targets "
            "(and --repos-file, if given). --org has no effect in this mode."
        ),
    ),
    output_dir: Path = typer.Option(Path("output"), help="Where CSVs and state live."),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL (mysql://user:pass@host:3306/db). Defaults to SECSCAN_DB_URL or local SQLite."),
    concurrency: int = typer.Option(4, help="Max repos reviewed in parallel."),
    model: str = typer.Option("sonnet", help="Claude model for reviews (OpenRouter: a slug like anthropic/claude-sonnet-4.5)."),
    provider: str = typer.Option("auto", help="anthropic|openrouter|auto (auto: OpenRouter if OPENROUTER_API_KEY is set)."),
    max_turns: int = typer.Option(60, help="Max agent turns per repo review."),
    max_cost_usd: float = typer.Option(None, help="Per-repo cost abort threshold (USD)."),
    include_archived: bool = typer.Option(False, help="Include archived repos."),
    include_forks: bool = typer.Option(False, help="Include forked repos."),
    max_size_mb: int = typer.Option(500, help="Skip repos larger than this (MB); 0 disables."),
    keep_clones: bool = typer.Option(False, help="Keep clones instead of deleting them."),
    resume: bool = typer.Option(True, help="Skip repos already reviewed (use --no-resume to force)."),
    limit: int = typer.Option(None, help="Cap number of repos (smoke tests)."),
) -> None:
    """Enumerate, clone, and security-review reachable repositories."""
    import asyncio

    from .orchestrator import run_scan

    cfg = _run_config(
        output_dir, concurrency, model, max_turns, max_cost_usd,
        include_archived, include_forks, max_size_mb, keep_clones, resume, limit,
        db_url=_resolve_db_url(db_url), provider=provider,
    )
    asyncio.run(run_scan(cfg, org=org, repos_file=repos_file, targets_only=targets_only))


@app.command("list-repos")
def list_repos(
    org: str = typer.Option(None, help="Limit to a single org/owner login."),
    include_archived: bool = typer.Option(False),
    include_forks: bool = typer.Option(False),
    max_size_mb: int = typer.Option(500),
) -> None:
    """Print the repositories that would be scanned (no cloning, no review)."""
    from .github_auth import build_auth

    filters = Filters(include_archived=include_archived, include_forks=include_forks, max_size_mb=max_size_mb)
    auth = build_auth()
    seen: set[str] = set()
    for client in (auth.app, auth.pat):
        if client is None:
            continue
        for repo in client.iter_repositories(org=org, filters=filters):
            if repo.full_name in seen:
                continue  # App entry wins; PAT duplicates are dropped
            seen.add(repo.full_name)
            typer.echo(f"{repo.full_name}\t{repo.size_kb} KB")


@app.command()
def review(
    path: Path = typer.Argument(..., help="Local repo directory to review."),
    output_dir: Path = typer.Option(Path("output"), help="Where the CSV is written."),
    model: str = typer.Option("sonnet"),
    provider: str = typer.Option("auto", help="anthropic|openrouter|auto (auto: OpenRouter if OPENROUTER_API_KEY is set)."),
    max_turns: int = typer.Option(60),
    max_cost_usd: float = typer.Option(None),
) -> None:
    """Security-review a single local repository directory."""
    import asyncio

    from .orchestrator import review_local

    cfg = _run_config(
        output_dir, 1, model, max_turns, max_cost_usd,
        False, False, 0, True, True, None,
        provider=provider,
    )
    asyncio.run(review_local(cfg, path))


@app.command()
def scan(
    full_name: str = typer.Argument(..., help="Repository as 'owner/name'."),
    output_dir: Path = typer.Option(Path("output"), help="Where the CSV and state live."),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
    model: str = typer.Option("sonnet", help="Claude model for the review (OpenRouter: a slug like anthropic/claude-sonnet-4.5)."),
    provider: str = typer.Option("auto", help="anthropic|openrouter|auto (auto: OpenRouter if OPENROUTER_API_KEY is set)."),
    max_turns: int = typer.Option(60, help="Max agent turns for the review."),
    max_cost_usd: float = typer.Option(None, help="Cost abort threshold (USD)."),
    keep_clones: bool = typer.Option(False, help="Keep the clone instead of deleting it."),
) -> None:
    """Clone one remote repository (GitHub App or PAT) and security-review it."""
    import asyncio

    from .orchestrator import scan_repo

    owner, name = _split_full_name(full_name)
    cfg = _run_config(
        output_dir, 1, model, max_turns, max_cost_usd,
        False, False, 0, keep_clones, False, None,
        db_url=_resolve_db_url(db_url), provider=provider,
    )
    asyncio.run(scan_repo(cfg, owner, name))


@app.command()
def report(
    output_dir: Path = typer.Option(Path("output"), help="Where state and CSVs live."),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
) -> None:
    """Rebuild summary.csv from the state database."""
    from .findings import write_summary_csv

    store = _open_store(output_dir, db_url)
    rows = store.all_records()
    out = write_summary_csv(output_dir / "summary.csv", rows)
    typer.echo(f"Wrote {out} ({len(rows)} repos)")


@app.command("send-report")
def send_report(
    email_to: list[str] = typer.Option(..., "--email-to", help="Recipient address; repeat for multiple."),
    email_provider: str = typer.Option("custom", help="gmail|o365|custom (presets for smtp.gmail.com / smtp.office365.com)."),
    smtp_host: str = typer.Option(None, help="SMTP host (custom provider); defaults to SMTP_HOST."),
    smtp_port: int = typer.Option(None, help="SMTP port; defaults to SMTP_PORT, preset, or 587."),
    subject: str = typer.Option(None, help="Subject; defaults to a findings summary."),
    max_findings: int = typer.Option(50, help="Cap the findings included in the email."),
    output_dir: Path = typer.Option(Path("output"), help="Where the state DB lives."),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
) -> None:
    """Email the latest scan results as an HTML report (with a plain-text part)."""
    from datetime import datetime, timezone

    from .config import ConfigError
    from .emailer import EmailConfig, build_message, send_email
    from .report_html import (
        build_report_html,
        build_report_text,
        default_subject,
        severity_sort_key,
    )

    store = _open_store(output_dir, db_url)
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
        typer.echo(f"Including {max_findings} of {total_findings} findings (raise --max-findings for more).")

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    html = build_report_html(records, findings, generated_at)
    text = build_report_text(records, findings, generated_at)

    try:
        cfg = EmailConfig.from_env(email_provider, host=smtp_host, port=smtp_port)
        msg = build_message(cfg, email_to, subject or default_subject(records), html, text)
        send_email(cfg, msg)
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)

    typer.echo(
        f"Sent report to {', '.join(email_to)} ({len(records)} repos, {len(findings)} findings)"
    )


_TARGET_DB_HELP = "MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."


@repo_app.command("add")
def repo_add(
    full_name: str = typer.Argument(..., help="Repository as 'owner/name'."),
    output_dir: Path = typer.Option(Path("output"), help="Where the state DB lives."),
    db_url: str = typer.Option(None, help=_TARGET_DB_HELP),
) -> None:
    """Add a GitHub repository to the scan targets."""
    from datetime import datetime, timezone

    owner, name = _split_full_name(full_name)
    store = _open_store(output_dir, db_url)
    added = store.add_target(owner, name, datetime.now(timezone.utc).isoformat())
    typer.echo(f"{'Added' if added else 'Already a target:'} {owner}/{name}")


@repo_app.command("list")
def repo_list(
    output_dir: Path = typer.Option(Path("output"), help="Where the state DB lives."),
    db_url: str = typer.Option(None, help=_TARGET_DB_HELP),
) -> None:
    """List the explicitly-added scan targets."""
    store = _open_store(output_dir, db_url)
    targets = store.list_targets()
    for owner, name in targets:
        typer.echo(f"{owner}/{name}")
    if not targets:
        typer.echo("(no targets — add one with: secscan repo add owner/name)")


@repo_app.command("remove")
def repo_remove(
    full_name: str = typer.Argument(..., help="Repository as 'owner/name'."),
    output_dir: Path = typer.Option(Path("output"), help="Where the state DB lives."),
    db_url: str = typer.Option(None, help=_TARGET_DB_HELP),
) -> None:
    """Remove a GitHub repository from the scan targets."""
    owner, name = _split_full_name(full_name)
    store = _open_store(output_dir, db_url)
    if store.remove_target(owner, name):
        typer.echo(f"Removed {owner}/{name}")
    else:
        typer.echo(f"Not a target: {owner}/{name}", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
