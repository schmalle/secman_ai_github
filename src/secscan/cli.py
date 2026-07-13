"""Command-line interface for secscan.

Commands:
  run         enumerate + clone + review reachable repos, write CSVs
  scan        clone + review a single remote repo by 'owner/name'
  list-repos  enumerate + filter only (no review) — show what would be scanned
  review      review a single local repo directory (dev/test loop, no GitHub)
  report      rebuild the aggregate summary.csv from the state DB
  repo        manage explicitly-added scan targets (add / list / remove)
  send-report email the latest results as an HTML report (Gmail / O365 / custom SMTP)
  push-to-secman push High/Critical findings from the state DB into secman
"""

from __future__ import annotations

from pathlib import Path

import typer

from .config import ConfigError, Filters, RunConfig

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


def _resolve_db_user(db_user: str | None) -> str | None:
    import os

    return db_user or os.environ.get("DB_USERNAME") or None


def _resolve_db_password(db_password: str | None) -> str | None:
    import os

    return db_password or os.environ.get("DB_PASSWORD") or None


def _resolve_db_ssl(db_ssl: bool) -> bool:
    import os

    if db_ssl:
        return True
    return os.environ.get("DB_SSL", "").strip().lower() in ("true", "1")


def _resolve_secman_url(url: str | None) -> str | None:
    import os

    return url or os.environ.get("SECMAN_URL") or None


def _resolve_secman_username(username: str | None) -> str | None:
    import os

    return username or os.environ.get("SECMAN_USERNAME") or None


def _resolve_secman_password(password: str | None) -> str | None:
    import os

    return password or os.environ.get("SECMAN_PASSWORD") or None


def _split_full_name(value: str) -> tuple[str, str]:
    parts = value.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise typer.BadParameter(f"expected 'owner/name', got {value!r}")
    return parts[0], parts[1]


def _open_store(
    output_dir: Path,
    db_url: str | None,
    db_user: str | None = None,
    db_password: str | None = None,
    db_ssl: bool = False,
):
    from .state import StateStore

    return StateStore(
        _resolve_db_url(db_url) or (output_dir / "secscan.sqlite3"),
        db_user=_resolve_db_user(db_user),
        db_password=_resolve_db_password(db_password),
        db_ssl=_resolve_db_ssl(db_ssl),
    )


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
    db_user: str | None = None,
    db_password: str | None = None,
    db_ssl: bool = False,
    no_db: bool = False,
    create_issues: bool = False,
    issue_dry_run: bool = False,
    provider: str = "auto",
    timeout_s: float = 900.0,
) -> RunConfig:
    if no_db and create_issues:
        raise ConfigError("--no-db and --create-issues cannot be combined (issue dedup needs the DB)")
    return RunConfig(
        output_dir=output_dir,
        state_db=output_dir / "secscan.sqlite3",
        db_url=db_url,
        db_user=db_user,
        db_password=db_password,
        db_ssl=db_ssl,
        no_db=no_db,
        create_issues=create_issues,
        issue_dry_run=issue_dry_run,
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
        timeout_s=timeout_s,
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
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_password: str = typer.Option(None, help="MySQL/MariaDB password (or DB_PASSWORD env). Overrides any password embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
    no_db: bool = typer.Option(False, "--no-db", help="Skip all DB storage; findings.csv is still written, summary.csv is skipped. Cannot combine with --create-issues."),
    create_issues: bool = typer.Option(False, "--create-issues", help="Open one GitHub issue per new High/Critical finding (deduped by content fingerprint). Requires the DB — cannot combine with --no-db."),
    dry_run: bool = typer.Option(False, "--dry-run", help="With --create-issues: preview what would be created/skipped, making zero GitHub API calls or DB writes."),
    concurrency: int = typer.Option(4, help="Max repos reviewed in parallel."),
    model: str = typer.Option("sonnet", help="Claude model for reviews (OpenRouter: a slug like anthropic/claude-sonnet-4.5)."),
    provider: str = typer.Option(
        "auto",
        help=(
            "anthropic|openrouter|auto|usecc (auto: OpenRouter if OPENROUTER_API_KEY is set; "
            "usecc: force the locally authenticated Claude Code session, ignoring "
            "OPENROUTER_API_KEY/ANTHROPIC_API_KEY/ANTHROPIC_BASE_URL)."
        ),
    ),
    max_turns: int = typer.Option(60, help="Max agent turns per repo review."),
    max_cost_usd: float = typer.Option(None, help="Per-repo cost abort threshold (USD)."),
    timeout: float = typer.Option(
        900.0, help="Abort a repo's review if the agent stalls (no output) this long, in seconds; 0 disables."
    ),
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

    try:
        cfg = _run_config(
            output_dir, concurrency, model, max_turns, max_cost_usd,
            include_archived, include_forks, max_size_mb, keep_clones, resume, limit,
            db_url=_resolve_db_url(db_url), db_user=db_user, db_password=db_password, db_ssl=db_ssl,
            no_db=no_db, create_issues=create_issues, issue_dry_run=dry_run,
            provider=provider, timeout_s=timeout,
        )
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
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
    provider: str = typer.Option(
        "auto",
        help=(
            "anthropic|openrouter|auto|usecc (auto: OpenRouter if OPENROUTER_API_KEY is set; "
            "usecc: force the locally authenticated Claude Code session, ignoring "
            "OPENROUTER_API_KEY/ANTHROPIC_API_KEY/ANTHROPIC_BASE_URL)."
        ),
    ),
    max_turns: int = typer.Option(60),
    max_cost_usd: float = typer.Option(None),
    timeout: float = typer.Option(
        900.0, help="Abort if the agent stalls (no output) this long, in seconds; 0 disables."
    ),
) -> None:
    """Security-review a single local repository directory."""
    import asyncio

    from .orchestrator import review_local

    cfg = _run_config(
        output_dir, 1, model, max_turns, max_cost_usd,
        False, False, 0, True, True, None,
        provider=provider, timeout_s=timeout,
    )
    asyncio.run(review_local(cfg, path))


@app.command()
def scan(
    full_name: str = typer.Argument(..., help="Repository as 'owner/name'."),
    output_dir: Path = typer.Option(Path("output"), help="Where the CSV and state live."),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_password: str = typer.Option(None, help="MySQL/MariaDB password (or DB_PASSWORD env). Overrides any password embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
    no_db: bool = typer.Option(False, "--no-db", help="Skip all DB storage; findings.csv is still written, summary.csv is skipped. Cannot combine with --create-issues."),
    create_issues: bool = typer.Option(False, "--create-issues", help="Open one GitHub issue per new High/Critical finding (deduped by content fingerprint). Requires the DB — cannot combine with --no-db."),
    dry_run: bool = typer.Option(False, "--dry-run", help="With --create-issues: preview what would be created/skipped, making zero GitHub API calls or DB writes."),
    model: str = typer.Option("sonnet", help="Claude model for the review (OpenRouter: a slug like anthropic/claude-sonnet-4.5)."),
    provider: str = typer.Option(
        "auto",
        help=(
            "anthropic|openrouter|auto|usecc (auto: OpenRouter if OPENROUTER_API_KEY is set; "
            "usecc: force the locally authenticated Claude Code session, ignoring "
            "OPENROUTER_API_KEY/ANTHROPIC_API_KEY/ANTHROPIC_BASE_URL)."
        ),
    ),
    max_turns: int = typer.Option(60, help="Max agent turns for the review."),
    max_cost_usd: float = typer.Option(None, help="Cost abort threshold (USD)."),
    timeout: float = typer.Option(
        900.0, help="Abort if the agent stalls (no output) this long, in seconds; 0 disables."
    ),
    keep_clones: bool = typer.Option(False, help="Keep the clone instead of deleting it."),
) -> None:
    """Clone one remote repository and security-review it (requires a PAT — single-repo
    scans don't enumerate App installations, so App-only credentials can't clone here)."""
    import asyncio

    from .orchestrator import scan_repo

    owner, name = _split_full_name(full_name)
    try:
        cfg = _run_config(
            output_dir, 1, model, max_turns, max_cost_usd,
            False, False, 0, keep_clones, False, None,
            db_url=_resolve_db_url(db_url), db_user=db_user, db_password=db_password, db_ssl=db_ssl,
            no_db=no_db, create_issues=create_issues, issue_dry_run=dry_run,
            provider=provider, timeout_s=timeout,
        )
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    asyncio.run(scan_repo(cfg, owner, name))


@app.command()
def report(
    output_dir: Path = typer.Option(Path("output"), help="Where state and CSVs live."),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_password: str = typer.Option(None, help="MySQL/MariaDB password (or DB_PASSWORD env). Overrides any password embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
) -> None:
    """Rebuild summary.csv from the state database."""
    from .findings import write_summary_csv

    store = _open_store(output_dir, db_url, db_user, db_password, db_ssl)
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
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_password: str = typer.Option(None, help="MySQL/MariaDB password (or DB_PASSWORD env). Overrides any password embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
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

    store = _open_store(output_dir, db_url, db_user, db_password, db_ssl)
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


@app.command("push-to-secman")
def push_to_secman(
    secman_url: str = typer.Option(None, "--secman-url", help="secman base URL (or SECMAN_URL env)."),
    secman_username: str = typer.Option(None, "--secman-username", help="secman username (or SECMAN_USERNAME env)."),
    secman_password: str = typer.Option(None, "--secman-password", help="secman password (or SECMAN_PASSWORD env)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview what would be pushed; makes zero login/API calls."),
    output_dir: Path = typer.Option(Path("output"), help="Where the state DB lives."),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env)."),
    db_password: str = typer.Option(None, help="MySQL/MariaDB password (or DB_PASSWORD env)."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env)."),
) -> None:
    """Push High/Critical findings from the state DB into secman via cli-add."""
    from datetime import datetime, timezone

    from . import secman_client
    from .findings import fingerprint

    url = _resolve_secman_url(secman_url)
    username = _resolve_secman_username(secman_username)
    password = _resolve_secman_password(secman_password)
    if not url or not username or not password:
        typer.echo(
            "Error: secman URL/username/password required "
            "(--secman-url/--secman-username/--secman-password or "
            "SECMAN_URL/SECMAN_USERNAME/SECMAN_PASSWORD env vars)",
            err=True,
        )
        raise typer.Exit(1)

    store = _open_store(output_dir, db_url, db_user, db_password, db_ssl)
    records = store.all_records()

    token = None
    if not dry_run:
        try:
            token = secman_client.login(url, username, password)
        except secman_client.SecmanPushError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(1)

    pushed = failed = 0
    for rec in records:
        for row in store.get_findings(rec.owner, rec.repo):
            if row["severity"] not in ("critical", "high"):
                continue

            class _RowFinding:
                severity = type("S", (), {"value": row["severity"]})()
                category = row["category"]
                title = row["title"]
                file_path = row["file_path"]

            fp = fingerprint(_RowFinding())
            issue = store.find_issue(rec.owner, rec.repo, fp)
            days_open = 0
            if issue is not None:
                first_seen = datetime.fromisoformat(issue.first_seen_at)
                days_open = max(0, (datetime.now(timezone.utc) - first_seen).days)
            cve = f"SECSCAN:{row['category'] or 'FINDING'}:{fp[:12]}"
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

    verb = "would push" if dry_run else "pushed"
    typer.echo(f"{verb} {pushed}" + ("" if dry_run else f", failed {failed}"))


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
