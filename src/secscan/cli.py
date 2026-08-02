"""Command-line interface for secscan.

Commands:
  run         enumerate + clone + review reachable repos, write CSVs
  scan        clone + review a single remote repo by 'owner/name'
  list-repos  enumerate + filter only (no review) — show what would be scanned
  review      review a single local repo directory (dev/test loop, no GitHub)
  report      rebuild the aggregate summary.csv from the state DB
  stats       print scan statistics from the state DB (table / csv / json)
  repo        manage explicitly-added scan targets (add / list / remove)
  send-report email the latest results as an HTML report (Gmail / O365 / custom SMTP)
  push-to-secman push High/Critical findings from the state DB into secman

`--dry-run` (on run / scan / push-to-secman, or SECSCAN_DRY_RUN=1 for all three)
means no external writes: no GitHub issue is opened and nothing reaches secman.
It also arms the guard in dryrun.py — see that module and CLAUDE.md.
"""

from __future__ import annotations

from pathlib import Path

import typer

from .config import ConfigError, Filters, RunConfig

app = typer.Typer(
    add_completion=False,
    help="Run autonomous Claude Code security reviews across GitHub App repositories.",
)

# Shared by --provider/--model on run/review/scan (see providers.py for the details).
_PROVIDER_HELP = (
    "anthropic|openrouter|kimi|copilot|auto|usecc (auto: OpenRouter if OPENROUTER_API_KEY "
    "is set, else Kimi if MOONSHOT_API_KEY is set, else Anthropic; kimi: Moonshot's "
    "Anthropic-compatible endpoint; copilot: a local Copilot bridge at COPILOT_BASE_URL, "
    "default http://localhost:4141; usecc: force the locally authenticated Claude Code "
    "session, ignoring every provider key plus ANTHROPIC_API_KEY/ANTHROPIC_BASE_URL)."
)
_MODEL_HELP = (
    "Model for reviews; the default alias maps per provider (OpenRouter: a slug like "
    "anthropic/claude-sonnet-4.5; Kimi: an ID like kimi-k2.7-code; Copilot: an ID like "
    "claude-sonnet-4.5 or gpt-4.1)."
)


repo_app = typer.Typer(
    add_completion=False,
    help="Manage explicitly-added scan targets (stored in the state DB).",
)
app.add_typer(repo_app, name="repo")

stats_app = typer.Typer(
    add_completion=False,
    help="Scan statistics from the state database.",
)
app.add_typer(stats_app, name="stats")


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


_DRY_RUN_HELP = (
    "Make no external writes: no GitHub issue is opened (with --create-issues, "
    "preview what would be created/skipped, with zero GitHub API calls and zero "
    "issue-tracking DB writes) and nothing is pushed to secman. The review itself "
    "still runs and still writes findings.csv and local state. Also settable via "
    "SECSCAN_DRY_RUN=1."
)


def _enter_dry_run(flag: bool) -> bool:
    """Resolve --dry-run (flag or SECSCAN_DRY_RUN) and arm the guard if it's on.

    Arming happens here, at the CLI edge, so every code path a command reaches is
    covered — not just the ones that remembered to check the flag.
    """
    from . import dryrun

    if not dryrun.resolve(flag):
        return False
    dryrun.activate()
    return True


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
    dry_run: bool = False,
    issue_prefix: str = "secscan:",
    provider: str = "auto",
    timeout_s: float = 900.0,
    branch: str | None = None,
    email_to: list[str] | None = None,
    email_provider: str = "custom",
    smtp_host: str | None = None,
    smtp_port: int | None = None,
    email_subject: str | None = None,
) -> RunConfig:
    if no_db and create_issues:
        raise ConfigError("--no-db and --create-issues cannot be combined (issue dedup needs the DB)")
    if no_db and email_to:
        raise ConfigError("--no-db and --email-to cannot be combined (the report is built from the state DB)")
    return RunConfig(
        output_dir=output_dir,
        state_db=output_dir / "secscan.sqlite3",
        db_url=db_url,
        db_user=db_user,
        db_password=db_password,
        db_ssl=db_ssl,
        no_db=no_db,
        create_issues=create_issues,
        dry_run=dry_run,
        issue_prefix=issue_prefix.strip(),
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
        branch=branch,
        resume=resume,
        limit=limit,
        email_to=list(email_to or []),
        email_provider=email_provider,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        email_subject=email_subject,
    )


def _validate_email_config(cfg: RunConfig) -> None:
    """Fail fast on SMTP misconfiguration before starting an expensive scan."""
    if not cfg.email_to:
        return
    from .emailer import EmailConfig

    EmailConfig.from_env(cfg.email_provider, host=cfg.smtp_host, port=cfg.smtp_port)


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
    dry_run: bool = typer.Option(False, "--dry-run", help=_DRY_RUN_HELP),
    issue_prefix: str = typer.Option("secscan:", "--issue-prefix", help="Prefix for issue titles opened by --create-issues; an empty string means no prefix."),
    concurrency: int = typer.Option(4, help="Max repos reviewed in parallel."),
    model: str = typer.Option("sonnet", help=_MODEL_HELP),
    provider: str = typer.Option("auto", help=_PROVIDER_HELP),
    max_turns: int = typer.Option(60, help="Max agent turns per repo review."),
    max_cost_usd: float = typer.Option(None, help="Per-repo cost abort threshold (USD)."),
    timeout: float = typer.Option(
        900.0, help="Abort a repo's review if the agent stalls (no output) this long, in seconds; 0 disables."
    ),
    include_archived: bool = typer.Option(False, help="Include archived repos."),
    include_forks: bool = typer.Option(False, help="Include forked repos."),
    max_size_mb: int = typer.Option(500, help="Skip repos larger than this (MB); 0 disables."),
    keep_clones: bool = typer.Option(False, help="Keep clones instead of deleting them."),
    branch: str = typer.Option(
        None,
        "--branch",
        help=(
            "Branch to clone and review; defaults to each repo's default branch. "
            "Applies to every repo in scope — repos without this branch are recorded "
            "as failed and the run continues."
        ),
    ),
    resume: bool = typer.Option(True, help="Skip repos already reviewed (use --no-resume to force)."),
    limit: int = typer.Option(None, help="Cap number of repos (smoke tests)."),
    email_to: list[str] = typer.Option(
        None, "--email-to",
        help=(
            "Email an HTML report when the run finds High/Critical findings; repeat "
            "for multiple recipients. Requires SMTP_USERNAME/SMTP_PASSWORD env vars. "
            "Cannot combine with --no-db."
        ),
    ),
    email_provider: str = typer.Option("custom", help="gmail|o365|custom (presets for smtp.gmail.com / smtp.office365.com)."),
    smtp_host: str = typer.Option(None, help="SMTP host (custom provider); defaults to SMTP_HOST."),
    smtp_port: int = typer.Option(None, help="SMTP port; defaults to SMTP_PORT, preset, or 587."),
    subject: str = typer.Option(None, help="Email subject; defaults to a findings summary."),
) -> None:
    """Enumerate, clone, and security-review reachable repositories."""
    import asyncio

    from .orchestrator import run_scan

    try:
        cfg = _run_config(
            output_dir, concurrency, model, max_turns, max_cost_usd,
            include_archived, include_forks, max_size_mb, keep_clones, resume, limit,
            db_url=_resolve_db_url(db_url), db_user=db_user, db_password=db_password, db_ssl=db_ssl,
            no_db=no_db, create_issues=create_issues, dry_run=_enter_dry_run(dry_run),
            issue_prefix=issue_prefix,
            provider=provider, timeout_s=timeout, branch=branch,
            email_to=email_to, email_provider=email_provider,
            smtp_host=smtp_host, smtp_port=smtp_port, email_subject=subject,
        )
        _validate_email_config(cfg)
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
    last_commit: bool = typer.Option(
        False, "--last-commit",
        help="Append the latest default-branch commit (short SHA, date); one extra API call per repo.",
    ),
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
            line = f"{repo.full_name}\t{repo.size_kb} KB"
            if last_commit:
                lc = client.last_commit(repo)
                line += f"\t{lc[0][:7]}\t{lc[1]}" if lc else "\t-\t-"
            typer.echo(line)


@app.command()
def review(
    path: Path = typer.Argument(..., help="Local repo directory to review."),
    output_dir: Path = typer.Option(Path("output"), help="Where the CSV is written."),
    model: str = typer.Option("sonnet", help=_MODEL_HELP),
    provider: str = typer.Option("auto", help=_PROVIDER_HELP),
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
    dry_run: bool = typer.Option(False, "--dry-run", help=_DRY_RUN_HELP),
    issue_prefix: str = typer.Option("secscan:", "--issue-prefix", help="Prefix for issue titles opened by --create-issues; an empty string means no prefix."),
    model: str = typer.Option("sonnet", help=_MODEL_HELP),
    provider: str = typer.Option("auto", help=_PROVIDER_HELP),
    max_turns: int = typer.Option(60, help="Max agent turns for the review."),
    max_cost_usd: float = typer.Option(None, help="Cost abort threshold (USD)."),
    timeout: float = typer.Option(
        900.0, help="Abort if the agent stalls (no output) this long, in seconds; 0 disables."
    ),
    keep_clones: bool = typer.Option(False, help="Keep the clone instead of deleting it."),
    branch: str = typer.Option(
        None, "--branch",
        help="Branch to clone and review; defaults to the repo's default branch.",
    ),
    email_to: list[str] = typer.Option(
        None, "--email-to",
        help=(
            "Email an HTML report when the scan finds High/Critical findings; repeat "
            "for multiple recipients. Requires SMTP_USERNAME/SMTP_PASSWORD env vars. "
            "Cannot combine with --no-db."
        ),
    ),
    email_provider: str = typer.Option("custom", help="gmail|o365|custom (presets for smtp.gmail.com / smtp.office365.com)."),
    smtp_host: str = typer.Option(None, help="SMTP host (custom provider); defaults to SMTP_HOST."),
    smtp_port: int = typer.Option(None, help="SMTP port; defaults to SMTP_PORT, preset, or 587."),
    subject: str = typer.Option(None, help="Email subject; defaults to a findings summary."),
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
            no_db=no_db, create_issues=create_issues, dry_run=_enter_dry_run(dry_run),
            issue_prefix=issue_prefix,
            provider=provider, timeout_s=timeout, branch=branch,
            email_to=email_to, email_provider=email_provider,
            smtp_host=smtp_host, smtp_port=smtp_port, email_subject=subject,
        )
        _validate_email_config(cfg)
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


_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _stats_payload(store, top: int) -> dict:
    from datetime import datetime, timezone

    from .report_html import totals

    records = store.all_records()
    t = totals(records)
    by_severity = store.severity_counts()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repos": {"total": len(records), "by_status": store.status_counts()},
        "findings": {"total": sum(by_severity.values()), "by_severity": by_severity},
        "totals": {
            "critical": t["critical"],
            "high": t["high"],
            "failed": t["failed"],
            "cost_usd": round(t["cost"], 3),
        },
        "issues_tracked": store.issue_count(),
        "last_reviewed_at": store.last_reviewed_at(),
        "top_repos": [
            {
                "repo": r.full_name,
                "status": r.status.value,
                "critical": r.critical_count,
                "high": r.high_count,
                "total_findings": r.total_findings,
                "cost_usd": round(r.cost_usd, 3),
                "reviewed_at": r.reviewed_at,
            }
            for r in store.top_repos(top)
        ],
    }


def _stats_table(payload: dict) -> str:
    lines = [
        f"secscan statistics (generated {payload['generated_at']})",
        "",
        f"Repos:          {payload['repos']['total']}"
        + (
            "  ("
            + ", ".join(f"{k}: {v}" for k, v in sorted(payload["repos"]["by_status"].items()))
            + ")"
            if payload["repos"]["by_status"]
            else ""
        ),
        f"Critical/High:  {payload['totals']['critical']} critical, {payload['totals']['high']} high"
        f" ({payload['totals']['failed']} repos failed)",
        f"Review cost:    ${payload['totals']['cost_usd']:.3f}",
        f"Issues tracked: {payload['issues_tracked']}",
        f"Last review:    {payload['last_reviewed_at'] or '-'}",
        "",
        "Stored findings by severity:",
    ]
    by_severity = payload["findings"]["by_severity"]
    for sev in _SEVERITIES:
        if sev in by_severity:
            lines.append(f"  {sev:<9} {by_severity[sev]}")
    for sev, n in sorted(by_severity.items()):
        if sev not in _SEVERITIES:
            lines.append(f"  {sev:<9} {n}")
    if not by_severity:
        lines.append("  (none stored)")
    lines += ["", f"Top repos by findings (showing {len(payload['top_repos'])}):"]
    for r in payload["top_repos"]:
        lines.append(
            f"  {r['repo']}: {r['critical']} critical, {r['high']} high, "
            f"{r['total_findings']} total [{r['status']}]"
        )
    if not payload["top_repos"]:
        lines.append("  (no repos recorded)")
    return "\n".join(lines)


def _stats_csv(payload: dict) -> str:
    import csv
    import io

    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "repo", "status", "critical", "high", "total_findings", "cost_usd", "reviewed_at",
        ],
    )
    writer.writeheader()
    for row in payload["top_repos"]:
        writer.writerow(row)
    return buf.getvalue()


@stats_app.callback(invoke_without_command=True)
def stats(
    ctx: typer.Context,
    format: str = typer.Option(
        "table", "--format",
        help="table|csv|json. csv emits per-repo rows (totals go to stderr); json emits the full payload.",
    ),
    output: Path = typer.Option(None, "--output", help="Write csv/json to this file instead of stdout."),
    top: int = typer.Option(10, help="How many top repos (by findings) to include."),
    output_dir: Path = typer.Option(Path("output"), help="Where the state DB lives."),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_password: str = typer.Option(None, help="MySQL/MariaDB password (or DB_PASSWORD env). Overrides any password embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
) -> None:
    """Print scan statistics from the state database (repos, findings by severity, cost)."""
    import json

    if ctx.invoked_subcommand is not None:
        return

    if format not in ("table", "csv", "json"):
        raise typer.BadParameter(f"--format must be table, csv, or json (got {format!r})")

    store = _open_store(output_dir, db_url, db_user, db_password, db_ssl)
    payload = _stats_payload(store, top)

    if format == "table":
        typer.echo(_stats_table(payload))
        return
    if format == "json":
        rendered = json.dumps(payload, indent=2)
    else:
        rendered = _stats_csv(payload)
        t = payload["totals"]
        typer.echo(
            f"{payload['repos']['total']} repos, {payload['findings']['total']} findings, "
            f"{t['critical']} critical, {t['high']} high, ${t['cost_usd']:.3f} total cost",
            err=True,
        )
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered if rendered.endswith("\n") else rendered + "\n")
        typer.echo(f"Wrote {output}")
    else:
        typer.echo(rendered)


def _delete_generated_csvs(output_dir: Path) -> int:
    """Remove summary.csv and every per-repo findings.csv; returns the file count.

    Only files this tool generated are unlinked (never a recursive directory
    delete); a per-repo directory is removed only if it ends up empty.
    """
    removed = 0
    summary = output_dir / "summary.csv"
    if summary.is_file():
        summary.unlink()
        removed += 1
    for csv_path in sorted(output_dir.glob("*__*/findings.csv")):
        csv_path.unlink()
        removed += 1
        try:
            csv_path.parent.rmdir()
        except OSError:
            pass  # other files live there; leave the directory alone
    return removed


@stats_app.command("reset")
def stats_reset(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    include_csv: bool = typer.Option(False, "--include-csv", help="Also delete summary.csv and every per-repo findings.csv under --output-dir."),
    output_dir: Path = typer.Option(Path("output"), help="Where the state DB lives."),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_password: str = typer.Option(None, help="MySQL/MariaDB password (or DB_PASSWORD env). Overrides any password embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
) -> None:
    """Delete all stored statistics (scan history and findings) from the state database.

    Registered scan targets and GitHub issue tracking are kept — clearing issue
    tracking would make the next --create-issues run re-open issues that already
    exist on GitHub.
    """
    store = _open_store(output_dir, db_url, db_user, db_password, db_ssl)
    n_repos = len(store.all_records())
    n_findings = sum(store.severity_counts().values())

    if not yes:
        # Name the SQLite file, but never echo a MySQL URL back — it can embed credentials.
        label = (
            "the configured MySQL/MariaDB database"
            if _resolve_db_url(db_url)
            else str(output_dir / "secscan.sqlite3")
        )
        typer.confirm(
            f"Delete {n_repos} repo records and {n_findings} findings from {label}?",
            abort=True,
        )

    repos_deleted, findings_deleted = store.clear_stats()
    typer.echo(
        f"Deleted {repos_deleted} repo records and {findings_deleted} findings "
        f"(targets and issue tracking kept)."
    )
    if include_csv:
        typer.echo(f"Deleted {_delete_generated_csvs(output_dir)} CSV files under {output_dir}")


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
    from .config import ConfigError
    from .report_sender import send_scan_report

    store = _open_store(output_dir, db_url, db_user, db_password, db_ssl)

    try:
        n_repos, n_findings = send_scan_report(
            store, email_to,
            provider=email_provider, host=smtp_host, port=smtp_port,
            subject=subject, max_findings=max_findings,
        )
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)

    typer.echo(
        f"Sent report to {', '.join(email_to)} ({n_repos} repos, {n_findings} findings)"
    )


@app.command("push-to-secman")
def push_to_secman(
    secman_url: str = typer.Option(None, "--secman-url", help="secman base URL (or SECMAN_URL env)."),
    secman_username: str = typer.Option(None, "--secman-username", help="secman username (or SECMAN_USERNAME env)."),
    secman_password: str = typer.Option(None, "--secman-password", help="secman password (or SECMAN_PASSWORD env)."),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help=(
            "Preview what would be pushed; makes zero login/API calls, so nothing "
            "is written to secman. Also settable via SECSCAN_DRY_RUN=1."
        ),
    ),
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

    dry_run = _enter_dry_run(dry_run)

    url = _resolve_secman_url(secman_url)
    username = _resolve_secman_username(secman_username)
    password = _resolve_secman_password(secman_password)
    # A dry run never logs in or posts, so it needs no secman credentials at all.
    if not dry_run and (not url or not username or not password):
        typer.echo(
            "Error: secman URL/username/password required "
            "(--secman-url/--secman-username/--secman-password or "
            "SECMAN_URL/SECMAN_USERNAME/SECMAN_PASSWORD env vars)",
            err=True,
        )
        raise typer.Exit(1)

    if dry_run:
        typer.echo("Dry run: nothing will be written to secman.")

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
