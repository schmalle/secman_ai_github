"""Command-line interface for secscan.

Commands:
  run         enumerate + clone + review reachable repos, write CSVs
  scan        clone + review a single remote repo by 'owner/name'
  list-repos  enumerate + filter only (no review) — show what would be scanned
  list-users  list an org's members and its repos' collaborators (org-only GitHub APIs)
  review      review a single local repo directory (dev/test loop, no GitHub)
  report      rebuild the aggregate summary.csv from the state DB
  stats       print scan statistics from the state DB (table / csv / json)
  repo        manage explicitly-added scan targets (add / list / remove)
  send-report email the latest results as an HTML report (Gmail / O365 / custom SMTP)
  push-to-secman push High/Critical findings from the state DB into secman
  skills      list / show the bundled security skill packs usable with --skill

`--dry-run` (on run / scan / push-to-secman, or SECSCAN_DRY_RUN=1 for all three)
means no external writes: no GitHub issue is opened and nothing reaches secman.
It also arms the guard in dryrun.py — see that module and CLAUDE.md.

`--github-api-url` (on run / scan / list-repos / list-users, or GITHUB_API_URL for
all four) selects the GitHub deployment: github.com / Enterprise Cloud by default,
Enterprise Cloud with data residency, or Enterprise Server.

`--skill` (repeatable, on run / scan / review) appends operator-chosen security
skill packs — bundled names or paths to Agent-Skills-format directories — to the
reviewer's system prompt. See skills.py and docs/SECURITY_SKILLS.md.

`--engine` (on run / scan / review, or SECSCAN_ENGINE) picks the reviewer: `claude`
(default; Claude Code via the Agent SDK, routed by --provider/--model) or
`codescanai` (the CodeScanAI CLI driven as a subprocess, configured by the
--codescanai-* flags / CODESCANAI_* env). See codescanai.py.
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
    "claude-sonnet-4.5 or gpt-4.1). With --engine codescanai it is CodeScanAI's model "
    "(gpt-4o, gemini-1.5-flash, llama3, …); left at the default alias, CodeScanAI's own "
    "per-provider default (or CODESCANAI_MODEL) is used."
)

_ENGINE_HELP = (
    "Which reviewer does the work (or SECSCAN_ENGINE env): claude — Claude Code via the "
    "Agent SDK (default; --provider/--model/--skill apply) — or codescanai — the "
    "CodeScanAI CLI (pip install codescanai) run as a subprocess over the same clone, "
    "configured with --codescanai-* / CODESCANAI_*. Findings from either engine flow "
    "into the same CSV, state DB, issues, secman push and email report."
)
_CODESCANAI_PROVIDER_HELP = (
    "CodeScanAI's AI provider (or CODESCANAI_PROVIDER env): openai (OPENAI_API_KEY), "
    "gemini (GEMINI_API_KEY), custom (an OpenAI-compatible server such as Ollama, via "
    "--codescanai-host), or auto (default: openai if OPENAI_API_KEY is set, else gemini "
    "if GEMINI_API_KEY is set; custom is never auto-selected)."
)
_CODESCANAI_HOST_HELP = (
    "Custom server URL for --codescanai-provider custom, e.g. http://localhost "
    "(or CODESCANAI_HOST env). Handed to CodeScanAI as OPENAI_BASE_URL together with "
    "--codescanai-port/--codescanai-endpoint, never on its command line."
)
_CODESCANAI_PORT_HELP = "Custom server port, e.g. 11434 for Ollama (or CODESCANAI_PORT env)."
_CODESCANAI_ENDPOINT_HELP = (
    "Custom server API path appended to host:port, e.g. /v1 for Ollama "
    "(or CODESCANAI_ENDPOINT env). Unset means the server root."
)
_CODESCANAI_BIN_HELP = (
    "How to invoke CodeScanAI (or CODESCANAI_BIN env); default `codescanai`. A path, or "
    "a full command line such as 'python3 -m core.runner_v2' or 'uvx codescanai'."
)
_CODESCANAI_ARG_HELP = (
    "Extra argument passed to the codescanai command line verbatim (repeatable), e.g. "
    "--codescanai-arg=--changes_only. Never put a token here — set CODESCANAI_TOKEN."
)
_CODESCANAI_DEFAULT_SEVERITY_HELP = (
    "Severity assigned to a CodeScanAI finding whose free-text severity cannot be "
    "mapped to critical/high/medium/low/info (or CODESCANAI_DEFAULT_SEVERITY env); "
    "default medium, i.e. such findings are counted but not reported as High/Critical."
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

skills_app = typer.Typer(
    add_completion=False,
    help="Security skill packs that --skill can add to a review.",
)
app.add_typer(skills_app, name="skills")

_SKILL_HELP = (
    "Add a security skill pack to the review (repeatable): a bundled name — see "
    "`secscan skills list` — or a path to a directory holding a SKILL.md in the Agent "
    "Skills format. Skill text is trusted operator input appended to the reviewer's "
    "system prompt; the reviewer stays read-only. Larger prompts cost more per turn."
)


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


_PUSH_TO_SECMAN_HELP = (
    "After the review, push this invocation's High/Critical findings to the secman "
    "backend over HTTPS (POST /api/vulnerabilities/cli-add). Requires the DB — cannot "
    "combine with --no-db. Needs --secman-url/--secman-username and the SECMAN_PASSWORD "
    "env var (no --secman-password flag: a CLI flag value is visible to any other local "
    "process via `ps`/`/proc/<pid>/cmdline` for as long as this process runs). Only "
    "the repositories reviewed here are pushed; use `secscan push-to-secman` for the "
    "whole state DB."
)
_SECMAN_URL_HELP = "secman base URL, e.g. https://secman.example.com (or SECMAN_URL env)."
_SECMAN_USERNAME_HELP = "secman username (or SECMAN_USERNAME env); needs the ADMIN or VULN role."

_SECMAN_CREDS_MISSING = (
    "secman URL/username/password required "
    "(--secman-url/--secman-username and SECMAN_URL/SECMAN_USERNAME env vars, or set "
    "them all via SECMAN_URL/SECMAN_USERNAME/SECMAN_PASSWORD env vars — there is no "
    "--secman-password flag, by design: see SECMAN_PASSWORD in the README)"
)

_DRY_RUN_HELP = (
    "Make no external writes: no GitHub issue is opened (with --create-issues, "
    "preview what would be created/skipped, with zero GitHub API calls and zero "
    "issue-tracking DB writes) and nothing is pushed to secman. The review itself "
    "still runs and still writes findings.csv and local state. Also settable via "
    "SECSCAN_DRY_RUN=1."
)


_GITHUB_API_URL_HELP = (
    "GitHub deployment to talk to (or GITHUB_API_URL env). Omit for github.com / "
    "Enterprise Cloud. Enterprise Cloud with data residency: https://TENANT.ghe.com. "
    "Enterprise Server: https://ghes.example.com (the /api/v3 suffix is added for you, "
    "and accepted if you pass it)."
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
    db_ssl: bool = False,
    no_db: bool = False,
    create_issues: bool = False,
    push_to_secman: bool = False,
    secman_url: str | None = None,
    secman_username: str | None = None,
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
    github_api_url: str | None = None,
    skills: list[str] | None = None,
    engine: str | None = None,
    codescanai_provider: str | None = None,
    codescanai_host: str | None = None,
    codescanai_port: int | None = None,
    codescanai_endpoint: str | None = None,
    codescanai_bin: str | None = None,
    codescanai_args: list[str] | None = None,
    codescanai_default_severity: str | None = None,
) -> RunConfig:
    if no_db and create_issues:
        raise ConfigError("--no-db and --create-issues cannot be combined (issue dedup needs the DB)")
    if no_db and email_to:
        raise ConfigError("--no-db and --email-to cannot be combined (the report is built from the state DB)")
    if no_db and push_to_secman:
        raise ConfigError(
            "--no-db and --push-to-secman cannot be combined "
            "(the push reads findings and first-seen dates from the DB)"
        )
    # Explicit --secman-url/--secman-username that would silently do nothing are a
    # configuration error. secman_password is never an explicit CLI value here (there
    # is no --secman-password flag, only the SECMAN_PASSWORD env var, to keep the
    # password out of argv/`ps`), so it is deliberately excluded from this check —
    # SECMAN_* in the environment is not an error, since it is often exported
    # process-wide.
    if not push_to_secman and (secman_url or secman_username):
        raise ConfigError("--secman-url/--secman-username require --push-to-secman")
    secman_password: str | None = None
    if push_to_secman:
        from .secman_push import resolve_credentials

        # No --secman-password flag exists (argv/ps exposure) — password comes from
        # SECMAN_PASSWORD only.
        secman_url, secman_username, secman_password = resolve_credentials(
            secman_url, secman_username, None
        )
        # A dry run never logs in or posts, so it needs no credentials. Otherwise fail
        # here, before an expensive review runs against an unconfigured push.
        if not dry_run and not (secman_url and secman_username and secman_password):
            raise ConfigError(_SECMAN_CREDS_MISSING)
    loaded_skills = _load_skills(skills)
    engine, codescanai_cfg = _resolve_engine(
        engine,
        provider=provider,
        skills=loaded_skills,
        codescanai_provider=codescanai_provider,
        codescanai_host=codescanai_host,
        codescanai_port=codescanai_port,
        codescanai_endpoint=codescanai_endpoint,
        codescanai_bin=codescanai_bin,
        codescanai_args=codescanai_args,
        codescanai_default_severity=codescanai_default_severity,
        model=model,
    )
    return RunConfig(
        output_dir=output_dir,
        state_db=output_dir / "secscan.sqlite3",
        github_api_url=github_api_url,
        db_url=db_url,
        db_user=db_user,
        # No --db-password flag exists (argv/ps exposure) — password comes from
        # DB_PASSWORD only.
        db_password=_resolve_db_password(None),
        db_ssl=db_ssl,
        no_db=no_db,
        create_issues=create_issues,
        push_to_secman=push_to_secman,
        secman_url=secman_url,
        secman_username=secman_username,
        secman_password=secman_password,
        dry_run=dry_run,
        issue_prefix=issue_prefix.strip(),
        filters=Filters(
            include_archived=include_archived,
            include_forks=include_forks,
            max_size_mb=max_size_mb,
        ),
        concurrency=concurrency,
        engine=engine,
        codescanai=codescanai_cfg,
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
        skills=loaded_skills,
    )


def _load_skills(refs: list[str] | None) -> list:
    """Resolve --skill references up front, so a typo fails before any clone/review."""
    if not refs:
        return []
    from .skills import SkillError, load_skills

    try:
        return load_skills(refs)
    except SkillError as exc:
        raise ConfigError(f"--skill: {exc}") from exc


_ENGINES = ("claude", "codescanai")


def _resolve_engine(
    engine: str | None,
    *,
    provider: str,
    skills: list,
    codescanai_provider: str | None,
    codescanai_host: str | None,
    codescanai_port: int | None,
    codescanai_endpoint: str | None,
    codescanai_bin: str | None,
    codescanai_args: list[str] | None,
    codescanai_default_severity: str | None,
    model: str,
):
    """Resolve --engine (flag, then SECSCAN_ENGINE, then claude) and its settings.

    CodeScanAI settings are resolved up front — API key present, binary installed,
    host well-formed — so a misconfigured engine fails before any clone or review.
    Flags that only make sense for the other engine are configuration errors rather
    than silently ignored; `CODESCANAI_*` environment variables are not, since they
    are often exported process-wide.
    """
    import os

    engine = (engine or os.environ.get("SECSCAN_ENGINE") or "claude").strip().lower()
    if engine not in _ENGINES:
        raise ConfigError(f"--engine must be one of {', '.join(_ENGINES)}; got {engine!r}")

    codescanai_flags = {
        "--codescanai-provider": codescanai_provider,
        "--codescanai-host": codescanai_host,
        "--codescanai-port": codescanai_port,
        "--codescanai-endpoint": codescanai_endpoint,
        "--codescanai-bin": codescanai_bin,
        "--codescanai-arg": codescanai_args or None,
        "--codescanai-default-severity": codescanai_default_severity,
    }
    given = [flag for flag, value in codescanai_flags.items() if value not in (None, "")]

    if engine != "codescanai":
        if given:
            raise ConfigError(f"{', '.join(given)} require --engine codescanai")
        return engine, None

    if skills:
        raise ConfigError(
            "--skill only applies to --engine claude: CodeScanAI's review prompt is not "
            "configurable, so a skill pack cannot be added to it"
        )
    if provider != "auto":
        raise ConfigError(
            "--provider selects the endpoint for the Claude Code reviewer and does not "
            "apply to --engine codescanai; use --codescanai-provider instead"
        )
    from .codescanai import resolve_config

    return engine, resolve_config(
        provider=codescanai_provider,
        model=model,
        host=codescanai_host,
        port=codescanai_port,
        endpoint=codescanai_endpoint,
        bin=codescanai_bin,
        extra_args=codescanai_args,
        default_severity=codescanai_default_severity,
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
    github_api_url: str = typer.Option(None, "--github-api-url", help=_GITHUB_API_URL_HELP),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL (mysql://user:pass@host:3306/db). Defaults to SECSCAN_DB_URL or local SQLite."),
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
    no_db: bool = typer.Option(False, "--no-db", help="Skip all DB storage; findings.csv is still written, summary.csv is skipped. Cannot combine with --create-issues."),
    create_issues: bool = typer.Option(False, "--create-issues", help="Open one GitHub issue per new High/Critical finding (deduped by content fingerprint). Requires the DB — cannot combine with --no-db."),
    push_to_secman: bool = typer.Option(False, "--push-to-secman", help=_PUSH_TO_SECMAN_HELP),
    secman_url: str = typer.Option(None, "--secman-url", help=_SECMAN_URL_HELP),
    secman_username: str = typer.Option(None, "--secman-username", help=_SECMAN_USERNAME_HELP),
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
    skill: list[str] = typer.Option(None, "--skill", help=_SKILL_HELP),
    engine: str = typer.Option(None, "--engine", help=_ENGINE_HELP),
    codescanai_provider: str = typer.Option(None, "--codescanai-provider", help=_CODESCANAI_PROVIDER_HELP),
    codescanai_host: str = typer.Option(None, "--codescanai-host", help=_CODESCANAI_HOST_HELP),
    codescanai_port: int = typer.Option(None, "--codescanai-port", help=_CODESCANAI_PORT_HELP),
    codescanai_endpoint: str = typer.Option(None, "--codescanai-endpoint", help=_CODESCANAI_ENDPOINT_HELP),
    codescanai_bin: str = typer.Option(None, "--codescanai-bin", help=_CODESCANAI_BIN_HELP),
    codescanai_arg: list[str] = typer.Option(None, "--codescanai-arg", help=_CODESCANAI_ARG_HELP),
    codescanai_default_severity: str = typer.Option(None, "--codescanai-default-severity", help=_CODESCANAI_DEFAULT_SEVERITY_HELP),
) -> None:
    """Enumerate, clone, and security-review reachable repositories."""
    import asyncio

    from .orchestrator import run_scan

    try:
        cfg = _run_config(
            output_dir, concurrency, model, max_turns, max_cost_usd,
            include_archived, include_forks, max_size_mb, keep_clones, resume, limit,
            db_url=_resolve_db_url(db_url), db_user=db_user, db_ssl=db_ssl,
            no_db=no_db, create_issues=create_issues, dry_run=_enter_dry_run(dry_run),
            push_to_secman=push_to_secman, secman_url=secman_url,
            secman_username=secman_username,
            issue_prefix=issue_prefix,
            provider=provider, timeout_s=timeout, branch=branch,
            email_to=email_to, email_provider=email_provider,
            smtp_host=smtp_host, smtp_port=smtp_port, email_subject=subject,
            github_api_url=github_api_url, skills=skill,
            engine=engine, codescanai_provider=codescanai_provider,
            codescanai_host=codescanai_host, codescanai_port=codescanai_port,
            codescanai_endpoint=codescanai_endpoint, codescanai_bin=codescanai_bin,
            codescanai_args=codescanai_arg,
            codescanai_default_severity=codescanai_default_severity,
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
        True, "--last-commit/--no-last-commit",
        help="Append the latest default-branch commit (short SHA, date). On by default; "
             "it costs one extra API call per repo, so --no-last-commit is the fast path.",
    ),
    output_dir: Path = typer.Option(Path("output"), help="Where the state DB lives."),
    github_api_url: str = typer.Option(None, "--github-api-url", help=_GITHUB_API_URL_HELP),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
    no_db: bool = typer.Option(False, "--no-db", help="Print only; do not record the last commit in the state DB."),
) -> None:
    """Print the repositories that would be scanned (no cloning, no review)."""
    from .github_auth import build_auth
    from .state import StateStore

    filters = Filters(include_archived=include_archived, include_forks=include_forks, max_size_mb=max_size_mb)
    try:
        auth = build_auth(github_api_url)
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    # Without --last-commit there is nothing new to record, so no store is opened.
    store = None if no_db or not last_commit else StateStore(
        _resolve_db_url(db_url) or (output_dir / "secscan.sqlite3"),
        db_user=_resolve_db_user(db_user),
        db_password=_resolve_db_password(None),
        db_ssl=_resolve_db_ssl(db_ssl),
    )
    try:
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
                    if lc and store is not None:
                        store.record_last_commit(repo.owner, repo.name, lc[0], lc[1])
                typer.echo(line)
    finally:
        if store is not None:
            store.close()


_LIST_USERS_ORG_HELP = (
    "Organization login whose members to list, with each member's role (admin/member). "
    "GitHub exposes members only for organizations — a personal account has none."
)
_LIST_USERS_REPO_HELP = (
    "Repository as 'owner/name' whose collaborators to list, with each collaborator's "
    "permission level. Repeat for multiple repositories."
)


def _user_rows(
    auth, org: str | None, repos: list[str], org_repos: bool, filters: Filters
) -> list:
    """Collect users across every requested scope, deduped, App first then PAT.

    Returns a flat list of GithubUser. Scopes are kept in insertion order so the table,
    the CSV and the DB all see the same sequence.
    """
    from .github_users import OrgAccessError

    clients = [c for c in (auth.app, auth.pat) if c is not None]
    scopes: list[tuple[str, str]] = []  # (org, repo); repo == "" means org members
    if org:
        scopes.append((org, ""))
    for full_name in repos:
        owner, name = _split_full_name(full_name)
        scopes.append((owner, name))
    if org_repos:
        for client in clients:
            for repo in client.iter_repositories(org=org, filters=filters):
                if (repo.owner, repo.name) not in scopes:
                    scopes.append((repo.owner, repo.name))

    collected: list = []
    seen: set[tuple[str, str, str]] = set()
    for scope_org, scope_repo in scopes:
        errors: list[OrgAccessError] = []
        for client in clients:
            try:
                if scope_repo:
                    users = list(
                        client.iter_repo_collaborators(f"{scope_org}/{scope_repo}")
                    )
                else:
                    users = list(client.iter_org_members(scope_org))
            except OrgAccessError as exc:
                errors.append(exc)  # the other credential may still be able to see it
                continue
            for user in users:
                key = (user.org, user.repo, user.login)
                if key in seen:
                    continue  # App entry wins; PAT duplicates are dropped
                seen.add(key)
                collected.append(user)
            break
        else:
            if errors:
                raise errors[0]
    return collected


@app.command("list-users")
def list_users(
    org: str = typer.Option(None, "--org", help=_LIST_USERS_ORG_HELP),
    repo: list[str] = typer.Option(None, "--repo", help=_LIST_USERS_REPO_HELP),
    org_repos: bool = typer.Option(
        False, "--org-repos",
        help="With --org, also list the collaborators of every repository in that org.",
    ),
    github_api_url: str = typer.Option(None, "--github-api-url", help=_GITHUB_API_URL_HELP),
    format: str = typer.Option("table", "--format", help="table|csv|json."),
    output: Path = typer.Option(None, "--output", help="Write csv/json to this file instead of stdout."),
    no_csv: bool = typer.Option(False, "--no-csv", help="Do not write <output-dir>/users.csv."),
    include_archived: bool = typer.Option(False, help="With --org-repos, include archived repos."),
    include_forks: bool = typer.Option(False, help="With --org-repos, include forked repos."),
    output_dir: Path = typer.Option(Path("output"), help="Where users.csv and the state DB live."),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
    no_db: bool = typer.Option(False, "--no-db", help="Print only; do not record the users in the state DB."),
) -> None:
    """List the usernames in an organization and on its repositories.

    Org members and repo collaborators are organization-only GitHub APIs; they work the
    same on github.com / Enterprise Cloud, Enterprise Cloud with data residency, and
    Enterprise Server (see --github-api-url). Read-only: nothing is written to GitHub.
    """
    import dataclasses
    import json
    from datetime import datetime, timezone

    from .findings import render_users_csv, write_users_csv
    from .github_auth import build_auth
    from .github_users import OrgAccessError

    if format not in ("table", "csv", "json"):
        raise typer.BadParameter(f"--format must be table, csv, or json (got {format!r})")
    repos = list(repo or [])
    if not org and not repos:
        raise typer.BadParameter("pass --org and/or --repo (repeatable) to say whose users to list")
    if org_repos and not org:
        raise typer.BadParameter("--org-repos needs --org to say which organization's repos to walk")

    filters = Filters(
        include_archived=include_archived, include_forks=include_forks, max_size_mb=0
    )
    try:
        auth = build_auth(github_api_url)
        users = _user_rows(auth, org, repos, org_repos, filters)
    except (ConfigError, OrgAccessError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)

    if not no_db:
        store = _open_store(output_dir, db_url, db_user, None, db_ssl)
        seen_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            # One replace per scope, so a scope with no users left still empties.
            scopes = {(u.org, u.repo) for u in users}
            for scope_org, scope_repo in sorted(scopes):
                store.replace_users(
                    scope_org,
                    scope_repo,
                    [u for u in users if (u.org, u.repo) == (scope_org, scope_repo)],
                    seen_at=seen_at,
                )
        finally:
            store.close()

    if not no_csv:
        csv_path = write_users_csv(output_dir / "users.csv", users)
        typer.echo(f"Wrote {csv_path} ({len(users)} users)", err=True)

    if format == "table":
        for user in users:
            typer.echo(
                "\t".join(
                    (
                        user.source, user.scope, user.login, user.role or "-",
                        user.user_type or "-", user.name or "-",
                    )
                )
            )
        if not users:
            typer.echo("(no users found)")
        return

    if format == "json":
        rendered = json.dumps([dataclasses.asdict(u) for u in users], indent=2)
    else:
        rendered = render_users_csv(users)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered if rendered.endswith("\n") else rendered + "\n")
        typer.echo(f"Wrote {output}")
    else:
        typer.echo(rendered)


@app.command()
def review(
    path: Path = typer.Argument(..., help="Local repo directory to review."),
    output_dir: Path = typer.Option(Path("output"), help="Where the CSV is written."),
    store_db: bool = typer.Option(
        False, "--store-db",
        help=(
            "Also record the result and its High/Critical findings in the state DB "
            "under 'local/<dirname>', so stats / report / push-to-secman see it. "
            "Off by default: review writes findings.csv only."
        ),
    ),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL (with --store-db); defaults to SECSCAN_DB_URL or local SQLite."),
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
    model: str = typer.Option("sonnet", help=_MODEL_HELP),
    provider: str = typer.Option("auto", help=_PROVIDER_HELP),
    max_turns: int = typer.Option(60),
    max_cost_usd: float = typer.Option(None),
    timeout: float = typer.Option(
        900.0, help="Abort if the agent stalls (no output) this long, in seconds; 0 disables."
    ),
    skill: list[str] = typer.Option(None, "--skill", help=_SKILL_HELP),
    engine: str = typer.Option(None, "--engine", help=_ENGINE_HELP),
    codescanai_provider: str = typer.Option(None, "--codescanai-provider", help=_CODESCANAI_PROVIDER_HELP),
    codescanai_host: str = typer.Option(None, "--codescanai-host", help=_CODESCANAI_HOST_HELP),
    codescanai_port: int = typer.Option(None, "--codescanai-port", help=_CODESCANAI_PORT_HELP),
    codescanai_endpoint: str = typer.Option(None, "--codescanai-endpoint", help=_CODESCANAI_ENDPOINT_HELP),
    codescanai_bin: str = typer.Option(None, "--codescanai-bin", help=_CODESCANAI_BIN_HELP),
    codescanai_arg: list[str] = typer.Option(None, "--codescanai-arg", help=_CODESCANAI_ARG_HELP),
    codescanai_default_severity: str = typer.Option(None, "--codescanai-default-severity", help=_CODESCANAI_DEFAULT_SEVERITY_HELP),
) -> None:
    """Security-review a single local repository directory."""
    import asyncio

    from .orchestrator import review_local

    try:
        cfg = _run_config(
            output_dir, 1, model, max_turns, max_cost_usd,
            False, False, 0, True, True, None,
            db_url=_resolve_db_url(db_url), db_user=_resolve_db_user(db_user),
            db_ssl=_resolve_db_ssl(db_ssl),
            no_db=not store_db,
            provider=provider, timeout_s=timeout, skills=skill,
            engine=engine, codescanai_provider=codescanai_provider,
            codescanai_host=codescanai_host, codescanai_port=codescanai_port,
            codescanai_endpoint=codescanai_endpoint, codescanai_bin=codescanai_bin,
            codescanai_args=codescanai_arg,
            codescanai_default_severity=codescanai_default_severity,
        )
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    asyncio.run(review_local(cfg, path))


@app.command()
def scan(
    full_name: str = typer.Argument(..., help="Repository as 'owner/name'."),
    output_dir: Path = typer.Option(Path("output"), help="Where the CSV and state live."),
    github_api_url: str = typer.Option(None, "--github-api-url", help=_GITHUB_API_URL_HELP),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
    no_db: bool = typer.Option(False, "--no-db", help="Skip all DB storage; findings.csv is still written, summary.csv is skipped. Cannot combine with --create-issues."),
    create_issues: bool = typer.Option(False, "--create-issues", help="Open one GitHub issue per new High/Critical finding (deduped by content fingerprint). Requires the DB — cannot combine with --no-db."),
    push_to_secman: bool = typer.Option(False, "--push-to-secman", help=_PUSH_TO_SECMAN_HELP),
    secman_url: str = typer.Option(None, "--secman-url", help=_SECMAN_URL_HELP),
    secman_username: str = typer.Option(None, "--secman-username", help=_SECMAN_USERNAME_HELP),
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
    skill: list[str] = typer.Option(None, "--skill", help=_SKILL_HELP),
    engine: str = typer.Option(None, "--engine", help=_ENGINE_HELP),
    codescanai_provider: str = typer.Option(None, "--codescanai-provider", help=_CODESCANAI_PROVIDER_HELP),
    codescanai_host: str = typer.Option(None, "--codescanai-host", help=_CODESCANAI_HOST_HELP),
    codescanai_port: int = typer.Option(None, "--codescanai-port", help=_CODESCANAI_PORT_HELP),
    codescanai_endpoint: str = typer.Option(None, "--codescanai-endpoint", help=_CODESCANAI_ENDPOINT_HELP),
    codescanai_bin: str = typer.Option(None, "--codescanai-bin", help=_CODESCANAI_BIN_HELP),
    codescanai_arg: list[str] = typer.Option(None, "--codescanai-arg", help=_CODESCANAI_ARG_HELP),
    codescanai_default_severity: str = typer.Option(None, "--codescanai-default-severity", help=_CODESCANAI_DEFAULT_SEVERITY_HELP),
) -> None:
    """Clone one remote repository and security-review it. Locates the App installation
    owning the repo (falling back to the PAT when the App is not installed there)."""
    import asyncio

    from .orchestrator import scan_repo

    owner, name = _split_full_name(full_name)
    try:
        cfg = _run_config(
            output_dir, 1, model, max_turns, max_cost_usd,
            False, False, 0, keep_clones, False, None,
            db_url=_resolve_db_url(db_url), db_user=db_user, db_ssl=db_ssl,
            no_db=no_db, create_issues=create_issues, dry_run=_enter_dry_run(dry_run),
            push_to_secman=push_to_secman, secman_url=secman_url,
            secman_username=secman_username,
            issue_prefix=issue_prefix,
            provider=provider, timeout_s=timeout, branch=branch,
            email_to=email_to, email_provider=email_provider,
            smtp_host=smtp_host, smtp_port=smtp_port, email_subject=subject,
            github_api_url=github_api_url, skills=skill,
            engine=engine, codescanai_provider=codescanai_provider,
            codescanai_host=codescanai_host, codescanai_port=codescanai_port,
            codescanai_endpoint=codescanai_endpoint, codescanai_bin=codescanai_bin,
            codescanai_args=codescanai_arg,
            codescanai_default_severity=codescanai_default_severity,
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
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
) -> None:
    """Rebuild summary.csv from the state database."""
    from .findings import write_summary_csv

    store = _open_store(output_dir, db_url, db_user, None, db_ssl)
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
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
) -> None:
    """Print scan statistics from the state database (repos, findings by severity, cost)."""
    import json

    if ctx.invoked_subcommand is not None:
        return

    if format not in ("table", "csv", "json"):
        raise typer.BadParameter(f"--format must be table, csv, or json (got {format!r})")

    store = _open_store(output_dir, db_url, db_user, None, db_ssl)
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
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
) -> None:
    """Delete all stored statistics (scan history and findings) from the state database.

    Registered scan targets and GitHub issue tracking are kept — clearing issue
    tracking would make the next --create-issues run re-open issues that already
    exist on GitHub.
    """
    store = _open_store(output_dir, db_url, db_user, None, db_ssl)
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
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
) -> None:
    """Email the latest scan results as an HTML report (with a plain-text part)."""
    from .config import ConfigError
    from .report_sender import send_scan_report

    store = _open_store(output_dir, db_url, db_user, None, db_ssl)

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
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env)."),
) -> None:
    """Push High/Critical findings from the state DB into secman via cli-add."""
    from . import secman_client, secman_push

    dry_run = _enter_dry_run(dry_run)

    # No --secman-password flag exists (argv/ps exposure) — password comes from
    # SECMAN_PASSWORD only.
    url, username, password = secman_push.resolve_credentials(
        secman_url, secman_username, None
    )
    # A dry run never logs in or posts, so it needs no secman credentials at all.
    if not dry_run and (not url or not username or not password):
        typer.echo(f"Error: {_SECMAN_CREDS_MISSING}", err=True)
        raise typer.Exit(1)

    if dry_run:
        typer.echo("Dry run: nothing will be written to secman.")

    store = _open_store(output_dir, db_url, db_user, None, db_ssl)

    try:
        pushed, failed = secman_push.push_records(
            store, store.all_records(),
            url=url, username=username, password=password, dry_run=dry_run,
        )
    except secman_client.SecmanPushError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)

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


@skills_app.command("list")
def skills_list() -> None:
    """List the bundled security skill packs (name, then description)."""
    from .skills import bundled_skills

    found = bundled_skills()
    if not found:
        typer.echo("No bundled skills found.")
        return
    for s in found:
        typer.echo(f"{s.name}\t{s.description}")
    typer.echo(
        "\nUse with: secscan run|scan|review --skill <name> [--skill <name-or-path> ...]",
        err=True,
    )


@skills_app.command("show")
def skills_show(
    name: str = typer.Argument(..., help="Bundled skill name, or a path to a skill directory / SKILL.md."),
) -> None:
    """Print a skill's SKILL.md exactly as the reviewer will receive it."""
    from .skills import SkillError, resolve_skill

    try:
        skill = resolve_skill(name)
    except SkillError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    typer.echo(f"# {skill.name}  ({skill.skill_md})", err=True)
    typer.echo(skill.skill_md.read_text(encoding="utf-8"))


if __name__ == "__main__":
    app()
