"""Async pipeline tying enumeration → clone → review → CSV → state together.

Bounded concurrency via a semaphore; per-repo failures are isolated and recorded so a
run continues; GitHub token minting and clones get a few retries with backoff.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import typer
from github import Auth, Github
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from . import codescanai, codex, dryrun, fixer, kimi_cli, pull_requests
from .cloner import CloneError, cleanup, clone_repo, head_commit
from .config import DEFAULT_API_URL, RunConfig
from .findings import Finding, write_findings_csv, write_summary_csv
from .github_app import RepoInfo, redact_url
from .github_auth import AuthContext, build_auth, resolve_target
from .integration_results import (
    IntegrationClient,
    IntegrationContext,
    IntegrationResultError,
    build_run_body,
    finding_external_id,
    match_subject,
    same_github_instance,
    subject_repository_full_name,
    validate_base_url,
)
from .issues import process_finding
from .providers import ProviderEnv, model_hint, resolve_model, resolve_provider, with_model_env
from .report_sender import send_scan_report
from .reviewer import review_repo
from .state import StateStore, Status

_RETRY = dict(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=20), reraise=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clone_root(cfg: RunConfig) -> Path:
    return cfg.output_dir / "_clones"


@retry(**_RETRY)
async def _mint_token(auth: AuthContext, repo: RepoInfo) -> str:
    return await asyncio.to_thread(auth.token_for, repo)


@retry(retry=retry_if_exception_type(CloneError), **_RETRY)
async def _clone(repo: RepoInfo, token: str, root: Path, branch: str | None = None) -> Path:
    return await clone_repo(repo, token, root, branch)


def _load_allowlist(repos_file: Path | None) -> set[str] | None:
    if not repos_file:
        return None
    lines = Path(repos_file).read_text().splitlines()
    return {ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")}


def _merge_scope(
    enumerated: list[RepoInfo],
    allowlist: set[str] | None,
    targets: list[tuple[str, str]],
) -> tuple[list[RepoInfo], list[tuple[str, str]]]:
    """Combine enumerated repos, the --repos-file allowlist, and DB targets.

    Returns (in-scope enumerated repos, unresolved 'owner/name' pairs to look up).
    Enumerated repos are filtered by the allowlist (if given). DB targets and
    allowlist entries not found in the enumeration are returned for resolution.
    Deduped by full_name; enumerated entries win (they carry an installation_id).
    """
    if allowlist is not None:
        enumerated = [r for r in enumerated if r.full_name in allowlist]
    seen = {r.full_name for r in enumerated}

    wanted: list[tuple[str, str]] = list(targets)
    if allowlist is not None:
        wanted += [tuple(entry.split("/", 1)) for entry in sorted(allowlist) if "/" in entry]

    unresolved: list[tuple[str, str]] = []
    for owner, name in wanted:
        full_name = f"{owner}/{name}"
        if full_name in seen:
            continue
        seen.add(full_name)
        unresolved.append((owner, name))
    return enumerated, unresolved


def _create_issues_sync(
    token: str, repo: RepoInfo, store: StateStore, owner: str, name: str,
    findings: list, dry_run: bool, prefix: str, api_url: str = DEFAULT_API_URL,
) -> tuple[int, int]:
    """Blocking: mint a Github client, resolve the repo, and process each finding.

    Runs on a worker thread via asyncio.to_thread — Github()/get_repo()/create_issue()
    (the latter inside process_finding) are all synchronous network calls.

    When dry_run is True, process_finding never touches gh_repo, so skip the
    Github()/get_repo() calls entirely — dry-run makes zero GitHub API calls.
    """
    gh_repo = None
    if not dry_run:
        gh_client = Github(auth=Auth.Token(token), base_url=api_url)
        gh_repo = gh_client.get_repo(repo.full_name)
    created = skipped = 0
    for finding in findings:
        outcome = process_finding(
            gh_repo, store, owner, name, finding,
            seen_at=_now(), dry_run=dry_run, prefix=prefix,
        )
        if outcome.action in ("created", "would_create"):
            created += 1
        else:
            skipped += 1
    return created, skipped


def _announce_dry_run(cfg: RunConfig) -> None:
    """Say so up front — the flag is a safety net, and a silent one is worthless."""
    if cfg.dry_run:
        typer.echo(dryrun.notice())


def _prepare_integration(cfg: RunConfig, github_host) -> IntegrationContext | None:
    """Authenticate and discover this scanner's permitted inventory subjects."""
    if not cfg.push_to_secman or cfg.secman_scanner_id is None or cfg.dry_run:
        return None
    from . import secman_client

    base_url = validate_base_url(cfg.secman_url)
    token = secman_client.login(base_url, cfg.secman_username, cfg.secman_password)
    client = IntegrationClient(base_url, token)
    subjects = client.list_subjects(cfg.secman_scanner_id)
    return IntegrationContext(
        scanner_id=cfg.secman_scanner_id,
        github_instance=github_host.web_url,
        subjects=subjects,
        client=client,
    )


def _integration_model(cfg: RunConfig) -> str | None:
    config_name = {"kimi-cli": "kimi"}.get(cfg.engine, cfg.engine)
    engine_cfg = getattr(cfg, config_name, None)
    return getattr(engine_cfg, "model", None) or cfg.model


async def _submit_integration_run(
    cfg: RunConfig,
    repo: RepoInfo,
    *,
    status: str,
    findings: list[Finding],
    started_at: str,
    completed_at: str,
    commit_sha: str | None = None,
    store: StateStore | None = None,
    fix_pr_url: str | None = None,
    metadata: dict | None = None,
) -> None:
    context: IntegrationContext | None = cfg.integration_context
    if context is None:
        return
    subject = match_subject(context.subjects, repo, context.github_instance)
    if subject is None:
        raise IntegrationResultError(f"no permitted SecMan subject matches {repo.full_name}")
    issue_urls: dict[str, str] = {}
    if store is not None:
        from .findings import fingerprint

        for finding in findings:
            issue = store.find_issue(repo.owner, repo.name, fingerprint(finding))
            if issue is not None:
                issue_urls[finding_external_id(finding)] = issue.issue_url
    run_metadata = {
        "repository": repo.full_name,
        "githubInstance": context.github_instance,
        "githubRepoId": repo.github_repo_id,
        "highCriticalOnly": True,
    }
    if metadata:
        run_metadata.update(metadata)
    body = build_run_body(
        scanner_id=context.scanner_id,
        subject=subject,
        status=status,
        findings=findings,
        started_at=started_at,
        completed_at=completed_at,
        metadata=run_metadata,
        engine=cfg.engine,
        model=_integration_model(cfg),
        commit_sha=commit_sha,
        issue_urls=issue_urls,
        fix_pr_url=fix_pr_url or None,
    )
    if store is not None:
        store.record_integration_payload(repo.owner, repo.name, context.scanner_id, body)
    await asyncio.to_thread(context.client.submit_run, body)


def _resolve_provider_env(cfg: RunConfig) -> ProviderEnv:
    if cfg.engine == codescanai.ENGINE_NAME:
        # No Claude Code subprocess to route: CodeScanAI brings its own provider.
        cs = cfg.codescanai
        typer.echo(
            f"Reviews run by CodeScanAI: {cs.endpoint_label}, model "
            f"{cs.model or 'provider default'}."
        )
        return ProviderEnv(name=codescanai.ENGINE_NAME)
    if cfg.engine in (codex.ENGINE_NAME, kimi_cli.ENGINE_NAME):
        engine_cfg = cfg.codex if cfg.engine == codex.ENGINE_NAME else cfg.kimi
        typer.echo(
            f"Reviews run by {engine_cfg.endpoint_label}, model "
            f"{engine_cfg.model or 'engine default'}."
        )
        if cfg.skills:
            typer.echo("Skills: " + ", ".join(s.name for s in cfg.skills))
        return ProviderEnv(name=cfg.engine)
    provider_env = resolve_provider(cfg.provider)
    if provider_env.name != "anthropic":
        where = f" ({provider_env.endpoint})" if provider_env.endpoint else ""
        typer.echo(f"Reviews routed through {provider_env.name}{where}.")
    cfg.model = resolve_model(provider_env, cfg.model)
    # Gateways need every model the CLI may call pinned to a slug they serve.
    provider_env = with_model_env(provider_env, cfg.model)
    hint = model_hint(provider_env, cfg.model)
    if hint:
        typer.echo(hint)
    if cfg.skills:
        typer.echo("Skills: " + ", ".join(s.name for s in cfg.skills))
    return provider_env


async def _review(
    cfg: RunConfig, path: Path, full_name: str, provider_env: ProviderEnv, out_dir: Path
):
    """Run the configured engine over one directory. `out_dir` is the repo's output
    directory (next to findings.csv), for engine-specific artifacts."""
    if cfg.engine == codescanai.ENGINE_NAME:
        return await codescanai.review_repo(
            path, full_name,
            cfg=cfg.codescanai,
            idle_timeout_s=cfg.timeout_s,
            report_path=out_dir / codescanai.REPORT_FILENAME,
        )
    if cfg.engine == codex.ENGINE_NAME:
        return await codex.review_repo(
            path, full_name, cfg=cfg.codex, idle_timeout_s=cfg.timeout_s, skills=cfg.skills,
        )
    if cfg.engine == kimi_cli.ENGINE_NAME:
        return await kimi_cli.review_repo(
            path, full_name, cfg=cfg.kimi, idle_timeout_s=cfg.timeout_s, skills=cfg.skills,
        )
    return await review_repo(
        path, full_name,
        model=cfg.model,
        max_turns=cfg.max_turns,
        max_cost_usd=cfg.max_cost_usd,
        extra_env=provider_env.env,
        idle_timeout_s=cfg.timeout_s,
        skills=cfg.skills,
    )


def _gh_repo_factory(token: str, full_name: str, api_url: str):
    """Deferred PyGithub client: only built outside dry-run, on a worker thread."""
    def factory():
        return Github(auth=Auth.Token(token), base_url=api_url).get_repo(full_name)
    return factory


async def _maybe_fix(
    cfg: RunConfig,
    workspace: Path,
    full_name: str,
    findings: list[Finding],
    provider_env: ProviderEnv,
    out_dir: Path,
    *,
    store: StateStore | None,
    repo: RepoInfo | None = None,
    token: str | None = None,
    base_branch: str = "",
    api_url: str = DEFAULT_API_URL,
) -> pull_requests.FixPrOutcome | None:
    """Run the fix step over `workspace` (already a disposable git checkout) and,
    with --create-fix-prs, push it as a pull request on `repo`.

    Returns the PR outcome, or None when no PR step ran. Never raises for a failed
    fix or PR — the review result is already persisted by the time this runs, and a
    fix that could not be produced must not turn a successful scan into a failure.
    """
    if not cfg.fix or not findings:
        return None
    want_pr = cfg.create_fix_prs and store is not None and repo is not None

    key = fixer.fix_key(findings)
    if want_pr:
        existing = store.find_fix_pr(repo.owner, repo.name, key)
        if existing:
            typer.echo(f"    fix PR: skipped, already open for these findings: {existing.pr_url}")
            return pull_requests.FixPrOutcome(
                "skipped", pr_url=existing.pr_url, branch=existing.branch,
                reason="a pull request for these findings already exists",
            )

    typer.echo(f"    fixing {len(findings)} High/Critical finding(s) …")
    result = await fixer.fix_findings(cfg, workspace, full_name, findings, provider_env)
    patch_path, _ = fixer.write_artifacts(out_dir, result)
    if result.error:
        typer.echo(f"    ! fix error: {result.error}")
    typer.echo(
        f"    fix: {len(result.changed_files)} file(s) changed, "
        f"{len(result.fixed_titles)} finding(s) reported fixed (${result.cost_usd:.3f}) — {patch_path}"
    )
    if not want_pr:
        return None

    outcome = await pull_requests.create_fix_pr(
        workspace=workspace, repo=repo, base_branch=base_branch, token=token or "",
        store=store, result=result, dry_run=cfg.dry_run, prefix=cfg.pr_prefix,
        draft=cfg.pr_draft,
        gh_repo_factory=_gh_repo_factory(token or "", repo.full_name, api_url),
    )
    if outcome.action == "created":
        typer.echo(f"    fix PR: created {outcome.pr_url} ({outcome.branch} → {base_branch})")
    elif outcome.action == "would_create":
        typer.echo(
            f"    fix PR: would push {outcome.branch} and open a pull request into "
            f"{base_branch} ({len(result.changed_files)} files)"
        )
    elif outcome.action == "no_changes":
        typer.echo("    fix PR: nothing to open, the fix agent changed no files")
    elif outcome.action == "failed":
        typer.echo(f"    ! fix PR failed: {outcome.reason}")
    return outcome


async def _process_repo(
    repo: RepoInfo, auth: AuthContext, store: StateStore, cfg: RunConfig,
    sem: asyncio.Semaphore, provider_env: ProviderEnv,
) -> tuple[int, int]:
    """Returns (critical, high) counts found for this repo; (0, 0) on failure."""
    owner, name = repo.owner, repo.name
    started_at = _now()
    async with sem:
        path: Path | None = None
        commit_sha: str | None = None
        try:
            if store is not None:
                context = cfg.integration_context
                github_instance = getattr(
                    getattr(auth, "host", None),
                    "web_url",
                    context.github_instance if context is not None else "",
                )
                store.record_github_identity(
                    owner, name, github_instance, repo.github_repo_id
                )
            token = await _mint_token(auth, repo)
            if store is not None:
                store.mark(owner, name, Status.CLONED)
            path = await _clone(repo, token, _clone_root(cfg), cfg.branch)

            if store is not None or cfg.integration_context is not None:
                commit = await head_commit(path)
                if commit is not None:  # unreadable HEAD must never fail a scan
                    commit_sha = commit[0]
                    if store is not None:
                        store.record_last_commit(owner, name, commit[0], commit[1])
            if store is not None:
                store.mark(owner, name, Status.REVIEWING)
            repo_out = cfg.output_dir / f"{owner}__{name}"
            res = await _review(cfg, path, repo.full_name, provider_env, repo_out)

            csv_path = repo_out / "findings.csv"
            write_findings_csv(csv_path, repo.full_name, res.high_critical)
            if store is not None:
                store.replace_findings(owner, name, res.high_critical)

            if store is not None and cfg.create_issues and res.high_critical:
                created, skipped = await asyncio.to_thread(
                    _create_issues_sync, token, repo, store, owner, name,
                    res.high_critical, cfg.dry_run, cfg.issue_prefix, auth.host.api_url,
                )
                verb = "would create" if cfg.dry_run else "created"
                skip_verb = "would skip" if cfg.dry_run else "skipped"
                typer.echo(f"    issues: {verb} {created}, {skip_verb} {skipped}")

            fix_outcome = None
            if cfg.fix and res.high_critical:
                # The clone is disposable, so the fixer edits it in place. The
                # base branch is what was actually checked out — --branch, or the
                # remote HEAD the shallow clone followed.
                base_branch = cfg.branch or await fixer.current_branch(path) or repo.default_branch
                fix_outcome = await _maybe_fix(
                    cfg, path, repo.full_name, res.high_critical, provider_env, repo_out,
                    store=store, repo=repo, token=token, base_branch=base_branch,
                    api_url=auth.host.api_url,
                )

            if res.error and not res.findings:
                if store is not None:
                    store.record_failure(owner, name, res.error)
                await _submit_integration_run(
                    cfg,
                    repo,
                    status="FAILED",
                    findings=[],
                    started_at=started_at,
                    completed_at=_now(),
                    commit_sha=commit_sha,
                    store=store,
                    metadata={"outcome": "review failed"},
                )
                typer.echo(f"  ! {repo.full_name}: review error: {res.error}")
                return (0, 0)
            else:
                if store is not None:
                    store.record_result(
                        owner, name,
                        critical=res.critical_count,
                        high=res.high_count,
                        total=res.total_findings,
                        duration_s=res.duration_s,
                        cost_usd=res.cost_usd,
                        reviewed_at=_now(),
                    )
                await _submit_integration_run(
                    cfg,
                    repo,
                    status="PARTIAL" if res.error else "SUCCESS",
                    findings=res.high_critical,
                    started_at=started_at,
                    completed_at=_now(),
                    commit_sha=commit_sha,
                    store=store,
                    fix_pr_url=(fix_outcome.pr_url if fix_outcome else None),
                    metadata={"totalFindings": res.total_findings},
                )
                branch_note = f" ({cfg.branch})" if cfg.branch else ""
                typer.echo(
                    f"  ✓ {repo.full_name}{branch_note}: {res.critical_count} critical, "
                    f"{res.high_count} high (${res.cost_usd:.3f})"
                )
                return (res.critical_count, res.high_count)
        except IntegrationResultError:
            raise
        except Exception as exc:
            if store is not None:
                store.record_failure(owner, name, redact_url(str(exc)))
            await _submit_integration_run(
                cfg,
                repo,
                status="FAILED",
                findings=[],
                started_at=started_at,
                completed_at=_now(),
                commit_sha=commit_sha,
                store=store,
                metadata={"outcome": "scan failed"},
            )
            typer.echo(f"  ! {repo.full_name}: {redact_url(str(exc))}")
            return (0, 0)
        finally:
            if path is not None and not cfg.keep_clones:
                cleanup(path)


def _maybe_email_report(cfg: RunConfig, store: StateStore | None, run_high_critical: int) -> None:
    """Auto-email the report at run end when --email-to is set.

    Only sends when this run found High/Critical findings; a delivery failure is a
    warning, never a run failure (results are already stored by this point).
    """
    if not cfg.email_to or store is None:
        return
    if run_high_critical == 0:
        typer.echo("No High/Critical findings this run; email report skipped.")
        return
    try:
        n_repos, n_findings = send_scan_report(
            store, cfg.email_to,
            provider=cfg.email_provider, host=cfg.smtp_host, port=cfg.smtp_port,
            subject=cfg.email_subject,
        )
        typer.echo(
            f"Emailed report to {', '.join(cfg.email_to)} "
            f"({n_repos} repos, {n_findings} findings)."
        )
    except Exception as exc:
        typer.echo(f"Warning: failed to send email report: {exc}", err=True)


def _maybe_push_to_secman(cfg: RunConfig, store: StateStore | None, full_names: list[str]) -> None:
    """Push the High/Critical findings of the repos this invocation reviewed.

    Only those repos — everything else in the state DB stays the job of the
    standalone `push-to-secman` command. Runs after the findings are already
    persisted, so a push failure never costs the review.
    """
    if not cfg.push_to_secman or cfg.secman_scanner_id is not None or store is None:
        return
    from . import secman_client, secman_push

    wanted = set(full_names)
    records = [r for r in store.all_records() if r.full_name in wanted]
    try:
        pushed, failed = secman_push.push_records(
            store, records,
            url=cfg.secman_url, username=cfg.secman_username,
            password=cfg.secman_password, dry_run=cfg.dry_run,
        )
    except secman_client.SecmanPushError as exc:
        typer.echo(f"Error: secman push failed: {exc}", err=True)
        raise typer.Exit(1)

    verb = "would push" if cfg.dry_run else "pushed"
    typer.echo(f"secman: {verb} {pushed}" + ("" if cfg.dry_run else f", failed {failed}"))


async def run_scan(
    cfg: RunConfig,
    org: str | None = None,
    repos_file: Path | None = None,
    targets_only: bool = False,
) -> None:
    _announce_dry_run(cfg)
    auth = build_auth(cfg.github_api_url)
    cfg.integration_context = await asyncio.to_thread(_prepare_integration, cfg, auth.host)
    store = None if cfg.no_db else StateStore(
        cfg.state_target, db_user=cfg.db_user, db_password=cfg.db_password, db_ssl=cfg.db_ssl
    )
    provider_env = _resolve_provider_env(cfg)

    if targets_only:
        typer.echo("Targets-only mode: skipping GitHub App enumeration.")
        repos: list[RepoInfo] = []
    elif auth.app is not None:
        typer.echo("Enumerating reachable repositories…")
        repos: list[RepoInfo] = await asyncio.to_thread(
            lambda: list(auth.app.iter_repositories(org=org, filters=cfg.filters))
        )
    else:
        typer.echo("No GitHub App configured; scanning explicit targets only.")
        repos = []

    # Explicit targets (secscan repo add) and unmatched allowlist entries join the
    # scope; they bypass Filters because they were added by hand.
    targets = store.list_targets() if store is not None else []
    allowlist = _load_allowlist(repos_file)
    repos, unresolved = _merge_scope(repos, allowlist, targets)
    for owner, name in unresolved:
        repos.append(await asyncio.to_thread(resolve_target, owner, name, auth))

    if cfg.integration_context is not None:
        if not targets_only:
            seen = {repo.full_name.lower() for repo in repos}
            matched_subject_ids = {
                subject.id
                for repo in repos
                if (
                    subject := match_subject(
                        cfg.integration_context.subjects,
                        repo,
                        cfg.integration_context.github_instance,
                    )
                ) is not None
            }
            normalized_allowlist = (
                {item.lower() for item in allowlist} if allowlist is not None else None
            )
            for subject in cfg.integration_context.subjects:
                full_name = subject_repository_full_name(subject)
                if (
                    full_name is None
                    or subject.id in matched_subject_ids
                    or full_name in seen
                    or not same_github_instance(
                        subject.github_instance,
                        cfg.integration_context.github_instance,
                    )
                ):
                    continue
                owner, name = full_name.split("/", 1)
                if org and owner.lower() != org.lower():
                    continue
                if normalized_allowlist is not None and full_name not in normalized_allowlist:
                    continue
                repos.append(await asyncio.to_thread(resolve_target, owner, name, auth))
                seen.add(full_name)
        permitted = []
        for repo in repos:
            if match_subject(
                cfg.integration_context.subjects,
                repo,
                cfg.integration_context.github_instance,
            ) is not None:
                permitted.append(repo)
            else:
                typer.echo(f"  - {repo.full_name}: not a permitted SecMan scanner subject")
        repos = permitted

    # Register all, then decide which to actually review (resume skips done).
    todo: list[RepoInfo] = []
    for repo in repos:
        if store is not None:
            store.upsert_pending(repo.owner, repo.name)
            if cfg.resume and store.is_done(repo.owner, repo.name):
                await _submit_integration_run(
                    cfg,
                    repo,
                    status="SKIPPED",
                    findings=[],
                    started_at=_now(),
                    completed_at=_now(),
                    commit_sha=store.get(repo.owner, repo.name).last_commit_sha or None,
                    store=store,
                    metadata={"outcome": "resume skipped"},
                )
                continue
        todo.append(repo)

    if cfg.limit is not None:
        todo = todo[: cfg.limit]

    typer.echo(f"{len(repos)} in scope, {len(todo)} to review (concurrency={cfg.concurrency}).")

    sem = asyncio.Semaphore(cfg.concurrency)
    results = await asyncio.gather(
        *(_process_repo(r, auth, store, cfg, sem, provider_env) for r in todo)
    )

    if store is None:
        typer.echo("Done. --no-db: summary.csv skipped (no state store).")
        return

    summary = write_summary_csv(cfg.output_dir / "summary.csv", store.all_records())
    records = store.all_records()
    total_cost = sum(r.cost_usd for r in records)
    failed = [r for r in records if r.status == Status.FAILED]
    typer.echo(
        f"Done. summary={summary} | total review cost ${total_cost:.3f} | "
        f"{len(failed)} failed."
    )
    _maybe_push_to_secman(cfg, store, [r.full_name for r in todo])
    # `if r` skips None from monkeypatched/cancelled tasks that return nothing
    _maybe_email_report(cfg, store, sum(r[0] + r[1] for r in results if r))


async def review_local(cfg: RunConfig, path: Path) -> None:
    """Review a single local repo directory (no GitHub).

    State is written only with --store-db (cfg.no_db False), under owner `local`
    and the directory name — the same identity as the findings.csv it writes.
    """
    path = Path(path).resolve()
    if not path.is_dir():
        raise typer.BadParameter(f"not a directory: {path}")
    name = path.name
    full_name = f"local/{name}"
    provider_env = _resolve_provider_env(cfg)

    store = None if cfg.no_db else StateStore(
        cfg.state_target, db_user=cfg.db_user, db_password=cfg.db_password, db_ssl=cfg.db_ssl
    )
    try:
        typer.echo(f"Reviewing {full_name} …")
        if store is not None:
            commit = await head_commit(path)
            if commit is not None:  # None when the directory is not a git repo
                store.record_last_commit("local", name, commit[0], commit[1])
            store.mark("local", name, Status.REVIEWING)

        repo_out = cfg.output_dir / f"local__{name}"
        res = await _review(cfg, path, full_name, provider_env, repo_out)

        csv_path = repo_out / "findings.csv"
        write_findings_csv(csv_path, full_name, res.high_critical)

        if store is not None:
            store.replace_findings("local", name, res.high_critical)
            if res.error and not res.findings:
                store.record_failure("local", name, res.error)
            else:
                store.record_result(
                    "local", name,
                    critical=res.critical_count,
                    high=res.high_count,
                    total=res.total_findings,
                    duration_s=res.duration_s,
                    cost_usd=res.cost_usd,
                    reviewed_at=_now(),
                )

        if res.error:
            typer.echo(f"  ! review error: {res.error}")
        unit = "files" if cfg.engine == codescanai.ENGINE_NAME else "turns"
        typer.echo(
            f"  {res.critical_count} critical, {res.high_count} high "
            f"({res.total_findings} total) — ${res.cost_usd:.3f}, {res.num_turns} {unit}"
        )
        typer.echo(f"  CSV: {csv_path}")
        if store is not None:
            summary = write_summary_csv(cfg.output_dir / "summary.csv", store.all_records())
            typer.echo(f"  Stored as {full_name}; summary={summary}")

        if cfg.fix and res.high_critical:
            await _fix_local(cfg, path, full_name, res.high_critical, provider_env, repo_out, store)
    finally:
        if store is not None:
            store.close()


async def _fix_local(
    cfg: RunConfig, path: Path, full_name: str, findings: list[Finding],
    provider_env: ProviderEnv, repo_out: Path, store: StateStore | None,
) -> None:
    """The fix step for `review`: never edits `path` itself.

    The fixer works on a fresh clone (or copy) under a temp directory; with
    --create-fix-prs the directory's `origin` must point at a repository on the
    configured GitHub host, and the PR targets the branch currently checked out.
    """
    repo = token = None
    base_branch = ""
    api_url = DEFAULT_API_URL
    if cfg.create_fix_prs:
        auth = build_auth(cfg.github_api_url)
        api_url = auth.host.api_url
        remote = pull_requests.parse_github_remote(await pull_requests.origin_url(path), auth.host)
        if remote is None:
            typer.echo(
                "  ! --create-fix-prs: the directory has no 'origin' remote on "
                f"{auth.host.web_url}; writing fixes.patch only"
            )
        else:
            owner, name = remote
            repo = await asyncio.to_thread(resolve_target, owner, name, auth)
            token = await _mint_token(auth, repo)
            base_branch = await fixer.current_branch(path)
            if not base_branch:
                typer.echo("  ! --create-fix-prs: HEAD is detached; cannot pick a base branch")
                repo = None
            elif await fixer.has_uncommitted_changes(path):
                typer.echo(
                    "  warning: the directory has uncommitted changes; the fix is based on "
                    "its committed HEAD and they are not part of it"
                )

    root = fixer.temp_workspace_root()
    try:
        typer.echo(f"  preparing fix workspace under {root} …")
        workspace = await fixer.prepare_workspace(path, root, path.name)
        await _maybe_fix(
            cfg, workspace, full_name, findings, provider_env, repo_out,
            store=store, repo=repo, token=token, base_branch=base_branch, api_url=api_url,
        )
    except fixer.FixError as exc:
        typer.echo(f"  ! fix workspace error: {exc}")
    finally:
        cleanup(root)  # the patch under --output-dir is the durable copy


async def scan_repo(cfg: RunConfig, owner: str, name: str) -> None:
    """Clone, review, and record one remote repo by name (no enumeration)."""
    _announce_dry_run(cfg)
    auth = build_auth(cfg.github_api_url)
    cfg.integration_context = await asyncio.to_thread(_prepare_integration, cfg, auth.host)
    store = None if cfg.no_db else StateStore(
        cfg.state_target, db_user=cfg.db_user, db_password=cfg.db_password, db_ssl=cfg.db_ssl
    )
    provider_env = _resolve_provider_env(cfg)

    repo = await asyncio.to_thread(resolve_target, owner, name, auth)
    if cfg.integration_context is not None and match_subject(
        cfg.integration_context.subjects,
        repo,
        cfg.integration_context.github_instance,
    ) is None:
        raise IntegrationResultError(f"no permitted SecMan subject matches {repo.full_name}")
    if store is not None:
        store.upsert_pending(owner, name)

    sem = asyncio.Semaphore(1)
    result = await _process_repo(repo, auth, store, cfg, sem, provider_env)
    critical, high = result or (0, 0)

    if store is None:
        typer.echo("Done. --no-db: summary.csv skipped (no state store).")
        return

    summary = write_summary_csv(cfg.output_dir / "summary.csv", store.all_records())
    typer.echo(f"Done. summary={summary}")
    _maybe_push_to_secman(cfg, store, [f"{owner}/{name}"])
    _maybe_email_report(cfg, store, critical + high)
