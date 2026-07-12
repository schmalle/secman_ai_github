"""Async pipeline tying enumeration → clone → review → CSV → state together.

Bounded concurrency via a semaphore; per-repo failures are isolated and recorded so a
run continues; GitHub token minting and clones get a few retries with backoff.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import typer
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from .cloner import CloneError, cleanup, clone_repo
from .config import RunConfig
from .findings import write_findings_csv, write_summary_csv
from .github_app import RepoInfo, redact_url
from .github_auth import AuthContext, build_auth, resolve_target
from .providers import ProviderEnv, model_hint, resolve_model, resolve_provider
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
async def _clone(repo: RepoInfo, token: str, root: Path) -> Path:
    return await clone_repo(repo, token, root)


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


def _resolve_provider_env(cfg: RunConfig) -> ProviderEnv:
    provider_env = resolve_provider(cfg.provider)
    if provider_env.name != "anthropic":
        typer.echo(f"Reviews routed through {provider_env.name}.")
    cfg.model = resolve_model(provider_env, cfg.model)
    hint = model_hint(provider_env, cfg.model)
    if hint:
        typer.echo(hint)
    return provider_env


async def _process_repo(
    repo: RepoInfo, auth: AuthContext, store: StateStore, cfg: RunConfig,
    sem: asyncio.Semaphore, provider_env: ProviderEnv,
) -> None:
    owner, name = repo.owner, repo.name
    async with sem:
        path: Path | None = None
        try:
            token = await _mint_token(auth, repo)
            if store is not None:
                store.mark(owner, name, Status.CLONED)
            path = await _clone(repo, token, _clone_root(cfg))

            if store is not None:
                store.mark(owner, name, Status.REVIEWING)
            res = await review_repo(
                path,
                repo.full_name,
                model=cfg.model,
                max_turns=cfg.max_turns,
                max_cost_usd=cfg.max_cost_usd,
                extra_env=provider_env.env,
                idle_timeout_s=cfg.timeout_s,
            )

            csv_path = cfg.output_dir / f"{owner}__{name}" / "findings.csv"
            write_findings_csv(csv_path, repo.full_name, res.high_critical)
            if store is not None:
                store.replace_findings(owner, name, res.high_critical)

            if res.error and not res.findings:
                if store is not None:
                    store.record_failure(owner, name, res.error)
                typer.echo(f"  ! {repo.full_name}: review error: {res.error}")
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
                typer.echo(
                    f"  ✓ {repo.full_name}: {res.critical_count} critical, "
                    f"{res.high_count} high (${res.cost_usd:.3f})"
                )
        except Exception as exc:
            if store is not None:
                store.record_failure(owner, name, redact_url(str(exc)))
            typer.echo(f"  ! {repo.full_name}: {redact_url(str(exc))}")
        finally:
            if path is not None and not cfg.keep_clones:
                cleanup(path)


async def run_scan(
    cfg: RunConfig,
    org: str | None = None,
    repos_file: Path | None = None,
    targets_only: bool = False,
) -> None:
    auth = build_auth()
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
    repos, unresolved = _merge_scope(repos, _load_allowlist(repos_file), targets)
    for owner, name in unresolved:
        repos.append(await asyncio.to_thread(resolve_target, owner, name, auth))

    # Register all, then decide which to actually review (resume skips done).
    todo: list[RepoInfo] = []
    for repo in repos:
        if store is not None:
            store.upsert_pending(repo.owner, repo.name)
            if cfg.resume and store.is_done(repo.owner, repo.name):
                continue
        todo.append(repo)

    if cfg.limit is not None:
        todo = todo[: cfg.limit]

    typer.echo(f"{len(repos)} in scope, {len(todo)} to review (concurrency={cfg.concurrency}).")

    sem = asyncio.Semaphore(cfg.concurrency)
    await asyncio.gather(*(_process_repo(r, auth, store, cfg, sem, provider_env) for r in todo))

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


async def review_local(cfg: RunConfig, path: Path) -> None:
    """Review a single local repo directory (no GitHub, no state)."""
    path = Path(path).resolve()
    if not path.is_dir():
        raise typer.BadParameter(f"not a directory: {path}")
    name = path.name
    full_name = f"local/{name}"
    provider_env = _resolve_provider_env(cfg)

    typer.echo(f"Reviewing {full_name} …")
    res = await review_repo(
        path, full_name, model=cfg.model, max_turns=cfg.max_turns,
        max_cost_usd=cfg.max_cost_usd, extra_env=provider_env.env,
        idle_timeout_s=cfg.timeout_s,
    )

    csv_path = cfg.output_dir / f"local__{name}" / "findings.csv"
    write_findings_csv(csv_path, full_name, res.high_critical)

    if res.error:
        typer.echo(f"  ! review error: {res.error}")
    typer.echo(
        f"  {res.critical_count} critical, {res.high_count} high "
        f"({res.total_findings} total) — ${res.cost_usd:.3f}, {res.num_turns} turns"
    )
    typer.echo(f"  CSV: {csv_path}")


async def scan_repo(cfg: RunConfig, owner: str, name: str) -> None:
    """Clone, review, and record one remote repo by name (no enumeration)."""
    auth = build_auth()
    store = None if cfg.no_db else StateStore(
        cfg.state_target, db_user=cfg.db_user, db_password=cfg.db_password, db_ssl=cfg.db_ssl
    )
    provider_env = _resolve_provider_env(cfg)

    repo = await asyncio.to_thread(resolve_target, owner, name, auth)
    if store is not None:
        store.upsert_pending(owner, name)

    sem = asyncio.Semaphore(1)
    await _process_repo(repo, auth, store, cfg, sem, provider_env)

    if store is None:
        typer.echo("Done. --no-db: summary.csv skipped (no state store).")
        return

    summary = write_summary_csv(cfg.output_dir / "summary.csv", store.all_records())
    typer.echo(f"Done. summary={summary}")
