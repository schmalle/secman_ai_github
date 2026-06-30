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
from .config import GithubAppConfig, RunConfig
from .findings import write_findings_csv, write_summary_csv
from .github_app import GithubAppClient, RepoInfo, redact_url
from .reviewer import review_repo
from .state import StateStore, Status

_RETRY = dict(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=20), reraise=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clone_root(cfg: RunConfig) -> Path:
    return cfg.output_dir / "_clones"


@retry(**_RETRY)
async def _mint_token(client: GithubAppClient, installation_id: int) -> str:
    return await asyncio.to_thread(client.installation_token, installation_id)


@retry(retry=retry_if_exception_type(CloneError), **_RETRY)
async def _clone(repo: RepoInfo, token: str, root: Path) -> Path:
    return await clone_repo(repo, token, root)


def _load_allowlist(repos_file: Path | None) -> set[str] | None:
    if not repos_file:
        return None
    lines = Path(repos_file).read_text().splitlines()
    return {ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")}


async def _process_repo(
    repo: RepoInfo, client: GithubAppClient, store: StateStore, cfg: RunConfig, sem: asyncio.Semaphore
) -> None:
    owner, name = repo.owner, repo.name
    async with sem:
        path: Path | None = None
        try:
            token = await _mint_token(client, repo.installation_id)
            store.mark(owner, name, Status.CLONED)
            path = await _clone(repo, token, _clone_root(cfg))

            store.mark(owner, name, Status.REVIEWING)
            res = await review_repo(
                path,
                repo.full_name,
                model=cfg.model,
                max_turns=cfg.max_turns,
                max_cost_usd=cfg.max_cost_usd,
            )

            csv_path = cfg.output_dir / f"{owner}__{name}" / "findings.csv"
            write_findings_csv(csv_path, repo.full_name, res.high_critical)

            if res.error and not res.findings:
                store.record_failure(owner, name, res.error)
                typer.echo(f"  ! {repo.full_name}: review error: {res.error}")
            else:
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
            store.record_failure(owner, name, redact_url(str(exc)))
            typer.echo(f"  ! {repo.full_name}: {redact_url(str(exc))}")
        finally:
            if path is not None and not cfg.keep_clones:
                cleanup(path)


async def run_scan(cfg: RunConfig, org: str | None = None, repos_file: Path | None = None) -> None:
    client = GithubAppClient(GithubAppConfig.from_env())
    store = StateStore(cfg.state_db)

    typer.echo("Enumerating reachable repositories…")
    repos: list[RepoInfo] = await asyncio.to_thread(
        lambda: list(client.iter_repositories(org=org, filters=cfg.filters))
    )

    allowlist = _load_allowlist(repos_file)
    if allowlist is not None:
        repos = [r for r in repos if r.full_name in allowlist]

    # Register all, then decide which to actually review (resume skips done).
    todo: list[RepoInfo] = []
    for repo in repos:
        store.upsert_pending(repo.owner, repo.name)
        if cfg.resume and store.is_done(repo.owner, repo.name):
            continue
        todo.append(repo)

    if cfg.limit is not None:
        todo = todo[: cfg.limit]

    typer.echo(f"{len(repos)} in scope, {len(todo)} to review (concurrency={cfg.concurrency}).")

    sem = asyncio.Semaphore(cfg.concurrency)
    await asyncio.gather(*(_process_repo(r, client, store, cfg, sem) for r in todo))

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

    typer.echo(f"Reviewing {full_name} …")
    res = await review_repo(
        path, full_name, model=cfg.model, max_turns=cfg.max_turns, max_cost_usd=cfg.max_cost_usd
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
