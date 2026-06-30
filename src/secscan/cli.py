"""Command-line interface for secscan.

Commands:
  run         enumerate + clone + review reachable repos, write CSVs
  list-repos  enumerate + filter only (no review) — show what would be scanned
  review      review a single local repo directory (dev/test loop, no GitHub)
  report      rebuild the aggregate summary.csv from the state DB
"""

from __future__ import annotations

from pathlib import Path

import typer

from .config import Filters, RunConfig

app = typer.Typer(
    add_completion=False,
    help="Run autonomous Claude Code security reviews across GitHub App repositories.",
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
) -> RunConfig:
    return RunConfig(
        output_dir=output_dir,
        state_db=output_dir / "secscan.sqlite3",
        filters=Filters(
            include_archived=include_archived,
            include_forks=include_forks,
            max_size_mb=max_size_mb,
        ),
        concurrency=concurrency,
        model=model,
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
    output_dir: Path = typer.Option(Path("output"), help="Where CSVs and state live."),
    concurrency: int = typer.Option(4, help="Max repos reviewed in parallel."),
    model: str = typer.Option("sonnet", help="Claude model for reviews."),
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
    )
    asyncio.run(run_scan(cfg, org=org, repos_file=repos_file))


@app.command("list-repos")
def list_repos(
    org: str = typer.Option(None, help="Limit to a single org/owner login."),
    include_archived: bool = typer.Option(False),
    include_forks: bool = typer.Option(False),
    max_size_mb: int = typer.Option(500),
) -> None:
    """Print the repositories that would be scanned (no cloning, no review)."""
    from .config import GithubAppConfig
    from .github_app import GithubAppClient

    filters = Filters(include_archived=include_archived, include_forks=include_forks, max_size_mb=max_size_mb)
    client = GithubAppClient(GithubAppConfig.from_env())
    for repo in client.iter_repositories(org=org, filters=filters):
        typer.echo(f"{repo.full_name}\t{repo.size_kb} KB")


@app.command()
def review(
    path: Path = typer.Argument(..., help="Local repo directory to review."),
    output_dir: Path = typer.Option(Path("output"), help="Where the CSV is written."),
    model: str = typer.Option("sonnet"),
    max_turns: int = typer.Option(60),
    max_cost_usd: float = typer.Option(None),
) -> None:
    """Security-review a single local repository directory."""
    import asyncio

    from .orchestrator import review_local

    cfg = _run_config(
        output_dir, 1, model, max_turns, max_cost_usd,
        False, False, 0, True, True, None,
    )
    asyncio.run(review_local(cfg, path))


@app.command()
def report(
    output_dir: Path = typer.Option(Path("output"), help="Where state and CSVs live."),
) -> None:
    """Rebuild summary.csv from the state database."""
    from .findings import write_summary_csv
    from .state import StateStore

    store = StateStore(output_dir / "secscan.sqlite3")
    rows = store.all_records()
    out = write_summary_csv(output_dir / "summary.csv", rows)
    typer.echo(f"Wrote {out} ({len(rows)} repos)")


if __name__ == "__main__":
    app()
