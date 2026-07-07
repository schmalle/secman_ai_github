# Single-repo scan and targets-only run Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `secscan scan owner/name` (clone + review one remote repo on demand) and `secscan run --targets-only` (scan only `repo add` targets, skipping GitHub App enumeration).

**Architecture:** Both features reuse existing orchestrator machinery — `_process_repo` (clone/review/record/cleanup pipeline) and `resolve_target` (repo lookup for explicit targets) — with no new pipeline logic. `run_scan` gains a boolean flag that short-circuits enumeration; a new `scan_repo` function drives `_process_repo` for a single repo.

**Tech Stack:** Python 3.10+, Typer (CLI), asyncio, pytest + pytest-asyncio (asyncio_mode=auto).

## Global Constraints

- Follow existing code style: no comments beyond what's already there unless clarifying a non-obvious constraint.
- Tests must not touch the network or require real GitHub/Claude credentials (existing project convention — see `tests/test_reviewer.py`, `tests/test_cli_repo.py`).
- `scan` and `run --targets-only` must not change the `repos`/`targets`/`findings` DB schema.
- Match the spec at `docs/superpowers/specs/2026-07-05-single-and-targets-only-scan-design.md`.

---

### Task 1: `run_scan` targets-only support

**Files:**
- Modify: `src/secscan/orchestrator.py:144` (the `run_scan` function signature and enumeration branch)
- Modify: `src/secscan/cli.py:87-115` (the `run` command)
- Test: `tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `orchestrator._process_repo(repo, auth, store, cfg, sem, provider_env)` (existing, unchanged), `orchestrator._merge_scope(enumerated, allowlist, targets)` (existing, unchanged), `github_auth.build_auth()` (existing), `state.StateStore` (existing).
- Produces: `orchestrator.run_scan(cfg, org=None, repos_file=None, targets_only=False)` — new `targets_only` keyword, default `False` so existing callers are unaffected.

- [ ] **Step 1: Write the failing test for targets-only enumeration skip**

Add to `tests/test_orchestrator.py` (new imports go at the top of the file alongside the existing ones):

```python
import secscan.orchestrator as orch
from secscan.config import RunConfig
from secscan.state import StateStore


class _FakeApp:
    def __init__(self):
        self.iter_called = False

    def iter_repositories(self, org=None, filters=None):
        self.iter_called = True
        return iter([])


class _FakeAuth:
    def __init__(self, app=None, pat=None):
        self.app = app
        self.pat = pat


async def test_run_scan_targets_only_skips_enumeration(tmp_path, monkeypatch):
    fake_app = _FakeApp()
    monkeypatch.setattr(orch, "build_auth", lambda: _FakeAuth(app=fake_app))

    processed = []

    async def fake_process_repo(repo, auth, store, cfg, sem, provider_env):
        processed.append(repo.full_name)

    monkeypatch.setattr(orch, "_process_repo", fake_process_repo)

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3")
    store = StateStore(cfg.state_target)
    store.add_target("octo", "demo")
    store.close()

    await orch.run_scan(cfg, targets_only=True)

    assert fake_app.iter_called is False
    assert processed == ["octo/demo"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_orchestrator.py::test_run_scan_targets_only_skips_enumeration -v`
Expected: FAIL with `TypeError: run_scan() got an unexpected keyword argument 'targets_only'`

- [ ] **Step 3: Add `targets_only` to `run_scan`**

In `src/secscan/orchestrator.py`, change the `run_scan` signature and enumeration branch (currently lines 144-156):

```python
async def run_scan(
    cfg: RunConfig,
    org: str | None = None,
    repos_file: Path | None = None,
    targets_only: bool = False,
) -> None:
    auth = build_auth()
    store = StateStore(cfg.state_target)
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
```

Leave the rest of the function (the `_merge_scope` call onward) untouched.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_orchestrator.py::test_run_scan_targets_only_skips_enumeration -v`
Expected: PASS

- [ ] **Step 5: Add the `--targets-only` CLI flag**

In `src/secscan/cli.py`, add a parameter to the `run` command (currently `src/secscan/cli.py:87-104`) right after `repos_file`:

```python
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
```

- [ ] **Step 6: Verify the flag parses**

Run: `uv run secscan run --help`
Expected: output includes a `--targets-only` line with the help text above.

- [ ] **Step 7: Run the full test suite**

Run: `uv run pytest -v`
Expected: all tests PASS (no regressions).

- [ ] **Step 8: Commit**

```bash
git add src/secscan/orchestrator.py src/secscan/cli.py tests/test_orchestrator.py
git commit -m "feat(cli): add --targets-only to run, skipping App enumeration"
```

---

### Task 2: `secscan scan owner/name`

**Files:**
- Modify: `src/secscan/orchestrator.py` (append a new `scan_repo` function; imports already present)
- Modify: `src/secscan/cli.py` (add the `scan` command; update the module docstring's command list at the top of the file)
- Test: `tests/test_orchestrator.py`
- Test: Create `tests/test_cli_scan.py`

**Interfaces:**
- Consumes: `orchestrator._process_repo` (existing), `github_auth.resolve_target(owner, name, auth)` (existing, already imported in `orchestrator.py`), `findings.write_summary_csv` (existing, already imported), `cli._split_full_name` (existing), `cli._run_config` (existing).
- Produces: `orchestrator.scan_repo(cfg: RunConfig, owner: str, name: str) -> None`.

- [ ] **Step 1: Write the failing test for `scan_repo`**

Add to `tests/test_orchestrator.py` (reuses the `_FakeAuth` class from Task 1):

```python
async def test_scan_repo_processes_single_repo_and_writes_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(orch, "build_auth", lambda: _FakeAuth(app=None, pat=None))

    calls = []

    async def fake_process_repo(repo, auth, store, cfg, sem, provider_env):
        calls.append(repo.full_name)
        store.record_result(
            repo.owner, repo.name,
            critical=1, high=0, total=1,
            duration_s=1.0, cost_usd=0.01, reviewed_at="now",
        )

    monkeypatch.setattr(orch, "_process_repo", fake_process_repo)

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3")

    await orch.scan_repo(cfg, "octo", "demo")

    assert calls == ["octo/demo"]
    assert (tmp_path / "summary.csv").exists()

    store = StateStore(cfg.state_target)
    record = store.get("octo", "demo")
    assert record is not None
    assert record.critical_count == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_orchestrator.py::test_scan_repo_processes_single_repo_and_writes_summary -v`
Expected: FAIL with `AttributeError: module 'secscan.orchestrator' has no attribute 'scan_repo'`

- [ ] **Step 3: Implement `scan_repo`**

Append to the end of `src/secscan/orchestrator.py` (after `review_local`):

```python
async def scan_repo(cfg: RunConfig, owner: str, name: str) -> None:
    """Clone, review, and record one remote repo by name (no enumeration)."""
    auth = build_auth()
    store = StateStore(cfg.state_target)
    provider_env = _resolve_provider_env(cfg)

    repo = await asyncio.to_thread(resolve_target, owner, name, auth)
    store.upsert_pending(owner, name)

    sem = asyncio.Semaphore(1)
    await _process_repo(repo, auth, store, cfg, sem, provider_env)

    summary = write_summary_csv(cfg.output_dir / "summary.csv", store.all_records())
    typer.echo(f"Done. summary={summary}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_orchestrator.py::test_scan_repo_processes_single_repo_and_writes_summary -v`
Expected: PASS

- [ ] **Step 5: Add the `scan` CLI command**

In `src/secscan/cli.py`, add a new command right after the `review` command (currently ends at `src/secscan/cli.py:160`), before the `report` command:

```python
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
```

- [ ] **Step 6: Update the module docstring's command list**

In `src/secscan/cli.py`, the file starts with (lines 1-10):

```python
"""Command-line interface for secscan.

Commands:
  run         enumerate + clone + review reachable repos, write CSVs
  list-repos  enumerate + filter only (no review) — show what would be scanned
  review      review a single local repo directory (dev/test loop, no GitHub)
  report      rebuild the aggregate summary.csv from the state DB
  repo        manage explicitly-added scan targets (add / list / remove)
  send-report email the latest results as an HTML report (Gmail / O365 / custom SMTP)
"""
```

Change it to:

```python
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
```

- [ ] **Step 7: Write the CLI validation test**

Create `tests/test_cli_scan.py`:

```python
from typer.testing import CliRunner

from secscan.cli import app

runner = CliRunner()


def test_scan_rejects_bad_name(tmp_path):
    for bad in ("noslash", "a/b/c", "/name", "owner/"):
        result = runner.invoke(app, ["scan", bad, "--output-dir", str(tmp_path)])
        assert result.exit_code != 0, bad
```

- [ ] **Step 8: Run test to verify it passes**

Run: `uv run pytest tests/test_cli_scan.py -v`
Expected: PASS

- [ ] **Step 9: Verify the command parses**

Run: `uv run secscan scan --help`
Expected: output shows the `full_name` argument and the options listed in Step 5.

- [ ] **Step 10: Run the full test suite**

Run: `uv run pytest -v`
Expected: all tests PASS (no regressions).

- [ ] **Step 11: Commit**

```bash
git add src/secscan/orchestrator.py src/secscan/cli.py tests/test_orchestrator.py tests/test_cli_scan.py
git commit -m "feat(cli): add 'scan' command to review a single remote repo on demand"
```

---

### Task 3: Documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing (documentation only).
- Produces: nothing consumed by later tasks — this is the last task.

- [ ] **Step 1: Add `scan` and `--targets-only` to the Usage block**

In `README.md`, the Usage section (currently lines 61-75) reads:

```
```bash
uv sync                                   # install deps into .venv

uv run secscan list-repos                 # preview what would be scanned
uv run secscan repo add octo/webapp       # add an explicit scan target (stored in DB)
uv run secscan repo list                  # show explicit targets
uv run secscan repo remove octo/webapp    # remove a target
uv run secscan review ./some/local/repo   # review one local dir (no GitHub)
uv run secscan run --limit 1              # full pipeline, one repo (smoke test)
uv run secscan run --org my-org           # scope to one org
uv run secscan run                        # all reachable repos + explicit targets
uv run secscan run --db-url mysql://user:pass@host:3306/secscan   # MySQL/MariaDB state
uv run secscan report                     # rebuild summary.csv from state
uv run secscan send-report --email-to sec@example.com --email-provider gmail
```
```

Replace with:

```
```bash
uv sync                                   # install deps into .venv

uv run secscan list-repos                 # preview what would be scanned
uv run secscan repo add octo/webapp       # add an explicit scan target (stored in DB)
uv run secscan repo list                  # show explicit targets
uv run secscan repo remove octo/webapp    # remove a target
uv run secscan scan octo/webapp           # clone + review one remote repo on demand
uv run secscan review ./some/local/repo   # review one local dir (no GitHub)
uv run secscan run --limit 1              # full pipeline, one repo (smoke test)
uv run secscan run --org my-org           # scope to one org
uv run secscan run --targets-only         # only scan 'repo add' targets (skip App enumeration)
uv run secscan run                        # all reachable repos + explicit targets
uv run secscan run --db-url mysql://user:pass@host:3306/secscan   # MySQL/MariaDB state
uv run secscan report                     # rebuild summary.csv from state
uv run secscan send-report --email-to sec@example.com --email-provider gmail
```
```

- [ ] **Step 2: Add `--targets-only` to the Common flags line**

Currently (README.md, around line 77-79):

```
Common flags: `--include-archived --include-forks --max-size-mb --concurrency
--model --provider --max-turns --max-cost-usd --output-dir --db-url --keep-clones
--no-resume --limit`.
```

Replace with:

```
Common flags: `--include-archived --include-forks --max-size-mb --concurrency
--model --provider --max-turns --max-cost-usd --output-dir --db-url --keep-clones
--no-resume --limit --targets-only`.
```

- [ ] **Step 3: Extend the "Scan targets" section**

Currently (README.md, around lines 95-102):

```
## Scan targets

`secscan repo add owner/name` registers a repository in the state database; every
`run` scans registered targets in addition to App-enumerated repos. Targets bypass
the size/archive/fork filters (they were added by hand) and are deduplicated against
enumeration. `repo list` and `repo remove` manage the set; targets follow the
selected backend (`--db-url` / `SECSCAN_DB_URL`), so a shared MySQL database gives a
shared target list.
```

Add a new paragraph directly after it:

```
To scan only the registered targets — without enumerating the whole GitHub App —
use `secscan run --targets-only` (a `--repos-file` allowlist still applies;
`--org` does not, since it only filters App enumeration). To scan one specific
remote repo on demand without registering it as a target, use
`secscan scan owner/name`; it clones, reviews, and records the result the same way
`run` does for a single repo, but doesn't add it to the target list.
```

- [ ] **Step 4: Verify the README renders sensibly**

Run: `uv run secscan run --help` and `uv run secscan scan --help`, and diff the output against what the README now documents — confirm flag names match exactly (`--targets-only`, `scan`'s options).

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: document 'scan' command and 'run --targets-only'"
```
