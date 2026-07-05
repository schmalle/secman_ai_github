# Single-repo scan and targets-only run

## Problem

`secscan` currently offers two scan entry points: `run` (enumerate the full GitHub
App + DB targets + `--repos-file` allowlist, then clone/review each) and `review`
(review one *local* directory, no GitHub involved). There is no way to:

1. Clone and review one specific **remote** repository on demand, without doing a
   full App enumeration or adding it as a permanent target first.
2. Scan only the repos registered via `secscan repo add`, without also enumerating
   every repo the GitHub App can reach.

## Design

### 1. `secscan scan owner/name`

A new orchestrator function, `scan_repo(cfg: RunConfig, owner: str, name: str) ->
None`, in `orchestrator.py`:

- Builds auth (`build_auth()`), opens the `StateStore`, resolves the provider env —
  same setup `run_scan`/`review_local` already do.
- Resolves a `RepoInfo` for the target via the existing `resolve_target(owner, name,
  auth)` helper (already used by `run_scan` for explicit DB targets the App
  enumeration didn't cover): PAT lookup first, else a generic `RepoInfo` with
  `installation_id=0` (clone via PAT).
- Registers the repo (`store.upsert_pending`) and drives it through the existing
  `_process_repo` helper — the same clone → review → write CSV → record
  state/findings → cleanup pipeline `run` uses per-repo, including its error
  handling. No new pipeline logic; this is reuse of `_process_repo` with a
  single-item, concurrency-1 "scope".
- Rewrites `summary.csv` from `store.all_records()` afterward, same as `run`.
- Always performs the scan — no resume-skip check. This is an explicit one-off
  action (mirrors `review`'s "always run" semantics for local dirs), not a batch
  job where skipping already-done repos matters.

New CLI command `scan` in `cli.py`:

```
secscan scan owner/name [--output-dir] [--db-url] [--model] [--provider]
                         [--max-turns] [--max-cost-usd] [--keep-clones]
```

Options mirror `review`'s (single-repo, no `Filters`/`concurrency`/`resume`/`limit`
knobs — explicit single-repo scans bypass filters the same way `repo add` targets
already do).

### 2. `secscan run --targets-only`

`run_scan` gains a `targets_only: bool = False` parameter. When `True`, it skips
`auth.app.iter_repositories(...)` entirely (`repos = []`) instead of enumerating,
and echoes a note that enumeration was skipped. Everything downstream is
unchanged: `_merge_scope` still pulls in DB targets and any `--repos-file`
allowlist, and concurrency/resume/state/CSV/summary behave exactly as today.

CLI `run` gains a `--targets-only` flag, passed straight through to `run_scan`.
`--org` has no effect when combined with `--targets-only` (it only filters App
enumeration) — documented in the flag's help text.

## Non-goals

- No change to how `resolve_target` finds App-installation coverage for a repo the
  App can't directly resolve (existing PAT-fallback limitation, documented in
  README, applies here too).
- No new database schema or state semantics — `scan` and `run --targets-only` both
  use the existing `repos`/`targets`/`findings` tables as-is.
- `scan` does not add the repo to the `targets` table — it's a one-off scan, not a
  registration. Users who want it scanned on every future `run` still need
  `secscan repo add`.

## Testing

Following the project's existing monkeypatch/fake style (no network, no real
subprocess):

- `test_orchestrator.py`:
  - `run_scan(..., targets_only=True)` never calls `auth.app.iter_repositories`
    even when an App is configured.
  - `scan_repo` resolves the target, calls `_process_repo` once, and writes
    `summary.csv`.
- CLI-level test (new `test_cli_scan.py` or added to `test_cli_repo.py`): bad
  `owner/name` argument is rejected the same way `repo add` rejects one.

## Documentation

- README: add `secscan scan owner/name` to the Usage block; document
  `--targets-only` in `run`'s flag list; update the "Scan targets" section to
  mention both new entry points.
- `cli.py` module docstring: add `scan` to the command list.
