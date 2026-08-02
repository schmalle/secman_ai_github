# Last commit in `list-repos`, persisted to state

Date: 2026-08-02

## Problem

`secscan list-repos` prints `owner/name` and size only. Knowing when a repository was
last touched is the cheapest way to judge whether it is worth scanning at all, and that
fact is currently unavailable unless the operator passes `--last-commit` — and even then
it is printed and thrown away, never stored.

## Goals

1. `list-repos` prints the latest commit (short SHA + `YYYY-MM-DD`) for every repo by default.
2. That fact is persisted in the state DB, so later commands and reports can use it.
3. A normal `run` fills the same columns without extra GitHub API calls.

## Non-goals

- Filtering or sorting repos by commit age. (Later, if wanted.)
- Surfacing the date in `stats`, `report`, `summary.csv`, or the HTML report.
- Changing what `--dry-run` covers. DB and state writes stay outside the guard, matching
  the existing carve-out documented in `CLAUDE.md`.

## Design

### 1. `list-repos` output

The latest-commit lookup becomes the default. `--last-commit` turns into a Typer boolean
toggle, `--last-commit / --no-last-commit`, defaulting to **on**:

```
schmalle/ask-elastic-py	3 KB	a1b2c3d	2026-06-14
schmalle/autocheck	1 KB	e4f5a6b	2025-11-02
```

Columns stay tab-separated: `full_name`, `size KB`, short SHA (7 chars), ISO date. A repo
that is empty or unreadable prints `-` `-`, as it does today.

`--no-last-commit` exists because the lookup costs **one extra GitHub API call per repo**
(`fetch_last_commit` in `github_app.py`). That is the whole reason the flag was off by
default; making it on by default trades listing speed and rate-limit budget for the
information, and `--no-last-commit` restores the old fast path exactly.

### 2. Schema: two columns on `repos`

| Column | SQLite | MySQL |
| --- | --- | --- |
| `last_commit_sha` | `TEXT NOT NULL DEFAULT ''` | `VARCHAR(64) NOT NULL DEFAULT ''` |
| `last_commit_date` | `TEXT NOT NULL DEFAULT ''` | `VARCHAR(32) NOT NULL DEFAULT ''` |

The full SHA is stored; truncation to 7 characters is a display concern and happens at
print time. The date is the commit's committer date as `YYYY-MM-DD`, the same format
`fetch_last_commit` already returns.

Both columns are added to `_REPOS_SQLITE` and `_REPOS_MYSQL` so fresh databases get them
from `CREATE TABLE`.

### 3. Migration

`state.py` has no migration mechanism — `StateStore.__init__` only executes
`CREATE TABLE IF NOT EXISTS`. An existing `output/secscan.sqlite3` or MySQL database would
therefore never gain the new columns, and every write to them would fail.

`StateStore.__init__` gains an idempotent `_ensure_columns()` step that runs immediately
after the schema loop. For each expected column it issues
`ALTER TABLE repos ADD COLUMN <name> <type> NOT NULL DEFAULT ''` and swallows the error
raised when the column already exists (SQLite: `duplicate column name`; MySQL: error 1060
`Duplicate column name`). Catch per statement, rollback-safe, continue on to the next.

This is deliberately the smallest thing that works rather than a versioned migration
framework: two columns, one table, both dialects tolerate the add-and-ignore pattern.

### 4. Store API

```python
def record_last_commit(self, owner: str, repo: str, sha: str, date: str) -> None:
    """Record the repo's latest commit without touching its scan status."""
```

It calls `upsert_pending(owner, repo)` — so a repo seen only by `list-repos` gets a row —
then `UPDATE repos SET last_commit_sha = ?, last_commit_date = ? WHERE owner = ? AND repo = ?`.

It must **not** go through `mark()`, because `mark()` writes `status`. Listing a repository
is not scanning it, and a `list-repos` run must never move a `done` repo back to `pending`
or otherwise disturb scan state.

`RepoRecord` gains `last_commit_sha: str = ""` and `last_commit_date: str = ""`, and
`_to_record` reads them.

### 5. `list-repos` gains DB flags

`list-repos` currently never touches the database. It gains the same options `run` has,
resolved through the same helpers (`_resolve_db_url`, `_resolve_db_user`,
`_resolve_db_password`, `_resolve_db_ssl`):

- `--output-dir` (default `output`) — the SQLite fallback path is `<output-dir>/secscan.sqlite3`
- `--db-url`, `--db-user`, `--db-password`, `--db-ssl`
- `--no-db` — print only, write nothing

Behavior:

- With `--no-db`, no store is opened.
- With `--no-last-commit`, there is nothing new to record, so no store is opened either.
- Otherwise, each enumerated repo with a resolvable commit is written via
  `record_last_commit`. A repo whose commit could not be read (`-` `-`) is not written.
- The store is closed when enumeration finishes.

### 6. `run` / `scan` record it from the clone

A plain `run` never invokes `list-repos`, so without this the new columns would stay empty
for the primary workflow.

After a successful clone, the working tree already contains the exact commit under review.
`orchestrator.py` reads it locally — `git log -1 --format=%H %cs` in the clone directory —
and calls `store.record_last_commit(...)`. This costs **zero** GitHub API calls and is
exact for the branch actually reviewed (including a non-default `--branch`), which the
enumeration-time lookup would not be.

Failure to read the local commit is non-fatal: log nothing, record nothing, continue the
review. A missing date must never fail a scan.

## Testing

- `list-repos` prints SHA + date with no flag (the previous default-off assertion in
  `tests/test_cli_list_repos.py` inverts).
- `--no-last-commit` makes no `last_commit` calls and prints only `full_name` + size.
- An unreadable/empty repo still prints `-` `-` and is not written to the store.
- `record_last_commit` on a `done` repo leaves `status` and finding counts untouched.
- `record_last_commit` on an unknown repo creates a `pending` row.
- Migration: open a `StateStore` against a SQLite DB created from the *old* `repos` schema,
  confirm both columns exist afterwards and a second open is a no-op.
- `list-repos --no-db` opens no store.
- `run` records the clone's HEAD; an unreadable clone does not fail the scan.

## Documentation

`README.md`: update the two `list-repos` usage lines and the paragraph describing the
output columns and `--last-commit`, including the API-cost note now attached to
`--no-last-commit` and the new DB flags on `list-repos`.
