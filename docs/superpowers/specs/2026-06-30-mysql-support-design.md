# MySQL support for secscan

**Date:** 2026-06-30
**Status:** Approved (design)

## Goal

Let secscan persist both its **run state** (the resumable manifest, one row per repo)
and its **security findings** in MySQL as an alternative to the default local SQLite
file. CSV outputs (`findings.csv` per repo, `summary.csv`) are unchanged and continue
to be written regardless of backend (dual-write).

The backend is chosen by a single connection URL: a `mysql://…` URL selects MySQL;
anything else (or no URL) keeps the existing SQLite-file behavior.

## Non-goals

- Replacing CSV output. CSVs remain the portable artifact and are always written.
- A migration tool to copy existing SQLite state into MySQL.
- Connection pooling, retries/reconnection on MySQL server timeouts, or HA concerns.
  The tool uses a single synchronous connection (DB writes happen on the event-loop
  thread, serialized), which is sufficient for current concurrency. Reconnection can
  be revisited if long runs hit server-side idle timeouts.
- Persisting findings for `review` (local single-repo review). That path has no state
  store today and stays CSV-only.

## Approach

Keep the project's raw DB-API, no-ORM style. Introduce a **thin SQL dialect
abstraction inside `state.py`**: one `StateStore` whose CRUD SQL is backend-agnostic,
with two dialects (SQLite, MySQL) supplying their own schema DDL, parameter
placeholder, and `INSERT … IGNORE` variant.

Rejected alternatives:
- **SQLAlchemy Core** — clean cross-DB but a heavy new dependency and a full rewrite of
  `state.py` for a 2-table schema. Overkill for this tool's style.
- **Two separate `StateStore` classes behind a Protocol** — duplicates all CRUD SQL per
  backend; more code to keep in sync.

## Components

### 1. `state.py` — dialect abstraction

An internal dialect object provides:

- `placeholder` — `"?"` (SQLite) or `"%s"` (MySQL).
- `insert_ignore` — `"INSERT OR IGNORE INTO"` (SQLite) or `"INSERT IGNORE INTO"` (MySQL).
- `schema` — the list of DDL statements for that backend (both `repos` and `findings`
  tables).
- `connect()` — returns an open DB-API connection.

`StateStore(target: str | Path)`:

- If `target` is a `str` starting with `mysql://`, parse it with `urllib.parse` and
  connect via **mysqlclient** (`MySQLdb.connect(host, port, user, passwd, db,
  charset="utf8mb4")`). Missing URL parts fall back to driver defaults
  (port 3306, etc.).
- Otherwise `target` is a SQLite file path — **identical behavior to today**
  (`sqlite3.connect`, `row_factory = sqlite3.Row`, parent dir created). All existing
  `StateStore(path)` call sites and tests keep working unchanged.

CRUD SQL is written once using `?` placeholders and translated to the dialect's
placeholder via a small `_ph(sql)` helper (`sql.replace("?", placeholder)`; no-op for
SQLite). The lone `INSERT OR IGNORE` (in `upsert_pending`) is built from the dialect's
`insert_ignore` prefix. Schema DDL is per-dialect, accounting for:

| Concern | SQLite | MySQL |
|---|---|---|
| PK on `(owner, repo)` text | `TEXT` | `VARCHAR(255)` (length required in key) |
| Float columns | `REAL` | `DOUBLE` |
| Findings PK | `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGINT AUTO_INCREMENT PRIMARY KEY` |

Row access stays uniform: SQLite uses `sqlite3.Row`; for MySQL the store reads rows as
dicts (cursor description → dict, or `DictCursor`) so `_to_record` / findings reads use
the same `row["col"]` access.

### 2. `findings` table + `StateStore.replace_findings(owner, repo, findings)`

New table mirroring `FINDING_FIELDS`:

```
findings(
  id           <autoincrement>,
  owner        VARCHAR/TEXT,
  repo         VARCHAR/TEXT,
  severity     TEXT,
  title        TEXT,
  category     TEXT,
  file_path    TEXT,
  line_range   TEXT,
  confidence   TEXT,
  description  TEXT,
  recommendation TEXT
)
```

`replace_findings(owner, repo, findings)`: delete existing rows for `(owner, repo)`,
then insert each finding, in one committed transaction. This makes re-review
(`--no-resume`) replace a repo's findings cleanly. It stores the same high/critical
findings that are written to CSV (`res.high_critical`).

The `findings` table is created in **both** backends so the code path is uniform (no
backend conditionals). For SQLite this is additive and harmless.

### 3. Config / backend selection (`config.py`, `cli.py`)

- `RunConfig` gains `db_url: str | None = None` (alongside the existing `state_db`
  default).
- Resolution order, computed in the CLI: `--db-url` flag → `SECSCAN_DB_URL` env →
  `None`. When `db_url` is set it is passed to `StateStore`; when `None`, the existing
  default SQLite path (`output_dir / "secscan.sqlite3"`) is used. This preserves
  today's default behavior with no env/flag set.
- `--db-url` option added to both `run` and `report` commands.

### 4. Wiring (`orchestrator.py`)

- `run_scan` opens the store from the resolved target (URL or SQLite path).
- In `_process_repo`, call `store.replace_findings(owner, name, res.high_critical)`
  alongside the existing `write_findings_csv(...)`.
- `summary.csv` still rebuilds from `store.all_records()` (backend-agnostic).
- `review_local` is unchanged (CSV-only, no state store).
- No dialect/backend branching in the orchestrator — the choice is hidden in
  `StateStore`.

### 5. Dependency + docs

- Add `mysqlclient>=2.2` to `pyproject.toml` dependencies.
- README: document `SECSCAN_DB_URL` (with a `mysql://user:pass@host:3306/secscan`
  example) and note mysqlclient's system build requirement (libmysqlclient /
  `default-libmysqlclient-dev` or `brew install mysql-client`).

## Data flow

```
run → resolve db_url (flag → env → default sqlite path)
    → StateStore(target)         # opens SQLite or MySQL, ensures repos + findings tables
    → per repo: store.mark(...) / record_result(...)         # state
                store.replace_findings(...)                  # findings → DB
                write_findings_csv(...)                      # findings → file (unchanged)
    → write_summary_csv(all_records())                       # summary → file (unchanged)
```

## Testing

- **Unchanged:** existing SQLite-backed `test_state.py` tests pass as-is.
- **New unit tests:**
  - `StateStore` backend selection: a `mysql://` string selects the MySQL dialect; a
    path/non-URL selects SQLite (assert via dialect attributes / placeholder, without
    opening a real MySQL connection).
  - Placeholder translation (`_ph`) produces `%s` for MySQL, `?` for SQLite.
  - `replace_findings` round-trip against SQLite (same dialect-agnostic code path):
    insert findings, read them back, re-run to confirm replacement (no duplicates).
- **Optional integration test:** a MySQL-backed round-trip gated behind
  `SECSCAN_TEST_MYSQL_URL`; skipped when the env var is unset so CI without a MySQL
  server stays green.

## Success criteria

1. With no `--db-url`/`SECSCAN_DB_URL`, behavior is byte-for-byte the same as today
   (SQLite file, CSVs).
2. With `SECSCAN_DB_URL=mysql://…`, a `run` writes state and findings into MySQL tables
   and still writes `findings.csv` and `summary.csv`.
3. `report --db-url mysql://…` rebuilds `summary.csv` from the MySQL `repos` table.
4. Re-review of a repo replaces (not duplicates) its findings rows.
5. All existing tests plus the new SQLite-backed tests pass.
