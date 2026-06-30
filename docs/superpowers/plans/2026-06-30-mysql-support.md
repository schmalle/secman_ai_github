# MySQL Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let secscan persist run state and security findings in MySQL as an alternative to the default local SQLite file, selected by a single connection URL, while always also writing the existing CSV outputs.

**Architecture:** Introduce a thin SQL dialect abstraction inside `state.py`. One `StateStore` runs backend-agnostic CRUD SQL; two dialect objects (SQLite, MySQL) supply per-backend schema DDL, the parameter placeholder, and the `INSERT … IGNORE` variant. A new `findings` table is added to both backends and populated alongside the CSV write. Backend is chosen by inspecting the target: a `mysql://…` string selects MySQL; anything else is a SQLite file path (today's behavior, unchanged).

**Tech Stack:** Python 3.10+, raw DB-API (`sqlite3` stdlib + `mysqlclient`/`MySQLdb`), `urllib.parse`, pydantic (existing `Finding` model), typer, pytest.

## Global Constraints

- Default behavior with no `--db-url` and no `SECSCAN_DB_URL` env var MUST be byte-for-byte identical to today (SQLite file at `output_dir / "secscan.sqlite3"`, CSVs written).
- CSV outputs (`findings.csv`, `summary.csv`) are ALWAYS written regardless of backend (dual-write). MySQL never replaces CSV.
- No ORM. Keep the raw DB-API style already used in `state.py`.
- New dependency: `mysqlclient>=2.2`. Its import (`MySQLdb`) MUST be a local (function-level) import so SQLite-only test paths don't require the C extension at module load.
- The MySQL connection charset is `utf8mb4`.
- `review` (local single-repo review) stays CSV-only; it has no state store.

---

### Task 1: Dialect abstraction in `state.py` (SQLite behavior-preserving)

Refactor `StateStore` to run through a dialect object and cursors instead of the `sqlite3` connection shortcut, accept `str | Path` targets, and select a dialect by target. No findings table yet. Existing SQLite behavior and all existing `test_state.py` tests must keep passing.

**Files:**
- Modify: `src/secscan/state.py`
- Test: `tests/test_state.py` (add new tests; existing ones must still pass)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `StateStore(target: str | Path)` — unchanged public methods (`upsert_pending`, `mark`, `record_result`, `record_failure`, `get`, `is_done`, `all_records`, `close`). A `str` beginning with `mysql://` selects MySQL; any other `str`/`Path` is a SQLite file path.
  - `_dialect_for(target: str | Path) -> _Dialect` — module-level pure selector.
  - `_Dialect` dataclass with attributes `placeholder: str`, `insert_ignore: str`, `schema: tuple[str, ...]`.
  - Module-level singletons `_SQLITE_DIALECT` (placeholder `"?"`) and `_MYSQL_DIALECT` (placeholder `"%s"`).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_state.py`:

```python
from secscan.state import _dialect_for, _MYSQL_DIALECT, _SQLITE_DIALECT


def test_dialect_for_selects_mysql_on_url():
    d = _dialect_for("mysql://user:pass@host:3306/secscan")
    assert d is _MYSQL_DIALECT
    assert d.placeholder == "%s"
    assert d.insert_ignore == "INSERT IGNORE INTO"


def test_dialect_for_selects_sqlite_for_path(tmp_path):
    assert _dialect_for(tmp_path / "s.sqlite3") is _SQLITE_DIALECT
    assert _dialect_for("output/secscan.sqlite3") is _SQLITE_DIALECT
    assert _SQLITE_DIALECT.placeholder == "?"


def test_store_translates_placeholders_for_dialect(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    assert store._ph("SELECT ? , ?") == "SELECT ? , ?"  # sqlite: unchanged
    store._d = _MYSQL_DIALECT  # exercise translation without a live server
    assert store._ph("SELECT ? , ?") == "SELECT %s , %s"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_state.py::test_dialect_for_selects_mysql_on_url -v`
Expected: FAIL with `ImportError: cannot import name '_dialect_for'`.

- [ ] **Step 3: Rewrite `state.py` with the dialect abstraction**

Replace the file contents with:

```python
"""Resumable state manifest backed by SQLite or MySQL.

One row per repository in `repos`, keyed by (owner, repo). Lets long multi-repo runs
be interrupted and resumed, and lets `secscan report` rebuild summary.csv afterwards.

The backend is chosen from the target passed to `StateStore`: a `mysql://…` URL selects
MySQL (via mysqlclient); anything else is a SQLite file path (the default).
"""

from __future__ import annotations

import sqlite3
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Status(str, Enum):
    PENDING = "pending"
    CLONED = "cloned"
    REVIEWING = "reviewing"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class RepoRecord:
    owner: str
    repo: str
    status: Status = Status.PENDING
    critical_count: int = 0
    high_count: int = 0
    total_findings: int = 0
    duration_s: float = 0.0
    cost_usd: float = 0.0
    reviewed_at: str = ""
    error: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"


# -- schema (per dialect) -------------------------------------------------------

_REPOS_SQLITE = """
CREATE TABLE IF NOT EXISTS repos (
    owner          TEXT NOT NULL,
    repo           TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count     INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    duration_s     REAL NOT NULL DEFAULT 0,
    cost_usd       REAL NOT NULL DEFAULT 0,
    reviewed_at    TEXT NOT NULL DEFAULT '',
    error          TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (owner, repo)
);
"""

_REPOS_MYSQL = """
CREATE TABLE IF NOT EXISTS repos (
    owner          VARCHAR(255) NOT NULL,
    repo           VARCHAR(255) NOT NULL,
    status         VARCHAR(32) NOT NULL DEFAULT 'pending',
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count     INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    duration_s     DOUBLE NOT NULL DEFAULT 0,
    cost_usd       DOUBLE NOT NULL DEFAULT 0,
    reviewed_at    VARCHAR(64) NOT NULL DEFAULT '',
    error          TEXT,
    PRIMARY KEY (owner, repo)
);
"""


@dataclass(frozen=True)
class _Dialect:
    placeholder: str
    insert_ignore: str
    schema: tuple[str, ...]


_SQLITE_DIALECT = _Dialect(
    placeholder="?",
    insert_ignore="INSERT OR IGNORE INTO",
    schema=(_REPOS_SQLITE,),
)

_MYSQL_DIALECT = _Dialect(
    placeholder="%s",
    insert_ignore="INSERT IGNORE INTO",
    schema=(_REPOS_MYSQL,),
)


def _is_mysql(target: str | Path) -> bool:
    return isinstance(target, str) and target.startswith("mysql://")


def _dialect_for(target: str | Path) -> _Dialect:
    return _MYSQL_DIALECT if _is_mysql(target) else _SQLITE_DIALECT


def _connect_sqlite(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def _connect_mysql(url: str):
    import MySQLdb
    from MySQLdb.cursors import DictCursor

    p = urllib.parse.urlparse(url)
    return MySQLdb.connect(
        host=p.hostname or "localhost",
        port=p.port or 3306,
        user=urllib.parse.unquote(p.username or ""),
        passwd=urllib.parse.unquote(p.password or ""),
        db=p.path.lstrip("/"),
        charset="utf8mb4",
        cursorclass=DictCursor,
    )


class StateStore:
    def __init__(self, target: str | Path):
        self._d = _dialect_for(target)
        if _is_mysql(target):
            self._conn = _connect_mysql(str(target))
        else:
            self._conn = _connect_sqlite(Path(target))
        cur = self._conn.cursor()
        for stmt in self._d.schema:
            cur.execute(stmt)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- internals --------------------------------------------------------------

    def _ph(self, sql: str) -> str:
        if self._d.placeholder == "?":
            return sql
        return sql.replace("?", self._d.placeholder)

    def _exec(self, sql: str, params: tuple = ()):
        cur = self._conn.cursor()
        cur.execute(self._ph(sql), params)
        self._conn.commit()
        return cur

    # -- writes -----------------------------------------------------------------

    def upsert_pending(self, owner: str, repo: str) -> None:
        """Insert a pending row if the repo is unknown; never downgrade an existing one."""
        self._exec(
            f"{self._d.insert_ignore} repos (owner, repo, status) VALUES (?, ?, ?)",
            (owner, repo, Status.PENDING.value),
        )

    def mark(self, owner: str, repo: str, status: Status, **fields) -> None:
        self.upsert_pending(owner, repo)
        cols = ["status"]
        vals: list = [status.value]
        for key, value in fields.items():
            cols.append(key)
            vals.append(value)
        assignments = ", ".join(f"{c} = ?" for c in cols)
        vals.extend([owner, repo])
        self._exec(
            f"UPDATE repos SET {assignments} WHERE owner = ? AND repo = ?", tuple(vals)
        )

    def record_result(
        self,
        owner: str,
        repo: str,
        *,
        critical: int,
        high: int,
        total: int,
        duration_s: float,
        cost_usd: float,
        reviewed_at: str,
    ) -> None:
        self.mark(
            owner,
            repo,
            Status.DONE,
            critical_count=critical,
            high_count=high,
            total_findings=total,
            duration_s=duration_s,
            cost_usd=cost_usd,
            reviewed_at=reviewed_at,
            error="",
        )

    def record_failure(self, owner: str, repo: str, error: str) -> None:
        self.mark(owner, repo, Status.FAILED, error=error)

    # -- reads ------------------------------------------------------------------

    def get(self, owner: str, repo: str) -> RepoRecord | None:
        cur = self._exec(
            "SELECT * FROM repos WHERE owner = ? AND repo = ?", (owner, repo)
        )
        row = cur.fetchone()
        return self._to_record(row) if row else None

    def is_done(self, owner: str, repo: str) -> bool:
        rec = self.get(owner, repo)
        return rec is not None and rec.status == Status.DONE

    def all_records(self) -> list[RepoRecord]:
        cur = self._exec("SELECT * FROM repos ORDER BY owner, repo")
        return [self._to_record(r) for r in cur.fetchall()]

    @staticmethod
    def _to_record(row) -> RepoRecord:
        return RepoRecord(
            owner=row["owner"],
            repo=row["repo"],
            status=Status(row["status"]),
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            total_findings=row["total_findings"],
            duration_s=row["duration_s"],
            cost_usd=row["cost_usd"],
            reviewed_at=row["reviewed_at"],
            error=row["error"] or "",
        )
```

- [ ] **Step 4: Run the full state test file to verify pass**

Run: `uv run pytest tests/test_state.py -v`
Expected: PASS — all pre-existing tests plus the three new ones.

- [ ] **Step 5: Commit**

```bash
git add src/secscan/state.py tests/test_state.py
git commit -m "refactor(state): dialect abstraction for SQLite/MySQL backends"
```

---

### Task 2: `findings` table and `replace_findings`

Add a `findings` table to both dialects and a method to replace a repo's findings (delete-then-insert). Tested against SQLite, which exercises the same dialect-agnostic code path used for MySQL.

**Files:**
- Modify: `src/secscan/state.py`
- Test: `tests/test_state.py`

**Interfaces:**
- Consumes: `Finding` from `secscan.findings` (has `.severity.value`, `.title`, `.category`, `.file_path`, `.line_range`, `.confidence`, `.description`, `.recommendation`).
- Produces:
  - `StateStore.replace_findings(owner: str, repo: str, findings: Iterable[Finding]) -> None`
  - `StateStore.get_findings(owner: str, repo: str) -> list[dict]` (read helper for tests/inspection; rows as dicts with the finding columns).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_state.py`:

```python
from secscan.findings import Finding


def _f(severity, title):
    return Finding(severity=severity, title=title, description="d")


def test_replace_findings_round_trip(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.replace_findings("octo", "repo", [_f("critical", "sqli"), _f("high", "xss")])
    rows = store.get_findings("octo", "repo")
    assert {r["title"] for r in rows} == {"sqli", "xss"}
    assert {r["severity"] for r in rows} == {"critical", "high"}


def test_replace_findings_replaces_not_appends(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.replace_findings("octo", "repo", [_f("high", "first")])
    store.replace_findings("octo", "repo", [_f("critical", "second")])
    rows = store.get_findings("octo", "repo")
    assert [r["title"] for r in rows] == ["second"]


def test_replace_findings_empty_clears(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.replace_findings("octo", "repo", [_f("high", "first")])
    store.replace_findings("octo", "repo", [])
    assert store.get_findings("octo", "repo") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_state.py::test_replace_findings_round_trip -v`
Expected: FAIL with `AttributeError: 'StateStore' object has no attribute 'replace_findings'`.

- [ ] **Step 3: Add the findings schema and methods**

In `src/secscan/state.py`, add the findings DDL constants after `_REPOS_MYSQL`:

```python
_FINDINGS_SQLITE = """
CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    owner          TEXT NOT NULL,
    repo           TEXT NOT NULL,
    severity       TEXT NOT NULL,
    title          TEXT NOT NULL,
    category       TEXT NOT NULL DEFAULT '',
    file_path      TEXT NOT NULL DEFAULT '',
    line_range     TEXT NOT NULL DEFAULT '',
    confidence     TEXT NOT NULL DEFAULT '',
    description    TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT ''
);
"""

_FINDINGS_MYSQL = """
CREATE TABLE IF NOT EXISTS findings (
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    owner          VARCHAR(255) NOT NULL,
    repo           VARCHAR(255) NOT NULL,
    severity       VARCHAR(32) NOT NULL,
    title          TEXT NOT NULL,
    category       VARCHAR(255) NOT NULL DEFAULT '',
    file_path      TEXT NOT NULL,
    line_range     VARCHAR(255) NOT NULL DEFAULT '',
    confidence     VARCHAR(32) NOT NULL DEFAULT '',
    description    TEXT NOT NULL,
    recommendation TEXT NOT NULL
);
"""
```

Update both dialect `schema` tuples to include the findings table:

```python
_SQLITE_DIALECT = _Dialect(
    placeholder="?",
    insert_ignore="INSERT OR IGNORE INTO",
    schema=(_REPOS_SQLITE, _FINDINGS_SQLITE),
)

_MYSQL_DIALECT = _Dialect(
    placeholder="%s",
    insert_ignore="INSERT IGNORE INTO",
    schema=(_REPOS_MYSQL, _FINDINGS_MYSQL),
)
```

Add `from typing import Iterable` to the imports and a `TYPE_CHECKING` import for `Finding`:

```python
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from .findings import Finding
```

Add these methods to `StateStore` (after `record_failure`):

```python
    _FINDING_COLS = (
        "owner", "repo", "severity", "title", "category",
        "file_path", "line_range", "confidence", "description", "recommendation",
    )

    def replace_findings(self, owner: str, repo: str, findings: "Iterable[Finding]") -> None:
        """Replace all stored findings for a repo (delete-then-insert), one transaction."""
        cur = self._conn.cursor()
        cur.execute(
            self._ph("DELETE FROM findings WHERE owner = ? AND repo = ?"), (owner, repo)
        )
        rows = [
            (
                owner, repo, f.severity.value, f.title, f.category,
                f.file_path, f.line_range, f.confidence, f.description, f.recommendation,
            )
            for f in findings
        ]
        if rows:
            cols = ", ".join(self._FINDING_COLS)
            marks = ", ".join("?" for _ in self._FINDING_COLS)
            cur.executemany(
                self._ph(f"INSERT INTO findings ({cols}) VALUES ({marks})"), rows
            )
        self._conn.commit()

    def get_findings(self, owner: str, repo: str) -> list[dict]:
        cur = self._exec(
            "SELECT * FROM findings WHERE owner = ? AND repo = ? ORDER BY id",
            (owner, repo),
        )
        return [dict(r) for r in cur.fetchall()]
```

- [ ] **Step 4: Run findings tests to verify they pass**

Run: `uv run pytest tests/test_state.py -v`
Expected: PASS — all state tests including the three new findings tests.

- [ ] **Step 5: Commit**

```bash
git add src/secscan/state.py tests/test_state.py
git commit -m "feat(state): persist findings in a findings table"
```

---

### Task 3: Config and CLI backend selection

Add `db_url` to `RunConfig` and a `--db-url` option (env fallback `SECSCAN_DB_URL`) to the `run` and `report` commands. When set, it is the `StateStore` target; otherwise the existing SQLite path is used.

**Files:**
- Modify: `src/secscan/config.py:54-71` (`RunConfig`)
- Modify: `src/secscan/cli.py`
- Test: `tests/test_config.py` (new file)

**Interfaces:**
- Consumes: `RunConfig` from Task's existing code.
- Produces:
  - `RunConfig.db_url: str | None` (default `None`).
  - `RunConfig.state_target` property → `self.db_url or self.state_db` (the value to pass to `StateStore`).
  - CLI helper `_resolve_db_url(db_url: str | None) -> str | None` → `db_url` or `SECSCAN_DB_URL` env or `None`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_config.py`:

```python
from pathlib import Path

from secscan.cli import _resolve_db_url
from secscan.config import RunConfig


def test_db_url_defaults_to_none():
    cfg = RunConfig()
    assert cfg.db_url is None


def test_state_target_prefers_db_url():
    cfg = RunConfig(state_db=Path("output/secscan.sqlite3"), db_url="mysql://h/db")
    assert cfg.state_target == "mysql://h/db"


def test_state_target_falls_back_to_sqlite_path():
    cfg = RunConfig(state_db=Path("output/secscan.sqlite3"))
    assert cfg.state_target == Path("output/secscan.sqlite3")


def test_resolve_db_url_flag_wins(monkeypatch):
    monkeypatch.setenv("SECSCAN_DB_URL", "mysql://env/db")
    assert _resolve_db_url("mysql://flag/db") == "mysql://flag/db"


def test_resolve_db_url_env_fallback(monkeypatch):
    monkeypatch.setenv("SECSCAN_DB_URL", "mysql://env/db")
    assert _resolve_db_url(None) == "mysql://env/db"


def test_resolve_db_url_none_when_unset(monkeypatch):
    monkeypatch.delenv("SECSCAN_DB_URL", raising=False)
    assert _resolve_db_url(None) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL with `AttributeError: 'RunConfig' object has no attribute 'db_url'`.

- [ ] **Step 3: Add `db_url` and `state_target` to `RunConfig`**

In `src/secscan/config.py`, inside `RunConfig` add the field after `state_db` (line 59) and the property after `__post_init__`:

```python
    state_db: Path = Path("output/secscan.sqlite3")
    db_url: str | None = None  # mysql://… selects MySQL; None uses state_db (SQLite)
```

```python
    @property
    def state_target(self) -> "str | Path":
        return self.db_url or self.state_db
```

- [ ] **Step 4: Add `_resolve_db_url` and wire `--db-url` in the CLI**

In `src/secscan/cli.py`:

Add the helper near the top (after the imports):

```python
def _resolve_db_url(db_url: str | None) -> str | None:
    import os

    return db_url or os.environ.get("SECSCAN_DB_URL") or None
```

Add a `db_url` parameter to `_run_config` and pass it through:

```python
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
) -> RunConfig:
    return RunConfig(
        output_dir=output_dir,
        state_db=output_dir / "secscan.sqlite3",
        db_url=db_url,
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
```

In the `run` command, add the option and pass it. Add this option after `output_dir` (line 59):

```python
    db_url: str = typer.Option(None, help="MySQL URL (mysql://user:pass@host:3306/db). Defaults to SECSCAN_DB_URL or local SQLite."),
```

and update its `_run_config(...)` call to pass `db_url=_resolve_db_url(db_url)` as the final argument:

```python
    cfg = _run_config(
        output_dir, concurrency, model, max_turns, max_cost_usd,
        include_archived, include_forks, max_size_mb, keep_clones, resume, limit,
        db_url=_resolve_db_url(db_url),
    )
```

In the `report` command, add the same option and use it to open the store:

```python
@app.command()
def report(
    output_dir: Path = typer.Option(Path("output"), help="Where state and CSVs live."),
    db_url: str = typer.Option(None, help="MySQL URL; defaults to SECSCAN_DB_URL or local SQLite."),
) -> None:
    """Rebuild summary.csv from the state database."""
    from .findings import write_summary_csv
    from .state import StateStore

    target = _resolve_db_url(db_url) or (output_dir / "secscan.sqlite3")
    store = StateStore(target)
    rows = store.all_records()
    out = write_summary_csv(output_dir / "summary.csv", rows)
    typer.echo(f"Wrote {out} ({len(rows)} repos)")
```

- [ ] **Step 5: Run config tests and the full suite**

Run: `uv run pytest tests/test_config.py tests/test_state.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/secscan/config.py src/secscan/cli.py tests/test_config.py
git commit -m "feat(config): --db-url / SECSCAN_DB_URL backend selection"
```

---

### Task 4: Orchestrator wiring (persist findings to the DB)

Open the store from `cfg.state_target` and write findings to the DB alongside the CSV in the per-repo path.

**Files:**
- Modify: `src/secscan/orchestrator.py:71-72` (findings write) and `src/secscan/orchestrator.py:101` (store open)
- Test: `tests/test_state.py` already covers `replace_findings`; verify the suite stays green. No orchestrator unit test exists today and the change is a single call plus the target swap.

**Interfaces:**
- Consumes: `StateStore.replace_findings`, `RunConfig.state_target`.
- Produces: no new public surface.

- [ ] **Step 1: Open the store from `state_target`**

In `src/secscan/orchestrator.py`, in `run_scan`, change:

```python
    store = StateStore(cfg.state_db)
```

to:

```python
    store = StateStore(cfg.state_target)
```

- [ ] **Step 2: Persist findings to the DB alongside the CSV**

In `_process_repo`, after the existing CSV write:

```python
            csv_path = cfg.output_dir / f"{owner}__{name}" / "findings.csv"
            write_findings_csv(csv_path, repo.full_name, res.high_critical)
```

add:

```python
            store.replace_findings(owner, name, res.high_critical)
```

- [ ] **Step 3: Verify the change compiles and the suite passes**

Run: `uv run python -c "import secscan.orchestrator"` then `uv run pytest -q`
Expected: import succeeds; all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/secscan/orchestrator.py
git commit -m "feat(orchestrator): persist findings to the state backend"
```

---

### Task 5: Dependency, docs, and optional MySQL integration test

Add the `mysqlclient` dependency, document `SECSCAN_DB_URL`, and add a MySQL round-trip test gated behind an env var so CI without a MySQL server stays green.

**Files:**
- Modify: `pyproject.toml:7-13` (dependencies)
- Modify: `README.md` (Configuration + Prerequisites)
- Test: `tests/test_state_mysql.py` (new, skipped unless `SECSCAN_TEST_MYSQL_URL` is set)

**Interfaces:**
- Consumes: `StateStore`, `Finding`.
- Produces: nothing importable beyond the test.

- [ ] **Step 1: Add the dependency**

In `pyproject.toml`, add to `dependencies`:

```toml
    "mysqlclient>=2.2",
```

- [ ] **Step 2: Sync and confirm the driver imports**

Run: `uv sync` then `uv run python -c "import MySQLdb; print(MySQLdb.__name__)"`
Expected: prints `MySQLdb`. (If the build fails, install system libs: macOS `brew install mysql-client` and ensure `mysql_config` is on `PATH`; Debian/Ubuntu `apt-get install default-libmysqlclient-dev pkg-config`.)

- [ ] **Step 3: Write the gated integration test**

Create `tests/test_state_mysql.py`:

```python
import os

import pytest

from secscan.findings import Finding
from secscan.state import StateStore, Status

MYSQL_URL = os.environ.get("SECSCAN_TEST_MYSQL_URL")

pytestmark = pytest.mark.skipif(
    not MYSQL_URL, reason="set SECSCAN_TEST_MYSQL_URL to run MySQL integration tests"
)


@pytest.fixture
def store():
    s = StateStore(MYSQL_URL)
    # clean slate for a deterministic test
    cur = s._conn.cursor()
    cur.execute("DELETE FROM findings")
    cur.execute("DELETE FROM repos")
    s._conn.commit()
    yield s
    s.close()


def test_mysql_state_round_trip(store):
    store.upsert_pending("octo", "repo")
    store.record_result(
        "octo", "repo",
        critical=1, high=2, total=3,
        duration_s=4.5, cost_usd=0.25, reviewed_at="2026-06-30T00:00:00Z",
    )
    rec = store.get("octo", "repo")
    assert rec.status == Status.DONE
    assert rec.critical_count == 1
    assert rec.cost_usd == 0.25


def test_mysql_findings_replace(store):
    f = Finding(severity="critical", title="sqli", description="d")
    store.replace_findings("octo", "repo", [f])
    store.replace_findings("octo", "repo", [f, Finding(severity="high", title="xss", description="d")])
    rows = store.get_findings("octo", "repo")
    assert {r["title"] for r in rows} == {"sqli", "xss"}
```

- [ ] **Step 4: Verify the test is collected and skipped without a server**

Run: `uv run pytest tests/test_state_mysql.py -v`
Expected: 2 tests SKIPPED (reason: `set SECSCAN_TEST_MYSQL_URL …`).

- [ ] **Step 5: Update the README**

In `README.md` Prerequisites, add a bullet:

```markdown
- (Optional) MySQL: to store state and findings in MySQL instead of the local SQLite
  file, install the `mysqlclient` system libs (macOS `brew install mysql-client`;
  Debian/Ubuntu `apt-get install default-libmysqlclient-dev pkg-config`).
```

In the Configuration table, add a row:

```markdown
| `SECSCAN_DB_URL` | MySQL URL (`mysql://user:pass@host:3306/secscan`) for state + findings. Unset = local SQLite file. |
```

And under Usage, add:

```markdown
uv run secscan run --db-url mysql://user:pass@host:3306/secscan   # state + findings in MySQL
```

- [ ] **Step 6: Run the full suite**

Run: `uv run pytest -q`
Expected: all tests pass (MySQL tests skipped unless `SECSCAN_TEST_MYSQL_URL` is set).

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml uv.lock README.md tests/test_state_mysql.py
git commit -m "feat: mysqlclient dependency, docs, and gated MySQL integration test"
```

---

## Self-Review Notes

- **Spec coverage:** dialect abstraction (Task 1), findings table + replace (Task 2), config/CLI selection incl. `report` (Task 3), orchestrator dual-write (Task 4), dependency + docs + gated integration test (Task 5). Default-behavior-unchanged is enforced by Task 1 keeping existing tests green and `state_target` falling back to `state_db`.
- **Dual-write:** CSV writes in `orchestrator.py` and `findings.py` are untouched; Task 4 only *adds* the DB write.
- **mysqlclient local import:** `MySQLdb` is imported inside `_connect_mysql` only, so SQLite-only runs and tests never import the C extension.
- **Type consistency:** `replace_findings` / `get_findings` / `state_target` / `_resolve_db_url` / `_dialect_for` names are used identically across tasks.
