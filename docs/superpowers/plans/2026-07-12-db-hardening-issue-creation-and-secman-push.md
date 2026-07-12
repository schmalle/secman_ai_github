# DB Hardening, GitHub Issue Creation, and secman Push Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make secscan's DB storage optional and MySQL-credential-flexible (Part A), let it open a GitHub issue per High/Critical finding with dedup and dry-run (Part B), and let it push High/Critical findings into secman via `cli-add` (Part C).

**Architecture:** Part A extends `state.py`'s existing SQLite/MySQL dialect abstraction (adds credential/SSL params to `_connect_mysql`, an `issue_tracking` table, and an opt-out `--no-db` path in the orchestrator). Part B adds a thin `issues.py` module (mirroring `emailer.py`'s style) that PyGithub-creates issues, deduped via the new `issue_tracking` table keyed by a stable content fingerprint. Part C adds `secman_client.py` (same thin-module style) that logs into secman (extracting the JWT from a `Set-Cookie` header, mirroring secman's own CLI) and pushes findings via `cli-add`, reusing Part B's fingerprint.

**Tech Stack:** Python 3.10+, Typer, PyGithub, `requests` (new), `tenacity`, raw DB-API (`sqlite3`/`mysqlclient`), pytest + `typer.testing.CliRunner` + hand-rolled fakes (no mocking framework — matches `FakeSMTP` in `test_emailer.py`).

## Global Constraints

- Default behavior with no new flags is unchanged (existing tests must keep passing throughout).
- `MySQLdb` is **not installed** in this dev environment (`uv run python -c "import MySQLdb"` fails — no system `mysql_config`). Any new MySQL-connection-argument logic MUST be unit-testable **without importing `MySQLdb`** — extract a pure `_mysql_connect_kwargs(...)` function and test that directly. `import MySQLdb` stays function-local inside `_connect_mysql` (existing constraint, do not change).
- `--db-ssl` is a plain encrypt-or-not toggle (`ssl={"ssl_mode": "REQUIRED"}`) — no CA/cert/key options, ever.
- `--db-user`/`--db-password` resolution order: CLI flag → `DB_USERNAME`/`DB_PASSWORD` env var → credentials embedded in `--db-url` → driver default (`""`).
- `--no-db` and `--create-issues` together MUST raise `ConfigError` before any repo is processed.
- Fingerprint formula (exact, used by both Part B and Part C): `hashlib.sha256(f"{finding.severity.value}|{finding.category}|{finding.title}|{finding.file_path}".encode()).hexdigest()`.
- GitHub issue title (exact): `f"[secscan] {finding.severity.value}: {finding.title} ({finding.file_path})"`. Label: `"secscan"`.
- secman `cve` value (exact): `f"SECSCAN:{finding_category_or_default}:{fingerprint[:12]}"` where `finding_category_or_default = row["category"] or "FINDING"`.
- secman push criticality: only `"critical"`/`"high"` severities are pushed, sent as `"CRITICAL"`/`"HIGH"` (uppercased).
- New dependency `requests` (Part C only) — added to `pyproject.toml` `dependencies`, not an optional extra (unlike `mysqlclient`, which stays optional since not everyone uses MySQL — but everyone who wants secman push needs `requests`, and it has no problematic system-library build step, so it's a plain dependency).
- Secrets (`--db-password`, `--secman-password`, etc.) are read from CLI flag or environment only, never logged, never written to disk — matching the existing `_env()` convention in `config.py`.
- Every new/changed CLI option needs a corresponding README update in the *same task* that adds it (no separate "docs" task at the end).

---

## Part A — DB backend hardening

### Task 1: MySQL credentials + SSL in `state.py`

Add a pure, MySQLdb-import-free `_mysql_connect_kwargs()` builder and thread `db_user`/`db_password`/`db_ssl` through `_connect_mysql` and `StateStore.__init__`.

**Files:**
- Modify: `src/secscan/state.py:173-206`
- Test: `tests/test_state.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `_mysql_connect_kwargs(url: str, *, user: str | None = None, password: str | None = None, ssl: bool = False) -> dict` — pure function, no `MySQLdb` import, returns kwargs for `MySQLdb.connect(**kwargs)` (excluding `cursorclass`, which stays in `_connect_mysql`).
  - `_connect_mysql(url: str, *, user: str | None = None, password: str | None = None, ssl: bool = False)` — now takes 3 new keyword-only params, still local-imports `MySQLdb`.
  - `StateStore.__init__(self, target: str | Path, *, db_user: str | None = None, db_password: str | None = None, db_ssl: bool = False)` — 3 new keyword-only params, passed through to `_connect_mysql` when `target` is a MySQL URL; ignored for SQLite targets.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_state.py` (new imports at top: add `_mysql_connect_kwargs` to the existing `from secscan.state import ...` line):

```python
from secscan.state import (
    RepoRecord, StateStore, Status, _dialect_for, _mysql_connect_kwargs,
    _MYSQL_DIALECT, _SQLITE_DIALECT,
)


def test_mysql_connect_kwargs_from_url_only():
    kw = _mysql_connect_kwargs("mysql://bob:secret@dbhost:3307/secscan")
    assert kw == {
        "host": "dbhost", "port": 3307, "user": "bob", "passwd": "secret",
        "db": "secscan", "charset": "utf8mb4",
    }


def test_mysql_connect_kwargs_explicit_user_password_win_over_url():
    kw = _mysql_connect_kwargs(
        "mysql://urluser:urlpass@dbhost:3306/secscan",
        user="flaguser", password="flagpass",
    )
    assert kw["user"] == "flaguser"
    assert kw["passwd"] == "flagpass"


def test_mysql_connect_kwargs_falls_back_to_url_when_none_given():
    kw = _mysql_connect_kwargs("mysql://urluser:urlpass@dbhost:3306/secscan")
    assert kw["user"] == "urluser"
    assert kw["passwd"] == "urlpass"


def test_mysql_connect_kwargs_no_ssl_by_default():
    kw = _mysql_connect_kwargs("mysql://u:p@h:3306/db")
    assert "ssl" not in kw


def test_mysql_connect_kwargs_ssl_true_adds_ssl_mode_required():
    kw = _mysql_connect_kwargs("mysql://u:p@h:3306/db", ssl=True)
    assert kw["ssl"] == {"ssl_mode": "REQUIRED"}


def test_store_init_accepts_mysql_credential_kwargs_for_sqlite_target_noop(tmp_path):
    # SQLite targets must silently ignore db_user/db_password/db_ssl (no crash).
    store = StateStore(tmp_path / "s.sqlite3", db_user="ignored", db_password="ignored", db_ssl=True)
    store.upsert_pending("octo", "repo")
    assert store.get("octo", "repo") is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_state.py::test_mysql_connect_kwargs_from_url_only -v`
Expected: FAIL with `ImportError: cannot import name '_mysql_connect_kwargs'`.

- [ ] **Step 3: Implement `_mysql_connect_kwargs` and thread it through**

In `src/secscan/state.py`, replace the current `_connect_mysql` function (lines 173-193):

```python
def _connect_mysql(url: str):
    try:
        import MySQLdb
        from MySQLdb.cursors import DictCursor
    except ImportError as exc:
        from .config import ConfigError

        raise ConfigError(
            "MySQL/MariaDB backend requires the 'mysql' extra: uv sync --extra mysql"
        ) from exc

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
```

with:

```python
def _mysql_connect_kwargs(
    url: str, *, user: str | None = None, password: str | None = None, ssl: bool = False
) -> dict:
    """Pure connection-argument builder — no MySQLdb import, so it's testable
    without the C extension installed."""
    p = urllib.parse.urlparse(url)
    kwargs: dict = {
        "host": p.hostname or "localhost",
        "port": p.port or 3306,
        "user": user or urllib.parse.unquote(p.username or ""),
        "passwd": password or urllib.parse.unquote(p.password or ""),
        "db": p.path.lstrip("/"),
        "charset": "utf8mb4",
    }
    if ssl:
        # Plain encrypt-or-not toggle: verifies against the system default CA
        # trust store. No custom CA/cert/key support by design.
        kwargs["ssl"] = {"ssl_mode": "REQUIRED"}
    return kwargs


def _connect_mysql(
    url: str, *, user: str | None = None, password: str | None = None, ssl: bool = False
):
    try:
        import MySQLdb
        from MySQLdb.cursors import DictCursor
    except ImportError as exc:
        from .config import ConfigError

        raise ConfigError(
            "MySQL/MariaDB backend requires the 'mysql' extra: uv sync --extra mysql"
        ) from exc

    kwargs = _mysql_connect_kwargs(url, user=user, password=password, ssl=ssl)
    return MySQLdb.connect(cursorclass=DictCursor, **kwargs)
```

Then replace `StateStore.__init__` (lines 197-206):

```python
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
```

with:

```python
class StateStore:
    def __init__(
        self,
        target: str | Path,
        *,
        db_user: str | None = None,
        db_password: str | None = None,
        db_ssl: bool = False,
    ):
        self._d = _dialect_for(target)
        if _is_mysql(target):
            self._conn = _connect_mysql(str(target), user=db_user, password=db_password, ssl=db_ssl)
        else:
            self._conn = _connect_sqlite(Path(target))
        cur = self._conn.cursor()
        for stmt in self._d.schema:
            cur.execute(stmt)
        self._conn.commit()
```

- [ ] **Step 4: Run the state tests to verify they pass**

Run: `uv run pytest tests/test_state.py -v`
Expected: PASS — all pre-existing tests plus the 6 new ones.

- [ ] **Step 5: Commit**

```bash
git add src/secscan/state.py tests/test_state.py
git commit -m "feat(state): MySQL credentials via param + SSL toggle, no-MySQLdb-import-required kwargs builder"
```

---

### Task 2: CLI wiring for `--db-user`/`--db-password`/`--db-ssl`

Add the 3 new flags (+ `DB_USERNAME`/`DB_PASSWORD`/`DB_SSL` env vars) to `run`, `scan`, `report`, `send-report`, threaded through `RunConfig`/`_open_store`/`_run_config`.

**Files:**
- Modify: `src/secscan/config.py:68-93` (`RunConfig`)
- Modify: `src/secscan/cli.py` (helpers, `_run_config`, `_open_store`, and the 4 commands' option lists + `StateStore(...)`/`_open_store(...)` call sites)
- Modify: `README.md` (Configuration table)
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `StateStore.__init__`'s new `db_user`/`db_password`/`db_ssl` kwargs (Task 1).
- Produces:
  - `RunConfig.db_user: str | None = None`, `RunConfig.db_password: str | None = None`, `RunConfig.db_ssl: bool = False`.
  - `cli._resolve_db_user(db_user: str | None) -> str | None` and `cli._resolve_db_password(db_password: str | None) -> str | None` — flag → env (`DB_USERNAME`/`DB_PASSWORD`) → `None`.
  - `cli._resolve_db_ssl(db_ssl: bool) -> bool` — flag (if `True`) → `DB_SSL` env truthy (`"true"`/`"1"`, case-insensitive) → `False`.
  - `cli._open_store(output_dir, db_url, db_user=None, db_password=None, db_ssl=False)` — now passes credentials through to `StateStore`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_config.py`:

```python
from secscan.cli import _resolve_db_password, _resolve_db_ssl, _resolve_db_user


def test_db_user_password_ssl_default_none_false():
    cfg = RunConfig()
    assert cfg.db_user is None
    assert cfg.db_password is None
    assert cfg.db_ssl is False


def test_resolve_db_user_flag_wins(monkeypatch):
    monkeypatch.setenv("DB_USERNAME", "envuser")
    assert _resolve_db_user("flaguser") == "flaguser"


def test_resolve_db_user_env_fallback(monkeypatch):
    monkeypatch.setenv("DB_USERNAME", "envuser")
    assert _resolve_db_user(None) == "envuser"


def test_resolve_db_user_none_when_unset(monkeypatch):
    monkeypatch.delenv("DB_USERNAME", raising=False)
    assert _resolve_db_user(None) is None


def test_resolve_db_password_flag_wins(monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "envpass")
    assert _resolve_db_password("flagpass") == "flagpass"


def test_resolve_db_password_env_fallback(monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "envpass")
    assert _resolve_db_password(None) == "envpass"


def test_resolve_db_ssl_flag_true_wins(monkeypatch):
    monkeypatch.delenv("DB_SSL", raising=False)
    assert _resolve_db_ssl(True) is True


def test_resolve_db_ssl_env_true_when_flag_false(monkeypatch):
    monkeypatch.setenv("DB_SSL", "true")
    assert _resolve_db_ssl(False) is True


def test_resolve_db_ssl_false_when_neither_set(monkeypatch):
    monkeypatch.delenv("DB_SSL", raising=False)
    assert _resolve_db_ssl(False) is False
```

(`RunConfig` is already imported at the top of `tests/test_config.py` from the MySQL-support plan's Task 3 — no new import needed for it.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_config.py::test_db_user_password_ssl_default_none_false -v`
Expected: FAIL with `TypeError: RunConfig.__init__() got an unexpected keyword argument` (or `AttributeError` on `cfg.db_user`).

- [ ] **Step 3: Add the 3 fields to `RunConfig`**

In `src/secscan/config.py`, in the `RunConfig` dataclass, change:

```python
    db_url: str | None = None  # mysql://… selects MySQL/MariaDB; None uses state_db (SQLite)
    filters: Filters = field(default_factory=Filters)
```

to:

```python
    db_url: str | None = None  # mysql://… selects MySQL/MariaDB; None uses state_db (SQLite)
    db_user: str | None = None  # overrides any user embedded in db_url
    db_password: str | None = None  # overrides any password embedded in db_url
    db_ssl: bool = False  # encrypt the MySQL connection (no custom CA/cert/key)
    filters: Filters = field(default_factory=Filters)
```

- [ ] **Step 4: Add the resolve helpers and thread credentials through `cli.py`**

In `src/secscan/cli.py`, add after `_resolve_db_url`:

```python
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
```

Replace `_open_store`:

```python
def _open_store(output_dir: Path, db_url: str | None):
    from .state import StateStore

    return StateStore(_resolve_db_url(db_url) or (output_dir / "secscan.sqlite3"))
```

with:

```python
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
```

Add `db_user`, `db_password`, `db_ssl` parameters to `_run_config` (after the existing `db_url` param) and pass them into `RunConfig(...)`:

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
    db_user: str | None = None,
    db_password: str | None = None,
    db_ssl: bool = False,
    provider: str = "auto",
    timeout_s: float = 900.0,
) -> RunConfig:
    return RunConfig(
        output_dir=output_dir,
        state_db=output_dir / "secscan.sqlite3",
        db_url=db_url,
        db_user=db_user,
        db_password=db_password,
        db_ssl=db_ssl,
        filters=Filters(
            include_archived=include_archived,
            include_forks=include_forks,
            max_size_mb=max_size_mb,
        ),
        concurrency=concurrency,
        model=model,
        provider=provider,
        max_turns=max_turns,
        max_cost_usd=max_cost_usd,
        timeout_s=timeout_s,
        keep_clones=keep_clones,
        resume=resume,
        limit=limit,
    )
```

In the `run` command, add 3 options after the existing `db_url` option (line 103):

```python
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env). Overrides any user embedded in --db-url."),
    db_password: str = typer.Option(None, help="MySQL/MariaDB password (or DB_PASSWORD env). Overrides any password embedded in --db-url."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env). No custom CA/cert/key."),
```

and update its `_run_config(...)` call to pass them through:

```python
    cfg = _run_config(
        output_dir, concurrency, model, max_turns, max_cost_usd,
        include_archived, include_forks, max_size_mb, keep_clones, resume, limit,
        db_url=_resolve_db_url(db_url), db_user=db_user, db_password=db_password, db_ssl=db_ssl,
        provider=provider, timeout_s=timeout,
    )
```

In the `scan` command, add the same 3 options after its existing `db_url` option (line 198) and update its `_run_config(...)` call the same way (add `db_user=db_user, db_password=db_password, db_ssl=db_ssl,` alongside the existing `db_url=_resolve_db_url(db_url)`).

In the `report` command, add the same 3 options after its `db_url` option (line 233), and change its body from:

```python
    store = _open_store(output_dir, db_url)
```

to:

```python
    store = _open_store(output_dir, db_url, db_user, db_password, db_ssl)
```

In the `send-report` command, add the same 3 options after its `db_url` option (line 253), and change its body from:

```python
    store = _open_store(output_dir, db_url)
```

to:

```python
    store = _open_store(output_dir, db_url, db_user, db_password, db_ssl)
```

(`repo add`/`repo list`/`repo remove` are intentionally left untouched — they use `_open_store` but the spec scopes the new flags to `run`/`scan`/`report`/`send-report` only.)

- [ ] **Step 5: Run the config tests and the full suite**

Run: `uv run pytest tests/test_config.py tests/test_state.py tests/test_cli_scan.py tests/test_cli_send_report.py -v`
Expected: PASS.

- [ ] **Step 6: Update the README Configuration table**

In `README.md`, in the Configuration table, add 2 rows after the `SECSCAN_DB_URL` row:

```markdown
| `DB_USERNAME` | MySQL/MariaDB username (or `--db-user`); overrides any user embedded in `SECSCAN_DB_URL` |
| `DB_PASSWORD` | MySQL/MariaDB password (or `--db-password`); overrides any password embedded in `SECSCAN_DB_URL` |
```

Add to the "Common flags" line, after `--db-url`:

```markdown
--db-user --db-password --db-ssl
```

- [ ] **Step 7: Commit**

```bash
git add src/secscan/config.py src/secscan/cli.py README.md tests/test_config.py
git commit -m "feat(cli): --db-user/--db-password/--db-ssl flags with env fallback"
```

---

### Task 3: `--no-db` flag

Skip DB storage entirely on `run`/`scan`/`review` when set; skip `summary.csv` (with a notice) since it's rebuilt from the store.

**Files:**
- Modify: `src/secscan/config.py` (`RunConfig`)
- Modify: `src/secscan/cli.py` (`run`, `scan`, `review` commands)
- Modify: `src/secscan/orchestrator.py:94-198,228-241` (`_process_repo`, `run_scan`, `scan_repo`)
- Modify: `README.md`
- Test: `tests/test_orchestrator.py`, `tests/test_config.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `RunConfig.no_db: bool = False`.
  - `orchestrator._process_repo(..., cfg, ...)` — when `cfg.no_db` is `True`, receives `store=None` and skips every `store.*` call.
  - `orchestrator.run_scan`/`scan_repo` — open `store = None if cfg.no_db else StateStore(cfg.state_target, db_user=cfg.db_user, db_password=cfg.db_password, db_ssl=cfg.db_ssl)`; skip the final `write_summary_csv(...)` call (print a notice instead) when `store is None`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_orchestrator.py`:

```python
async def test_process_repo_skips_store_when_no_db(tmp_path, monkeypatch):
    from secscan.reviewer import ReviewResult

    async def fake_mint_token(auth, repo):
        return "tok"

    async def fake_clone(repo, token, root):
        return tmp_path / "clone"

    async def fake_review_repo(path, full_name, *, model, max_turns, max_cost_usd, extra_env, idle_timeout_s):
        return ReviewResult(repo_full_name=full_name)

    monkeypatch.setattr(orch, "_mint_token", fake_mint_token)
    monkeypatch.setattr(orch, "_clone", fake_clone)
    monkeypatch.setattr(orch, "review_repo", fake_review_repo)
    monkeypatch.setattr(orch, "cleanup", lambda path: None)

    cfg = RunConfig(output_dir=tmp_path, no_db=True)
    sem = asyncio.Semaphore(1)
    provider_env = orch.ProviderEnv(name="anthropic")

    # store=None must not raise — this is the core assertion.
    await orch._process_repo(_repo(name="demo"), object(), None, cfg, sem, provider_env)

    assert (tmp_path / "octo__demo" / "findings.csv").exists()


async def test_run_scan_no_db_skips_summary_csv(tmp_path, monkeypatch, capsys):
    fake_app = _FakeApp()
    monkeypatch.setattr(orch, "build_auth", lambda: _FakeAuth(app=fake_app))

    async def fake_process_repo(repo, auth, store, cfg, sem, provider_env):
        pass

    monkeypatch.setattr(orch, "_process_repo", fake_process_repo)

    cfg = RunConfig(output_dir=tmp_path, no_db=True)
    await orch.run_scan(cfg, targets_only=True)

    assert not (tmp_path / "summary.csv").exists()
    assert "summary.csv skipped" in capsys.readouterr().out
```

Add to `tests/test_config.py`:

```python
def test_no_db_defaults_false():
    assert RunConfig().no_db is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_orchestrator.py::test_process_repo_skips_store_when_no_db -v`
Expected: FAIL — `RunConfig(...)` raises `TypeError: unexpected keyword argument 'no_db'`.

- [ ] **Step 3: Add `no_db` to `RunConfig`**

In `src/secscan/config.py`, in `RunConfig`, add after the `db_ssl` field added in Task 2:

```python
    db_ssl: bool = False  # encrypt the MySQL connection (no custom CA/cert/key)
    no_db: bool = False  # skip all DB storage; findings.csv still written, summary.csv skipped
```

- [ ] **Step 4: Make `_process_repo` tolerate `store=None`**

In `src/secscan/orchestrator.py`, in `_process_repo`, change every `store.` call to be guarded. Replace:

```python
        try:
            token = await _mint_token(auth, repo)
            store.mark(owner, name, Status.CLONED)
            path = await _clone(repo, token, _clone_root(cfg))

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
            store.replace_findings(owner, name, res.high_critical)

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
```

with:

```python
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
```

- [ ] **Step 5: Open `store=None` and skip `summary.csv` in `run_scan`**

In `src/secscan/orchestrator.py`, in `run_scan`, change:

```python
    auth = build_auth()
    store = StateStore(cfg.state_target)
    provider_env = _resolve_provider_env(cfg)
```

to:

```python
    auth = build_auth()
    store = None if cfg.no_db else StateStore(
        cfg.state_target, db_user=cfg.db_user, db_password=cfg.db_password, db_ssl=cfg.db_ssl
    )
    provider_env = _resolve_provider_env(cfg)
```

`run_scan` also calls `store.list_targets()`, `store.upsert_pending(...)`, `store.is_done(...)`, and `store.all_records()` outside `_process_repo` — these need `store is not None` guards too. Change:

```python
    repos, unresolved = _merge_scope(repos, _load_allowlist(repos_file), store.list_targets())
    for owner, name in unresolved:
        repos.append(await asyncio.to_thread(resolve_target, owner, name, auth))

    # Register all, then decide which to actually review (resume skips done).
    todo: list[RepoInfo] = []
    for repo in repos:
        store.upsert_pending(repo.owner, repo.name)
        if cfg.resume and store.is_done(repo.owner, repo.name):
            continue
        todo.append(repo)
```

to:

```python
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
```

(With `--no-db`, `--resume` has no effect — there's no state to resume from. This is expected: resume requires the DB.)

Finally, change the end of `run_scan`:

```python
    sem = asyncio.Semaphore(cfg.concurrency)
    await asyncio.gather(*(_process_repo(r, auth, store, cfg, sem, provider_env) for r in todo))

    summary = write_summary_csv(cfg.output_dir / "summary.csv", store.all_records())
    records = store.all_records()
    total_cost = sum(r.cost_usd for r in records)
    failed = [r for r in records if r.status == Status.FAILED]
    typer.echo(
        f"Done. summary={summary} | total review cost ${total_cost:.3f} | "
        f"{len(failed)} failed."
    )
```

to:

```python
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
```

- [ ] **Step 6: Same treatment for `scan_repo`**

In `src/secscan/orchestrator.py`, change `scan_repo`:

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

to:

```python
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
```

- [ ] **Step 7: Add `--no-db` to the `run`, `scan`, and `review` CLI commands**

In `src/secscan/cli.py`, add a `no_db` parameter to `_run_config` (after `db_ssl`) and pass it into `RunConfig(...)`:

```python
    db_ssl: bool = False,
    no_db: bool = False,
    provider: str = "auto",
```

and in the `return RunConfig(...)` block:

```python
        db_ssl=db_ssl,
        no_db=no_db,
```

In the `run` command, add the option after `db_ssl` (added in Task 2):

```python
    no_db: bool = typer.Option(False, "--no-db", help="Skip all DB storage; findings.csv is still written, summary.csv is skipped. Cannot combine with --create-issues."),
```

and pass `no_db=no_db` in its `_run_config(...)` call.

In the `scan` command, add the same option and pass `no_db=no_db` the same way.

In the `review` command — it has no `db_url`/DB flags at all today (it's already CSV-only, no state store — see `orchestrator.review_local`, which never touches a `StateStore`). **No change needed for `review`** — it's already equivalent to always-`--no-db` behavior. (This corrects an assumption in the original design discussion; `review_local` never opens a store, so `--no-db` would be a no-op flag there. Leaving it off `review`'s option list, matching how `--create-issues` is also `run`/`scan`-only in Part B.)

- [ ] **Step 8: Run the full suite**

Run: `uv run pytest -q`
Expected: all tests pass.

- [ ] **Step 9: Update the README**

In `README.md`, add to the "Common flags" line:

```markdown
--no-db
```

Add a new paragraph after the "Common flags" paragraph:

```markdown
`--no-db` skips all DB storage (state, findings, targets) for `run`/`scan` — only
per-repo `findings.csv` is written; `summary.csv` is skipped since it's normally
rebuilt from the state store. Useful for one-off scans where you don't want
`output/secscan.sqlite3` (or a configured MySQL backend) touched at all.
```

- [ ] **Step 10: Commit**

```bash
git add src/secscan/config.py src/secscan/cli.py src/secscan/orchestrator.py README.md tests/test_orchestrator.py tests/test_config.py
git commit -m "feat(cli): --no-db skips DB storage for run/scan"
```

---

### Task 4: `scripts/setup-mysql.sh`

New database-provisioning script + README section.

**Files:**
- Create: `scripts/setup-mysql.sh`
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing (standalone shell script).
- Produces: a `scripts/setup-mysql.sh` executable that provisions a MySQL/MariaDB DB+user and prints a ready-to-export config block.

- [ ] **Step 1: Write the script**

Create `scripts/setup-mysql.sh`:

```bash
#!/usr/bin/env bash
# Provisions a MySQL/MariaDB database + application user for secscan.
# Prompts for the admin password and the new app-user password (hidden input) —
# never accepts either as a flag, to avoid shell-history/`ps` leakage.
set -euo pipefail

HOST=""
PORT=3306
DB_NAME=""
APP_USER=""
ADMIN_USER=""
USE_SSL=false

usage() {
    echo "Usage: $0 --host <host> [--port 3306] --db-name <name> --app-user <user> --admin-user <user> [--ssl]" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --db-name) DB_NAME="$2"; shift 2 ;;
        --app-user) APP_USER="$2"; shift 2 ;;
        --admin-user) ADMIN_USER="$2"; shift 2 ;;
        --ssl) USE_SSL=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

if [[ -z "$HOST" || -z "$DB_NAME" || -z "$APP_USER" || -z "$ADMIN_USER" ]]; then
    usage
fi

if ! command -v mysql >/dev/null 2>&1; then
    echo "Error: the 'mysql' CLI client is not on PATH." >&2
    exit 1
fi

read -rs -p "Admin password for '$ADMIN_USER'@'$HOST': " ADMIN_PASSWORD
echo
read -rs -p "New password for app user '$APP_USER': " APP_PASSWORD
echo
read -rs -p "Confirm app user password: " APP_PASSWORD_CONFIRM
echo

if [[ "$APP_PASSWORD" != "$APP_PASSWORD_CONFIRM" ]]; then
    echo "Error: app user passwords did not match." >&2
    exit 1
fi

mysql --host="$HOST" --port="$PORT" --user="$ADMIN_USER" --password="$ADMIN_PASSWORD" <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS '$APP_USER'@'%' IDENTIFIED BY '$APP_PASSWORD';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$APP_USER'@'%';
FLUSH PRIVILEGES;
SQL

echo
echo "Database '$DB_NAME' and user '$APP_USER' are ready. Export:"
echo
echo "  export SECSCAN_DB_URL=mysql://$HOST:$PORT/$DB_NAME"
echo "  export DB_USERNAME=$APP_USER"
echo "  export DB_PASSWORD=$APP_PASSWORD"
if [[ "$USE_SSL" == true ]]; then
    echo "  export DB_SSL=true"
fi
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x scripts/setup-mysql.sh`
Expected: no output; `ls -l scripts/setup-mysql.sh` shows the `x` bit set.

- [ ] **Step 3: Verify the flag parsing / usage path (no real server needed)**

Run: `./scripts/setup-mysql.sh --host localhost --db-name secscan`
Expected: exits 2, prints the `Usage:` line to stderr (missing `--app-user`/`--admin-user`).

Run: `MYSQL_MISSING_PATH_TEST=1 PATH=/usr/bin ./scripts/setup-mysql.sh --host h --db-name d --app-user a --admin-user r 2>&1 | grep -q "not on PATH" && echo OK || echo "(skip: mysql client is on PATH in this env, cannot exercise the missing-client branch statically)"`
Expected: either `OK`, or the skip message — both are acceptable; this step is a manual sanity check, not a pytest-collected test (the script has no server to run the full happy path against in this environment).

- [ ] **Step 4: Add the README section**

In `README.md`, add a new section after "MySQL / MariaDB backend":

```markdown
## MySQL setup script

`scripts/setup-mysql.sh` provisions a database and application user on a MySQL/
MariaDB server you already have admin access to (for local ephemeral testing,
use the `docker run mariadb` one-liner above instead — this script is for a
real, persistent server).

Prerequisites: the `mysql` CLI client on `PATH`, network access to the target
server, and admin credentials for it.

```bash
./scripts/setup-mysql.sh --host db.internal --db-name secscan \
    --app-user secscan --admin-user root [--port 3306] [--ssl]
```

You'll be prompted (hidden input) for the admin password and a new password for
the app user — neither is ever accepted as a command-line flag. On success it
prints the config to export:

```
export SECSCAN_DB_URL=mysql://db.internal:3306/secscan
export DB_USERNAME=secscan
export DB_PASSWORD=<the password you entered>
export DB_SSL=true   # only if --ssl was passed
```
```

- [ ] **Step 5: Commit**

```bash
git add scripts/setup-mysql.sh README.md
git commit -m "feat: scripts/setup-mysql.sh database provisioning script"
```

---

## Part B — GitHub issue creation

### Task 5: `fingerprint()` in `findings.py`

Shared, stable content-hash function for a `Finding` — used by issue dedup (this part) and the secman `cve` value (Part C).

**Files:**
- Modify: `src/secscan/findings.py`
- Test: `tests/test_findings.py`

**Interfaces:**
- Consumes: `Finding` (existing).
- Produces: `fingerprint(finding: Finding) -> str` — `sha256(f"{severity}|{category}|{title}|{file_path}").hexdigest()`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_findings.py` (check the existing file first for its import style — add `fingerprint` to the `from secscan.findings import ...` line):

```python
def test_fingerprint_stable_across_line_range_changes():
    a = Finding(severity="high", title="SQLi", description="d", file_path="x.py", line_range="10-12", category="CWE-89")
    b = Finding(severity="high", title="SQLi", description="d", file_path="x.py", line_range="99-101", category="CWE-89")
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_differs_on_title():
    a = Finding(severity="high", title="SQLi", description="d", file_path="x.py")
    b = Finding(severity="high", title="XSS", description="d", file_path="x.py")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_differs_on_severity():
    a = Finding(severity="high", title="SQLi", description="d", file_path="x.py")
    b = Finding(severity="critical", title="SQLi", description="d", file_path="x.py")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_is_hex_sha256():
    f = Finding(severity="high", title="SQLi", description="d", file_path="x.py")
    fp = fingerprint(f)
    assert len(fp) == 64
    int(fp, 16)  # raises ValueError if not hex
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_findings.py::test_fingerprint_is_hex_sha256 -v`
Expected: FAIL with `ImportError: cannot import name 'fingerprint'`.

- [ ] **Step 3: Implement `fingerprint`**

In `src/secscan/findings.py`, add `import hashlib` to the imports (after `import dataclasses`):

```python
import dataclasses
import hashlib
import json
```

Add the function after `filter_high_critical`:

```python
def fingerprint(finding: Finding) -> str:
    """Stable content hash for a finding — excludes line_range/description so
    minor LLM rewording or line drift between reruns doesn't change the
    identity used for GitHub issue dedup (Part B) and the secman cve value
    (Part C)."""
    key = f"{finding.severity.value}|{finding.category}|{finding.title}|{finding.file_path}"
    return hashlib.sha256(key.encode()).hexdigest()
```

- [ ] **Step 4: Run the findings tests**

Run: `uv run pytest tests/test_findings.py -v`
Expected: PASS — all pre-existing tests plus the 4 new ones.

- [ ] **Step 5: Commit**

```bash
git add src/secscan/findings.py tests/test_findings.py
git commit -m "feat(findings): add stable fingerprint() for issue dedup and secman push"
```

---

### Task 6: `issue_tracking` table + `StateStore` methods

**Files:**
- Modify: `src/secscan/state.py`
- Test: `tests/test_state.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `IssueRecord` dataclass: `owner: str, repo: str, fingerprint: str, issue_number: int, issue_url: str, first_seen_at: str, last_seen_at: str`.
  - `StateStore.find_issue(owner: str, repo: str, fingerprint: str) -> IssueRecord | None`.
  - `StateStore.record_issue_created(owner: str, repo: str, fingerprint: str, issue_number: int, issue_url: str, seen_at: str) -> None`.
  - `StateStore.touch_issue_seen(owner: str, repo: str, fingerprint: str, seen_at: str) -> None`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_state.py` (add `IssueRecord` to the existing `from secscan.state import ...` line):

```python
def test_find_issue_returns_none_when_untracked(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    assert store.find_issue("octo", "repo", "deadbeef") is None


def test_record_issue_created_then_find_issue(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.record_issue_created(
        "octo", "repo", "deadbeef", 42, "https://github.com/octo/repo/issues/42",
        "2026-07-12T00:00:00+00:00",
    )
    rec = store.find_issue("octo", "repo", "deadbeef")
    assert rec is not None
    assert rec.issue_number == 42
    assert rec.issue_url == "https://github.com/octo/repo/issues/42"
    assert rec.first_seen_at == "2026-07-12T00:00:00+00:00"
    assert rec.last_seen_at == "2026-07-12T00:00:00+00:00"


def test_touch_issue_seen_updates_last_seen_only(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.record_issue_created(
        "octo", "repo", "deadbeef", 42, "https://github.com/octo/repo/issues/42",
        "2026-07-01T00:00:00+00:00",
    )
    store.touch_issue_seen("octo", "repo", "deadbeef", "2026-07-12T00:00:00+00:00")
    rec = store.find_issue("octo", "repo", "deadbeef")
    assert rec.first_seen_at == "2026-07-01T00:00:00+00:00"  # unchanged
    assert rec.last_seen_at == "2026-07-12T00:00:00+00:00"  # bumped


def test_issue_tracking_scoped_by_owner_repo_fingerprint(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.record_issue_created("octo", "one", "fp1", 1, "url1", "t1")
    store.record_issue_created("octo", "two", "fp1", 2, "url2", "t2")  # same fp, different repo
    assert store.find_issue("octo", "one", "fp1").issue_number == 1
    assert store.find_issue("octo", "two", "fp1").issue_number == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_state.py::test_find_issue_returns_none_when_untracked -v`
Expected: FAIL with `AttributeError: 'StateStore' object has no attribute 'find_issue'`.

- [ ] **Step 3: Add the DDL, dataclass, and methods**

In `src/secscan/state.py`, add the `IssueRecord` dataclass after `RepoRecord` (after its `full_name` property, before the `# -- schema` comment):

```python
@dataclass
class IssueRecord:
    owner: str
    repo: str
    fingerprint: str
    issue_number: int
    issue_url: str
    first_seen_at: str
    last_seen_at: str
```

Add the DDL constants after `_TARGETS_MYSQL`:

```python
_ISSUE_TRACKING_SQLITE = """
CREATE TABLE IF NOT EXISTS issue_tracking (
    owner         TEXT NOT NULL,
    repo          TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    issue_number  INTEGER NOT NULL,
    issue_url     TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    PRIMARY KEY (owner, repo, fingerprint)
);
"""

_ISSUE_TRACKING_MYSQL = """
CREATE TABLE IF NOT EXISTS issue_tracking (
    owner         VARCHAR(255) NOT NULL,
    repo          VARCHAR(255) NOT NULL,
    fingerprint   VARCHAR(64) NOT NULL,
    issue_number  INTEGER NOT NULL,
    issue_url     TEXT NOT NULL,
    first_seen_at VARCHAR(64) NOT NULL,
    last_seen_at  VARCHAR(64) NOT NULL,
    PRIMARY KEY (owner, repo, fingerprint)
);
"""
```

Update both dialect `schema` tuples:

```python
_SQLITE_DIALECT = _Dialect(
    placeholder="?",
    insert_ignore="INSERT OR IGNORE INTO",
    schema=(_REPOS_SQLITE, _FINDINGS_SQLITE, _TARGETS_SQLITE, _ISSUE_TRACKING_SQLITE),
)

_MYSQL_DIALECT = _Dialect(
    placeholder="%s",
    insert_ignore="INSERT IGNORE INTO",
    schema=(_REPOS_MYSQL, _FINDINGS_MYSQL, _TARGETS_MYSQL, _ISSUE_TRACKING_MYSQL),
)
```

Add the 3 methods to `StateStore`, after `get_findings` and before the `# -- scan targets` comment:

```python
    # -- GitHub issue dedup -------------------------------------------------------

    def find_issue(self, owner: str, repo: str, fingerprint: str) -> "IssueRecord | None":
        cur = self._exec(
            "SELECT * FROM issue_tracking WHERE owner = ? AND repo = ? AND fingerprint = ?",
            (owner, repo, fingerprint),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return IssueRecord(
            owner=row["owner"], repo=row["repo"], fingerprint=row["fingerprint"],
            issue_number=row["issue_number"], issue_url=row["issue_url"],
            first_seen_at=row["first_seen_at"], last_seen_at=row["last_seen_at"],
        )

    def record_issue_created(
        self, owner: str, repo: str, fingerprint: str,
        issue_number: int, issue_url: str, seen_at: str,
    ) -> None:
        self._exec(
            "INSERT INTO issue_tracking "
            "(owner, repo, fingerprint, issue_number, issue_url, first_seen_at, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (owner, repo, fingerprint, issue_number, issue_url, seen_at, seen_at),
        )

    def touch_issue_seen(self, owner: str, repo: str, fingerprint: str, seen_at: str) -> None:
        self._exec(
            "UPDATE issue_tracking SET last_seen_at = ? "
            "WHERE owner = ? AND repo = ? AND fingerprint = ?",
            (seen_at, owner, repo, fingerprint),
        )
```

- [ ] **Step 4: Run the state tests**

Run: `uv run pytest tests/test_state.py -v`
Expected: PASS — all pre-existing tests plus the 4 new ones.

- [ ] **Step 5: Commit**

```bash
git add src/secscan/state.py tests/test_state.py
git commit -m "feat(state): issue_tracking table for GitHub issue dedup (first/last seen)"
```

---

### Task 7: `src/secscan/issues.py` — per-finding issue creation

**Files:**
- Create: `src/secscan/issues.py`
- Test: `tests/test_issues.py` (new)

**Interfaces:**
- Consumes: `fingerprint` (Task 5, `findings.py`), `StateStore.find_issue`/`record_issue_created`/`touch_issue_seen` (Task 6), `Finding`.
- Produces:
  - `IssueOutcome` dataclass: `action: str` (`"created"`/`"skipped"`/`"would_create"`), `finding_title: str`, `issue_url: str = ""`.
  - `process_finding(gh_repo, store, owner: str, repo: str, finding: Finding, *, seen_at: str, dry_run: bool) -> IssueOutcome` — `gh_repo` is a PyGithub `Repository` object (already resolved by the caller via `Github(auth=Auth.Token(...)).get_repo(f"{owner}/{repo}")`, so this module has zero auth-token knowledge, keeping it easy to test with a fake).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_issues.py`:

```python
from secscan.findings import Finding, fingerprint
from secscan.issues import process_finding
from secscan.state import StateStore


class _FakeIssue:
    def __init__(self, number, html_url):
        self.number = number
        self.html_url = html_url


class _FakeGhRepo:
    def __init__(self):
        self.created = []

    def create_issue(self, title, body, labels):
        issue = _FakeIssue(len(self.created) + 1, f"https://github.com/octo/repo/issues/{len(self.created) + 1}")
        self.created.append((title, body, labels))
        return issue


def _finding(**overrides):
    defaults = dict(
        severity="high", title="SQLi", description="Unsanitized input", file_path="app.py",
        line_range="10-12", category="CWE-89", recommendation="Use parameterized queries", confidence="high",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_new_finding_creates_issue_and_records_tracking(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    gh_repo = _FakeGhRepo()
    finding = _finding()

    outcome = process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-12T00:00:00+00:00", dry_run=False)

    assert outcome.action == "created"
    assert len(gh_repo.created) == 1
    title, body, labels = gh_repo.created[0]
    assert title == "[secscan] high: SQLi (app.py)"
    assert labels == ["secscan"]
    assert "Unsanitized input" in body
    assert "Use parameterized queries" in body

    tracked = store.find_issue("octo", "repo", fingerprint(finding))
    assert tracked is not None
    assert tracked.issue_number == 1


def test_repeated_finding_skips_and_touches_last_seen(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    gh_repo = _FakeGhRepo()
    finding = _finding()

    process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-01T00:00:00+00:00", dry_run=False)
    outcome = process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-12T00:00:00+00:00", dry_run=False)

    assert outcome.action == "skipped"
    assert len(gh_repo.created) == 1  # no second issue

    tracked = store.find_issue("octo", "repo", fingerprint(finding))
    assert tracked.first_seen_at == "2026-07-01T00:00:00+00:00"
    assert tracked.last_seen_at == "2026-07-12T00:00:00+00:00"


def test_dry_run_new_finding_makes_no_calls_or_writes(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    gh_repo = _FakeGhRepo()
    finding = _finding()

    outcome = process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-12T00:00:00+00:00", dry_run=True)

    assert outcome.action == "would_create"
    assert gh_repo.created == []
    assert store.find_issue("octo", "repo", fingerprint(finding)) is None


def test_dry_run_repeated_finding_reports_skip_without_touching(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    gh_repo = _FakeGhRepo()
    finding = _finding()

    process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-01T00:00:00+00:00", dry_run=False)
    outcome = process_finding(gh_repo, store, "octo", "repo", finding, seen_at="2026-07-12T00:00:00+00:00", dry_run=True)

    assert outcome.action == "skipped"
    tracked = store.find_issue("octo", "repo", fingerprint(finding))
    assert tracked.last_seen_at == "2026-07-01T00:00:00+00:00"  # NOT bumped in dry-run
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_issues.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'secscan.issues'`.

- [ ] **Step 3: Implement `issues.py`**

Create `src/secscan/issues.py`:

```python
"""Open one GitHub issue per High/Critical finding, deduped by content fingerprint.

Mirrors emailer.py's style: a thin function, no framework. The caller resolves
GitHub auth and passes an already-authenticated PyGithub Repository object, so
this module has no credential knowledge and is trivial to test with a fake.
"""

from __future__ import annotations

from dataclasses import dataclass

from .findings import Finding, fingerprint
from .state import StateStore


@dataclass
class IssueOutcome:
    action: str  # "created" | "skipped" | "would_create"
    finding_title: str
    issue_url: str = ""


def _issue_title(finding: Finding) -> str:
    return f"[secscan] {finding.severity.value}: {finding.title} ({finding.file_path})"


def _issue_body(finding: Finding, fp: str) -> str:
    return (
        f"**Category:** {finding.category or '(none)'}\n"
        f"**Confidence:** {finding.confidence}\n"
        f"**File:** {finding.file_path} ({finding.line_range or 'line range unknown'})\n\n"
        f"{finding.description}\n\n"
        f"**Recommendation:**\n{finding.recommendation}\n\n"
        f"---\n_Opened automatically by secscan. Fingerprint: `{fp}`_"
    )


def process_finding(
    gh_repo,
    store: StateStore,
    owner: str,
    repo: str,
    finding: Finding,
    *,
    seen_at: str,
    dry_run: bool,
) -> IssueOutcome:
    fp = fingerprint(finding)
    existing = store.find_issue(owner, repo, fp)

    if existing:
        if not dry_run:
            store.touch_issue_seen(owner, repo, fp, seen_at)
        return IssueOutcome(action="skipped", finding_title=finding.title, issue_url=existing.issue_url)

    if dry_run:
        return IssueOutcome(action="would_create", finding_title=finding.title)

    issue = gh_repo.create_issue(
        title=_issue_title(finding), body=_issue_body(finding, fp), labels=["secscan"]
    )
    store.record_issue_created(owner, repo, fp, issue.number, issue.html_url, seen_at)
    return IssueOutcome(action="created", finding_title=finding.title, issue_url=issue.html_url)
```

- [ ] **Step 4: Run the issues tests**

Run: `uv run pytest tests/test_issues.py -v`
Expected: PASS — all 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/secscan/issues.py tests/test_issues.py
git commit -m "feat(issues): process_finding() opens/dedups one GitHub issue per finding"
```

---

### Task 8: `--create-issues`/`--dry-run` wiring + `--no-db` mutual exclusion

**Files:**
- Modify: `src/secscan/config.py` (`RunConfig`)
- Modify: `src/secscan/cli.py` (`run`, `scan` commands; `--no-db`+`--create-issues` validation)
- Modify: `src/secscan/orchestrator.py:94-144` (`_process_repo`)
- Modify: `README.md`
- Test: `tests/test_config.py`, `tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `process_finding` (Task 7), `IssueOutcome`.
- Produces:
  - `RunConfig.create_issues: bool = False`, `RunConfig.issue_dry_run: bool = False` (named `issue_dry_run` — not `dry_run` — to avoid any future collision with an unrelated dry-run concept elsewhere in `RunConfig`).
  - `_run_config(...)` raises `ConfigError` when `no_db and create_issues` are both `True`.
  - `_process_repo` calls `process_finding` for each `res.high_critical` finding when `cfg.create_issues` is `True`, and prints a per-repo `created N, skipped M` (or `would create N, would skip M` in dry-run) summary line.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_config.py`:

```python
from secscan.config import ConfigError


def test_create_issues_and_issue_dry_run_default_false():
    cfg = RunConfig()
    assert cfg.create_issues is False
    assert cfg.issue_dry_run is False


def test_run_config_rejects_no_db_with_create_issues():
    import pytest
    from secscan.cli import _run_config

    with pytest.raises(ConfigError, match="no-db.*create-issues|create-issues.*no-db"):
        _run_config(
            output_dir=Path("output"), concurrency=1, model="sonnet", max_turns=1,
            max_cost_usd=None, include_archived=False, include_forks=False, max_size_mb=0,
            keep_clones=True, resume=False, limit=None, no_db=True, create_issues=True,
        )
```

Add to `tests/test_orchestrator.py`:

```python
async def test_process_repo_creates_issues_when_enabled(tmp_path, monkeypatch):
    from secscan.findings import Finding
    from secscan.reviewer import ReviewResult
    import secscan.orchestrator as orch_module

    async def fake_mint_token(auth, repo):
        return "tok"

    async def fake_clone(repo, token, root):
        return tmp_path / "clone"

    finding = Finding(severity="high", title="SQLi", description="d", file_path="app.py")

    async def fake_review_repo(path, full_name, *, model, max_turns, max_cost_usd, extra_env, idle_timeout_s):
        return ReviewResult(repo_full_name=full_name, high_critical=[finding], findings=[finding])

    created_calls = []

    class _FakeGhRepo:
        def create_issue(self, title, body, labels):
            created_calls.append(title)
            class _I:
                number = 1
                html_url = "https://github.com/octo/demo/issues/1"
            return _I()

    class _FakeGithubClient:
        def get_repo(self, full_name):
            return _FakeGhRepo()

    monkeypatch.setattr(orch, "_mint_token", fake_mint_token)
    monkeypatch.setattr(orch, "_clone", fake_clone)
    monkeypatch.setattr(orch, "review_repo", fake_review_repo)
    monkeypatch.setattr(orch, "cleanup", lambda path: None)
    monkeypatch.setattr(orch_module, "Github", lambda auth: _FakeGithubClient())

    cfg = RunConfig(output_dir=tmp_path, create_issues=True)
    store = StateStore(cfg.state_target)
    sem = asyncio.Semaphore(1)
    provider_env = orch.ProviderEnv(name="anthropic")

    class _FakeAuthCtx:
        def token_for(self, repo):
            return "tok"

    await orch._process_repo(_repo(name="demo"), _FakeAuthCtx(), store, cfg, sem, provider_env)

    assert created_calls == ["[secscan] high: SQLi (app.py)"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_config.py::test_create_issues_and_issue_dry_run_default_false -v`
Expected: FAIL — `TypeError: RunConfig.__init__() got an unexpected keyword argument 'create_issues'`.

- [ ] **Step 3: Add fields to `RunConfig`**

In `src/secscan/config.py`, in `RunConfig`, add after `no_db`:

```python
    no_db: bool = False  # skip all DB storage; findings.csv still written, summary.csv skipped
    create_issues: bool = False  # open one GitHub issue per new High/Critical finding
    issue_dry_run: bool = False  # preview issue creation without any GitHub API calls or DB writes
```

- [ ] **Step 4: Add the mutual-exclusion check and thread the 2 fields through `cli.py`**

In `src/secscan/cli.py`, add `create_issues`/`issue_dry_run` params to `_run_config` (after `no_db`) and validate:

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
    db_user: str | None = None,
    db_password: str | None = None,
    db_ssl: bool = False,
    no_db: bool = False,
    create_issues: bool = False,
    issue_dry_run: bool = False,
    provider: str = "auto",
    timeout_s: float = 900.0,
) -> RunConfig:
    if no_db and create_issues:
        raise ConfigError("--no-db and --create-issues cannot be combined (issue dedup needs the DB)")
    return RunConfig(
        output_dir=output_dir,
        state_db=output_dir / "secscan.sqlite3",
        db_url=db_url,
        db_user=db_user,
        db_password=db_password,
        db_ssl=db_ssl,
        no_db=no_db,
        create_issues=create_issues,
        issue_dry_run=issue_dry_run,
        filters=Filters(
            include_archived=include_archived,
            include_forks=include_forks,
            max_size_mb=max_size_mb,
        ),
        concurrency=concurrency,
        model=model,
        provider=provider,
        max_turns=max_turns,
        max_cost_usd=max_cost_usd,
        timeout_s=timeout_s,
        keep_clones=keep_clones,
        resume=resume,
        limit=limit,
    )
```

Add `from .config import ConfigError, Filters, RunConfig` (update the existing `from .config import Filters, RunConfig` import line at the top of `cli.py` to include `ConfigError`).

In the `run` command, add 2 options after `no_db` (Task 3):

```python
    create_issues: bool = typer.Option(False, "--create-issues", help="Open one GitHub issue per new High/Critical finding (deduped by content fingerprint). Requires the DB — cannot combine with --no-db."),
    dry_run: bool = typer.Option(False, "--dry-run", help="With --create-issues: preview what would be created/skipped, making zero GitHub API calls or DB writes."),
```

and pass `create_issues=create_issues, issue_dry_run=dry_run,` in its `_run_config(...)` call.

In the `scan` command, add the same 2 options and pass them the same way.

- [ ] **Step 5: Call `process_finding` from `_process_repo`**

In `src/secscan/orchestrator.py`, add imports at the top:

```python
from github import Auth, Github

from .issues import process_finding
```

In `_process_repo`, after the `write_findings_csv`/`store.replace_findings` block and before the `if res.error and not res.findings:` check, insert:

```python
            if store is not None and cfg.create_issues and res.high_critical:
                gh_client = Github(auth=Auth.Token(auth.token_for(repo)))
                gh_repo = gh_client.get_repo(repo.full_name)
                created = skipped = 0
                for finding in res.high_critical:
                    outcome = process_finding(
                        gh_repo, store, owner, name, finding,
                        seen_at=_now(), dry_run=cfg.issue_dry_run,
                    )
                    if outcome.action in ("created", "would_create"):
                        created += 1
                    else:
                        skipped += 1
                verb = "would create" if cfg.issue_dry_run else "created"
                skip_verb = "would skip" if cfg.issue_dry_run else "skipped"
                typer.echo(f"    issues: {verb} {created}, {skip_verb} {skipped}")
```

(Placed after the CSV/DB write and before the success/failure summary echo, so issue creation happens once per repo, using the same `res.high_critical` list already computed.)

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/test_config.py tests/test_orchestrator.py -v`
Expected: PASS — all pre-existing tests plus the new ones.

Run: `uv run pytest -q`
Expected: full suite passes.

- [ ] **Step 7: Update the README**

In `README.md`, add to "Common flags":

```markdown
--create-issues --dry-run
```

Add a new section after "Scan targets":

```markdown
## Creating GitHub issues

`--create-issues` (on `run`/`scan`) opens one GitHub issue per new High/Critical
finding, deduped by a content fingerprint (severity + category + title + file
path) tracked in the state DB — re-scanning the same repo never opens a second
issue for a finding already tracked, it just bumps that finding's "last seen"
timestamp. `--dry-run` previews what would be created/skipped with **zero**
GitHub API calls and zero DB writes. Requires the DB (`--no-db --create-issues`
is a config error).

```bash
uv run secscan scan octo/webapp --create-issues --dry-run   # preview
uv run secscan scan octo/webapp --create-issues             # actually open issues
```

**Prerequisite:** the GitHub App's permissions need **Issues: Write** added
(alongside the existing Contents: Read, Metadata: Read) — existing installations
require re-approval after this permission is added to the App manifest. PAT mode
already covers this via the `repo` scope.
```

- [ ] **Step 8: Commit**

```bash
git add src/secscan/config.py src/secscan/cli.py src/secscan/orchestrator.py README.md tests/test_config.py tests/test_orchestrator.py
git commit -m "feat(cli): --create-issues/--dry-run wiring, --no-db mutual exclusion"
```

---

## Part C — Push findings to secman

### Task 9: `src/secscan/secman_client.py`

**Files:**
- Create: `src/secscan/secman_client.py`
- Modify: `pyproject.toml` (add `requests` dependency)
- Test: `tests/test_secman_client.py` (new)

**Interfaces:**
- Consumes: nothing from earlier tasks (standalone HTTP client).
- Produces:
  - `SecmanPushError(Exception)`.
  - `login(base_url: str, username: str, password: str) -> str` — returns the JWT string.
  - `push_vulnerability(base_url: str, token: str, *, hostname: str, cve: str, criticality: str, days_open: int) -> dict` — returns the parsed JSON response body.

- [ ] **Step 1: Add the `requests` dependency**

In `pyproject.toml`, add to `dependencies` (after `"tenacity>=8.2",`):

```toml
    "requests>=2.31",
```

Run: `uv sync`
Expected: exits 0; `requests` now installed.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_secman_client.py`:

```python
import pytest

from secscan.secman_client import SecmanPushError, login, push_vulnerability


class _FakeResponse:
    def __init__(self, status_code, json_body=None, headers=None):
        self.status_code = status_code
        self._json_body = json_body or {}
        self.headers = headers or {}

    def json(self):
        return self._json_body

    @property
    def text(self):
        import json
        return json.dumps(self._json_body)


def test_login_extracts_token_from_set_cookie(monkeypatch):
    def fake_post(url, json, timeout):
        assert url == "https://secman.example.com/api/auth/login"
        assert json == {"username": "vulnbot", "password": "pw"}
        return _FakeResponse(200, {"id": 1, "username": "vulnbot"}, headers={
            "Set-Cookie": "secman_auth=abc.def.ghi; Path=/; HttpOnly; Secure; SameSite=Lax"
        })

    import secscan.secman_client as client
    monkeypatch.setattr(client.requests, "post", fake_post)

    token = login("https://secman.example.com", "vulnbot", "pw")
    assert token == "abc.def.ghi"


def test_login_401_raises_secman_push_error(monkeypatch):
    def fake_post(url, json, timeout):
        return _FakeResponse(401, {"error": "Invalid credentials"})

    import secscan.secman_client as client
    monkeypatch.setattr(client.requests, "post", fake_post)

    with pytest.raises(SecmanPushError, match="401|Invalid credentials"):
        login("https://secman.example.com", "vulnbot", "wrongpw")


def test_login_no_cookie_raises_secman_push_error(monkeypatch):
    def fake_post(url, json, timeout):
        return _FakeResponse(200, {"id": 1}, headers={})

    import secscan.secman_client as client
    monkeypatch.setattr(client.requests, "post", fake_post)

    with pytest.raises(SecmanPushError, match="token"):
        login("https://secman.example.com", "vulnbot", "pw")


def test_push_vulnerability_sends_bearer_and_body(monkeypatch):
    captured = {}

    def fake_post(url, json, headers, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _FakeResponse(200, {
            "success": True, "message": "ok", "assetId": 1, "assetName": "octo/repo",
            "assetCreated": True, "vulnerabilityId": "SECSCAN:CWE-89:abc123", "id": 5,
            "operation": "CREATED",
        })

    import secscan.secman_client as client
    monkeypatch.setattr(client.requests, "post", fake_post)

    result = push_vulnerability(
        "https://secman.example.com", "abc.def.ghi",
        hostname="octo/repo", cve="SECSCAN:CWE-89:abc123", criticality="HIGH", days_open=3,
    )

    assert captured["url"] == "https://secman.example.com/api/vulnerabilities/cli-add"
    assert captured["json"] == {
        "hostname": "octo/repo", "cve": "SECSCAN:CWE-89:abc123",
        "criticality": "HIGH", "daysOpen": 3,
    }
    assert captured["headers"] == {"Authorization": "Bearer abc.def.ghi"}
    assert result["operation"] == "CREATED"


def test_push_vulnerability_400_raises_without_retrying_forever(monkeypatch):
    def fake_post(url, json, headers, timeout):
        return _FakeResponse(400, {"error": "Criticality must be CRITICAL, HIGH, MEDIUM, or LOW"})

    import secscan.secman_client as client
    monkeypatch.setattr(client.requests, "post", fake_post)

    with pytest.raises(SecmanPushError, match="400"):
        push_vulnerability(
            "https://secman.example.com", "tok",
            hostname="octo/repo", cve="bad", criticality="NOPE", days_open=0,
        )
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_secman_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'secscan.secman_client'`.

- [ ] **Step 4: Implement `secman_client.py`**

Create `src/secscan/secman_client.py`:

```python
"""Thin HTTP client for pushing findings into secman via POST /api/vulnerabilities/cli-add.

Mirrors secman's own CLI (CliHttpClient.authenticate in the secman repo): the
login response carries no token in its JSON body — the JWT only appears in the
Set-Cookie: secman_auth=<jwt> response header. Subsequent requests send it as
a standard Authorization: Bearer header (Micronaut's bearer-token reader stays
active alongside cookie auth on the secman backend).
"""

from __future__ import annotations

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

_TIMEOUT_S = 30
_RETRY = dict(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=20),
    retry=retry_if_exception_type(requests.exceptions.ConnectionError),
    reraise=True,
)


class SecmanPushError(Exception):
    """Raised on login failure or a rejected cli-add call."""


def _extract_cookie_token(set_cookie_header: str, cookie_name: str = "secman_auth") -> str | None:
    for part in set_cookie_header.split(";"):
        part = part.strip()
        if part.startswith(f"{cookie_name}="):
            return part[len(f"{cookie_name}="):]
    return None


@retry(**_RETRY)
def login(base_url: str, username: str, password: str) -> str:
    """POST /api/auth/login, return the JWT extracted from Set-Cookie."""
    resp = requests.post(
        f"{base_url}/api/auth/login",
        json={"username": username, "password": password},
        timeout=_TIMEOUT_S,
    )
    if resp.status_code != 200:
        raise SecmanPushError(f"secman login failed: {resp.status_code} {resp.text[:300]}")

    set_cookie = resp.headers.get("Set-Cookie", "")
    token = _extract_cookie_token(set_cookie)
    if not token:
        raise SecmanPushError("secman login succeeded but no auth token found in Set-Cookie response header")
    return token


@retry(**_RETRY)
def push_vulnerability(
    base_url: str,
    token: str,
    *,
    hostname: str,
    cve: str,
    criticality: str,
    days_open: int,
) -> dict:
    """POST /api/vulnerabilities/cli-add with Authorization: Bearer {token}."""
    resp = requests.post(
        f"{base_url}/api/vulnerabilities/cli-add",
        json={"hostname": hostname, "cve": cve, "criticality": criticality, "daysOpen": days_open},
        headers={"Authorization": f"Bearer {token}"},
        timeout=_TIMEOUT_S,
    )
    if resp.status_code != 200:
        raise SecmanPushError(f"cli-add failed: {resp.status_code} {resp.text[:300]}")
    return resp.json()
```

- [ ] **Step 5: Run the secman_client tests**

Run: `uv run pytest tests/test_secman_client.py -v`
Expected: PASS — all 5 tests.

- [ ] **Step 6: Run the full suite**

Run: `uv run pytest -q`
Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml uv.lock src/secscan/secman_client.py tests/test_secman_client.py
git commit -m "feat(secman): login + push_vulnerability HTTP client"
```

---

### Task 10: `push-to-secman` CLI command

**Files:**
- Modify: `src/secscan/cli.py` (new `push-to-secman` command)
- Modify: `README.md`
- Test: `tests/test_cli_push_to_secman.py` (new)

**Interfaces:**
- Consumes: `login`/`push_vulnerability`/`SecmanPushError` (Task 9), `fingerprint` (Task 5), `StateStore.find_issue` (Task 6, optional `daysOpen` enrichment), `_open_store` (existing).
- Produces: `secscan push-to-secman` Typer command.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_cli_push_to_secman.py`:

```python
from typer.testing import CliRunner

import secscan.secman_client as secman_client
from secscan.cli import app
from secscan.findings import Finding, fingerprint
from secscan.state import StateStore

runner = CliRunner()


def _seed(tmp_path):
    store = StateStore(tmp_path / "secscan.sqlite3")
    store.record_result(
        "octo", "demo",
        critical=1, high=1, total=3,
        duration_s=1.0, cost_usd=0.1, reviewed_at="2026-07-01T00:00:00+00:00",
    )
    store.replace_findings(
        "octo", "demo",
        [
            Finding(severity="critical", title="SQLi", description="d", file_path="a.py", category="CWE-89"),
            Finding(severity="high", title="XSS", description="d", file_path="b.py"),
            Finding(severity="medium", title="Weak crypto", description="d", file_path="c.py"),
        ],
    )
    store.close()


def _secman_env(monkeypatch):
    monkeypatch.setenv("SECMAN_URL", "https://secman.example.com")
    monkeypatch.setenv("SECMAN_USERNAME", "vulnbot")
    monkeypatch.setenv("SECMAN_PASSWORD", "pw")


def test_push_to_secman_pushes_only_high_critical(tmp_path, monkeypatch):
    _seed(tmp_path)
    _secman_env(monkeypatch)

    monkeypatch.setattr(secman_client, "login", lambda url, u, p: "tok")
    pushed = []

    def fake_push(url, token, *, hostname, cve, criticality, days_open):
        pushed.append((hostname, cve, criticality, days_open))
        return {"operation": "CREATED"}

    monkeypatch.setattr(secman_client, "push_vulnerability", fake_push)

    result = runner.invoke(app, ["push-to-secman", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert len(pushed) == 2  # only critical + high, not medium
    hostnames = {p[0] for p in pushed}
    assert hostnames == {"octo/demo"}
    criticalities = {p[2] for p in pushed}
    assert criticalities == {"CRITICAL", "HIGH"}
    assert "pushed 2" in result.output


def test_push_to_secman_dry_run_makes_no_calls(tmp_path, monkeypatch):
    _seed(tmp_path)
    _secman_env(monkeypatch)

    login_called = []
    monkeypatch.setattr(secman_client, "login", lambda url, u, p: login_called.append(1) or "tok")
    push_called = []
    monkeypatch.setattr(
        secman_client, "push_vulnerability",
        lambda *a, **kw: push_called.append(1) or {"operation": "CREATED"},
    )

    result = runner.invoke(app, ["push-to-secman", "--dry-run", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert login_called == []
    assert push_called == []
    assert "would push 2" in result.output


def test_push_to_secman_missing_credentials_fails_clearly(tmp_path, monkeypatch):
    _seed(tmp_path)
    for var in ("SECMAN_URL", "SECMAN_USERNAME", "SECMAN_PASSWORD"):
        monkeypatch.delenv(var, raising=False)

    result = runner.invoke(app, ["push-to-secman", "--output-dir", str(tmp_path)])

    assert result.exit_code != 0
    assert "secman" in result.output.lower()


def test_push_to_secman_one_failure_does_not_abort_run(tmp_path, monkeypatch):
    _seed(tmp_path)
    _secman_env(monkeypatch)
    monkeypatch.setattr(secman_client, "login", lambda url, u, p: "tok")

    calls = []

    def fake_push(url, token, *, hostname, cve, criticality, days_open):
        calls.append(cve)
        if len(calls) == 1:
            raise secman_client.SecmanPushError("400 bad request")
        return {"operation": "CREATED"}

    monkeypatch.setattr(secman_client, "push_vulnerability", fake_push)

    result = runner.invoke(app, ["push-to-secman", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert len(calls) == 2  # both findings attempted despite the first failing
    assert "failed 1" in result.output


def test_push_to_secman_cve_format_and_days_open_default_zero(tmp_path, monkeypatch):
    _seed(tmp_path)
    _secman_env(monkeypatch)
    monkeypatch.setattr(secman_client, "login", lambda url, u, p: "tok")

    pushed = []
    monkeypatch.setattr(
        secman_client, "push_vulnerability",
        lambda url, token, **kw: pushed.append(kw) or {"operation": "CREATED"},
    )

    runner.invoke(app, ["push-to-secman", "--output-dir", str(tmp_path)])

    sqli = next(p for p in pushed if p["hostname"] == "octo/demo" and p["criticality"] == "CRITICAL")
    assert sqli["cve"].startswith("SECSCAN:CWE-89:")
    assert sqli["days_open"] == 0  # no issue_tracking row exists for this finding
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli_push_to_secman.py -v`
Expected: FAIL — `push-to-secman` is not a recognized command (Typer reports usage error / exit code 2).

- [ ] **Step 3: Implement the `push-to-secman` command**

In `src/secscan/cli.py`, add near the top (after the existing imports, before `app = typer.Typer(...)`):

```python
def _resolve_secman_url(url: str | None) -> str | None:
    import os

    return url or os.environ.get("SECMAN_URL") or None


def _resolve_secman_username(username: str | None) -> str | None:
    import os

    return username or os.environ.get("SECMAN_USERNAME") or None


def _resolve_secman_password(password: str | None) -> str | None:
    import os

    return password or os.environ.get("SECMAN_PASSWORD") or None
```

Add the command after `send_report` (before `_TARGET_DB_HELP`):

```python
@app.command("push-to-secman")
def push_to_secman(
    secman_url: str = typer.Option(None, "--secman-url", help="secman base URL (or SECMAN_URL env)."),
    secman_username: str = typer.Option(None, "--secman-username", help="secman username (or SECMAN_USERNAME env)."),
    secman_password: str = typer.Option(None, "--secman-password", help="secman password (or SECMAN_PASSWORD env)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview what would be pushed; makes zero login/API calls."),
    output_dir: Path = typer.Option(Path("output"), help="Where the state DB lives."),
    db_url: str = typer.Option(None, help="MySQL/MariaDB URL; defaults to SECSCAN_DB_URL or local SQLite."),
    db_user: str = typer.Option(None, help="MySQL/MariaDB username (or DB_USERNAME env)."),
    db_password: str = typer.Option(None, help="MySQL/MariaDB password (or DB_PASSWORD env)."),
    db_ssl: bool = typer.Option(False, help="Encrypt the MySQL/MariaDB connection (or DB_SSL=true env)."),
) -> None:
    """Push High/Critical findings from the state DB into secman via cli-add."""
    from datetime import datetime, timezone

    from . import secman_client
    from .findings import fingerprint

    url = _resolve_secman_url(secman_url)
    username = _resolve_secman_username(secman_username)
    password = _resolve_secman_password(secman_password)
    if not url or not username or not password:
        typer.echo(
            "Error: secman URL/username/password required "
            "(--secman-url/--secman-username/--secman-password or "
            "SECMAN_URL/SECMAN_USERNAME/SECMAN_PASSWORD env vars)",
            err=True,
        )
        raise typer.Exit(1)

    store = _open_store(output_dir, db_url, db_user, db_password, db_ssl)
    records = store.all_records()

    token = None
    if not dry_run:
        try:
            token = secman_client.login(url, username, password)
        except secman_client.SecmanPushError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(1)

    now = datetime.now(timezone.utc).isoformat()
    pushed = failed = 0
    for rec in records:
        for row in store.get_findings(rec.owner, rec.repo):
            if row["severity"] not in ("critical", "high"):
                continue

            class _RowFinding:
                severity = type("S", (), {"value": row["severity"]})()
                category = row["category"]
                title = row["title"]
                file_path = row["file_path"]

            fp = fingerprint(_RowFinding())
            issue = store.find_issue(rec.owner, rec.repo, fp)
            days_open = 0
            if issue is not None:
                first_seen = datetime.fromisoformat(issue.first_seen_at)
                days_open = max(0, (datetime.now(timezone.utc) - first_seen).days)
            cve = f"SECSCAN:{row['category'] or 'FINDING'}:{fp[:12]}"
            hostname = rec.full_name

            if dry_run:
                typer.echo(f"would push {hostname} {cve} {row['severity'].upper()}")
                pushed += 1
                continue

            try:
                secman_client.push_vulnerability(
                    url, token,
                    hostname=hostname, cve=cve,
                    criticality=row["severity"].upper(), days_open=days_open,
                )
                pushed += 1
            except secman_client.SecmanPushError as exc:
                typer.echo(f"failed: {hostname} {cve}: {exc}", err=True)
                failed += 1

    verb = "would push" if dry_run else "pushed"
    typer.echo(f"{verb} {pushed}" + ("" if dry_run else f", failed {failed}"))
```

(The `_RowFinding` shim exists because `fingerprint()` takes a `Finding`-shaped object with `.severity.value`/`.category`/`.title`/`.file_path`, but `store.get_findings()` returns plain dicts, not `Finding` instances — this avoids re-validating through Pydantic just to compute a hash.)

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/test_cli_push_to_secman.py -v`
Expected: PASS — all 5 tests.

Run: `uv run pytest -q`
Expected: full suite passes.

- [ ] **Step 5: Update the README**

In `README.md`, add to the Configuration table:

```markdown
| `SECMAN_URL` | secman base URL for `push-to-secman` (or `--secman-url`) |
| `SECMAN_USERNAME` | secman username for `push-to-secman` (or `--secman-username`); needs ADMIN or VULN role |
| `SECMAN_PASSWORD` | secman password for `push-to-secman` (or `--secman-password`) |
```

Add to the Usage code block:

```markdown
uv run secscan push-to-secman                              # push High/Critical findings to secman
uv run secscan push-to-secman --dry-run                    # preview only
```

Add a new section after "Creating GitHub issues":

```markdown
## Push findings to secman

`secscan push-to-secman` pushes every High/Critical finding currently in the
state DB into [secman](https://github.com/schmalle/secman) via its
`POST /api/vulnerabilities/cli-add` endpoint (requires an ADMIN or VULN-role
secman account). One secman asset is created per scanned repo (`owner/repo` as
the hostname); re-running after a later scan updates the existing secman
vulnerability rather than duplicating it (secman upserts by asset + a stable
synthetic identifier derived from the finding's fingerprint).

```bash
export SECMAN_URL=https://secman.example.com
export SECMAN_USERNAME=vulnbot
export SECMAN_PASSWORD=…
uv run secscan push-to-secman --dry-run   # preview what would be pushed
uv run secscan push-to-secman             # actually push
```

**Known limitation:** secman's `cli-add` schema has no free-text field — it only
shows a compact identifier (`SECSCAN:<category>:<fingerprint prefix>`), severity,
and asset name. Full finding detail (description, recommendation, file/line)
stays in secscan's own `findings.csv`/state DB and, if `--create-issues` was
used, the linked GitHub issue.
```

- [ ] **Step 6: Commit**

```bash
git add src/secscan/cli.py README.md tests/test_cli_push_to_secman.py
git commit -m "feat(cli): push-to-secman command"
```

---

## Self-Review Notes

**Spec coverage** (checked against both spec files):
- A1 (`--no-db`, `summary.csv` skip, mutual exclusion) → Task 3 (skip) + Task 8 (mutual exclusion, since `--create-issues` doesn't exist until then).
- A2 (credentials flag/env, precedence) → Task 1 (state.py) + Task 2 (cli.py).
- A3 (`--db-ssl`) → Task 1 + Task 2.
- A4 (`setup-mysql.sh` + docs) → Task 4.
- B1 (`--create-issues`/`--dry-run` trigger) → Task 8.
- B2 (fingerprint, `issue_tracking` table) → Task 5 (fingerprint) + Task 6 (table).
- B3 (`issues.py` per-finding flow, title/body/label) → Task 7.
- B4 (Issues: Write prerequisite doc) → Task 8, Step 7.
- C — auth/login, push_vulnerability, cve/hostname/criticality/daysOpen mapping, dry-run, error handling → Task 9 (client) + Task 10 (command).
- Non-goals verified NOT implemented: no issue close/reopen, no CA/cert/key SSL, no `review` support for `--no-db`/`--create-issues`, no secman-side dedup table, no `--insecure` TLS bypass.

**Placeholder scan:** no TBD/TODO; every step has literal code, not descriptions. The one soft spot — Task 4 Step 3's script smoke test — is explicitly framed as a manual sanity check (not a pytest assertion) because there's no real MySQL server in this environment; this is disclosed, not hidden.

**Type/signature consistency across tasks:**
- `StateStore.__init__(target, *, db_user=None, db_password=None, db_ssl=False)` (Task 1) is called identically in Task 3's `run_scan`/`scan_repo` edits and Task 2's `_open_store`.
- `fingerprint(finding) -> str` (Task 5) signature matches its use in Task 7 (`issues.py`) and Task 10 (`push-to-secman`, via the `_RowFinding` shim).
- `IssueRecord.first_seen_at`/`last_seen_at` (Task 6) field names match Task 10's `issue.first_seen_at` read.
- `process_finding(gh_repo, store, owner, repo, finding, *, seen_at, dry_run) -> IssueOutcome` (Task 7) matches its call site in Task 8.
- `RunConfig.issue_dry_run` (not `dry_run`) is used consistently in Task 8's `_process_repo` edit (`cfg.issue_dry_run`) — deliberately distinct from `push-to-secman`'s local `dry_run` CLI parameter (Task 10), which is not a `RunConfig` field at all (that command doesn't build a `RunConfig`-driven review, just opens a store).
- `secman_client.login`/`push_vulnerability`/`SecmanPushError` (Task 9) names match Task 10's `from . import secman_client` usage and its test's `monkeypatch.setattr(secman_client, ...)` calls.

**Fixed during self-review:** Task 3 originally risked implying `--no-db` should also apply to `review` — corrected in Step 7 to explicitly note `review_local` never opens a store today, so no `review`-side change is needed (avoids a wasted/confusing no-op flag). Also corrected `run_scan`'s `store.list_targets()`/`upsert_pending`/`is_done` calls (outside `_process_repo`) to guard on `store is not None`, which the original spec's A1 section didn't call out explicitly but is required for `run --no-db` to actually work end-to-end (not just inside `_process_repo`). Also fixed a test/implementation mismatch in Task 9: `test_login_no_cookie_raises_secman_push_error` asserts `match="token"` but the drafted error message said "no JWT found" (no "token" substring) — reworded to "no auth token found in Set-Cookie response header" so the test actually matches the code it's testing.
