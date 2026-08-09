"""Resumable state manifest backed by SQLite or MySQL/MariaDB.

One row per repository in `repos`, keyed by (owner, repo). Lets long multi-repo runs
be interrupted and resumed, and lets `secscan report` rebuild summary.csv afterwards.

The backend is chosen from the target passed to `StateStore`: a `mysql://…` (or
`mariadb://…`) URL selects MySQL/MariaDB (via mysqlclient, the `mysql` extra);
anything else is a SQLite file path (the default).
"""

from __future__ import annotations

import sqlite3
import threading
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from .findings import Finding
    from .github_users import GithubUser


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
    last_commit_sha: str = ""
    last_commit_date: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass
class IssueRecord:
    owner: str
    repo: str
    fingerprint: str
    issue_number: int
    issue_url: str
    first_seen_at: str
    last_seen_at: str


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
    last_commit_sha  TEXT NOT NULL DEFAULT '',
    last_commit_date TEXT NOT NULL DEFAULT '',
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
    last_commit_sha  VARCHAR(64) NOT NULL DEFAULT '',
    last_commit_date VARCHAR(32) NOT NULL DEFAULT '',
    PRIMARY KEY (owner, repo)
);
"""


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


_TARGETS_SQLITE = """
CREATE TABLE IF NOT EXISTS targets (
    owner    TEXT NOT NULL,
    repo     TEXT NOT NULL,
    added_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (owner, repo)
);
"""

_TARGETS_MYSQL = """
CREATE TABLE IF NOT EXISTS targets (
    owner    VARCHAR(255) NOT NULL,
    repo     VARCHAR(255) NOT NULL,
    added_at VARCHAR(64) NOT NULL DEFAULT '',
    PRIMARY KEY (owner, repo)
);
"""


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


_GITHUB_USERS_SQLITE = """
CREATE TABLE IF NOT EXISTS github_users (
    org        TEXT NOT NULL,
    repo       TEXT NOT NULL DEFAULT '',
    login      TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT '',
    role       TEXT NOT NULL DEFAULT '',
    user_id    INTEGER NOT NULL DEFAULT 0,
    name       TEXT NOT NULL DEFAULT '',
    email      TEXT NOT NULL DEFAULT '',
    user_type  TEXT NOT NULL DEFAULT '',
    site_admin INTEGER NOT NULL DEFAULT 0,
    html_url   TEXT NOT NULL DEFAULT '',
    seen_at    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (org, repo, login)
);
"""

# `repo` is '' for an org-members row, so (org, repo, login) is a single key covering
# both listings. The three key columns total 3060 bytes under utf8mb4 — inside InnoDB's
# 3072-byte index limit, but that is why they are not wider.
_GITHUB_USERS_MYSQL = """
CREATE TABLE IF NOT EXISTS github_users (
    org        VARCHAR(255) NOT NULL,
    repo       VARCHAR(255) NOT NULL DEFAULT '',
    login      VARCHAR(255) NOT NULL,
    source     VARCHAR(32) NOT NULL DEFAULT '',
    role       VARCHAR(32) NOT NULL DEFAULT '',
    user_id    BIGINT NOT NULL DEFAULT 0,
    name       TEXT NOT NULL,
    email      VARCHAR(320) NOT NULL DEFAULT '',
    user_type  VARCHAR(32) NOT NULL DEFAULT '',
    site_admin TINYINT(1) NOT NULL DEFAULT 0,
    html_url   TEXT NOT NULL,
    seen_at    VARCHAR(64) NOT NULL DEFAULT '',
    PRIMARY KEY (org, repo, login)
);
"""


# Columns added to `repos` after the table shipped. `CREATE TABLE IF NOT EXISTS` is a
# no-op on a database that already has the table, so these are applied separately and
# the "column already exists" error is swallowed — see _ensure_columns.
_MIGRATIONS_SQLITE = (
    "ALTER TABLE repos ADD COLUMN last_commit_sha TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE repos ADD COLUMN last_commit_date TEXT NOT NULL DEFAULT ''",
)

_MIGRATIONS_MYSQL = (
    "ALTER TABLE repos ADD COLUMN last_commit_sha VARCHAR(64) NOT NULL DEFAULT ''",
    "ALTER TABLE repos ADD COLUMN last_commit_date VARCHAR(32) NOT NULL DEFAULT ''",
)


@dataclass(frozen=True)
class _Dialect:
    placeholder: str
    insert_ignore: str
    schema: tuple[str, ...]
    migrations: tuple[str, ...]


_SQLITE_DIALECT = _Dialect(
    placeholder="?",
    insert_ignore="INSERT OR IGNORE INTO",
    schema=(
        _REPOS_SQLITE, _FINDINGS_SQLITE, _TARGETS_SQLITE, _ISSUE_TRACKING_SQLITE,
        _GITHUB_USERS_SQLITE,
    ),
    migrations=_MIGRATIONS_SQLITE,
)

_MYSQL_DIALECT = _Dialect(
    placeholder="%s",
    insert_ignore="INSERT IGNORE INTO",
    schema=(
        _REPOS_MYSQL, _FINDINGS_MYSQL, _TARGETS_MYSQL, _ISSUE_TRACKING_MYSQL,
        _GITHUB_USERS_MYSQL,
    ),
    migrations=_MIGRATIONS_MYSQL,
)


def _is_mysql(target: str | Path) -> bool:
    return isinstance(target, str) and target.startswith(("mysql://", "mariadb://"))


def _dialect_for(target: str | Path) -> _Dialect:
    return _MYSQL_DIALECT if _is_mysql(target) else _SQLITE_DIALECT


def _connect_sqlite(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    # check_same_thread=False: the --create-issues path in orchestrator.py runs
    # StateStore calls via asyncio.to_thread (to keep blocking GitHub API calls off
    # the event loop), which hands them to a worker thread different from the one
    # that opened this connection — possibly a different worker thread per
    # concurrently-processed repo. Python's sqlite3 module links against the
    # system SQLite library, which defaults to "serialized" threading mode
    # (internally mutex-protected), so a single shared connection used from
    # multiple threads is safe from corruption; check_same_thread=False only
    # lifts Python's own same-thread guard rail on top of that.
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


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


class StateStore:
    def __init__(
        self,
        target: str | Path,
        *,
        db_user: str | None = None,
        db_password: str | None = None,
        db_ssl: bool = False,
    ):
        self._target = target
        self._d = _dialect_for(target)
        self._is_mysql = _is_mysql(target)
        self._db_user = db_user
        self._db_password = db_password
        self._db_ssl = db_ssl
        self._thread_local = threading.local()  # per-thread MySQL connections only
        if self._is_mysql:
            self._conn = _connect_mysql(str(target), user=db_user, password=db_password, ssl=db_ssl)
        else:
            self._conn = _connect_sqlite(Path(target))
        cur = self._conn.cursor()
        for stmt in self._d.schema:
            cur.execute(stmt)
        self._conn.commit()
        self._ensure_columns()

    def _ensure_columns(self) -> None:
        """Add post-release columns to a database created by an older secscan.

        Each ALTER is independent and idempotent: on a database that already has the
        column, the driver raises (SQLite "duplicate column name", MySQL error 1060)
        and we move on. Broad except by design — the alternative is dialect-specific
        error-code matching for a statement whose only expected failure is "already
        applied", and a genuinely broken database fails loudly on the first real query.
        """
        for stmt in self._d.migrations:
            cur = self._conn.cursor()
            try:
                cur.execute(stmt)
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    def close(self) -> None:
        self._conn.close()

    # -- internals --------------------------------------------------------------

    @property
    def _active_conn(self):
        """The connection to use for the calling thread.

        SQLite: always the single shared connection — safe because
        check_same_thread=False plus SQLite's serialized threading mode make
        one connection safe to share across threads (see _connect_sqlite).

        MySQL: mysqlclient's DB-API threadsafety=1 means the module is
        thread-safe but a single connection is not — concurrent use from
        multiple threads (e.g. one per --create-issues worker thread via
        asyncio.to_thread) risks "commands out of sync" errors. So MySQL
        gets one connection per thread, opened lazily and cached in
        thread-local storage; the thread that constructed this StateStore
        (always the main/event-loop thread in this codebase) keeps reusing
        self._conn from __init__.
        """
        if not self._is_mysql or threading.current_thread() is threading.main_thread():
            return self._conn
        if not hasattr(self._thread_local, "conn"):
            self._thread_local.conn = _connect_mysql(
                str(self._target), user=self._db_user, password=self._db_password, ssl=self._db_ssl,
            )
        return self._thread_local.conn

    def _ph(self, sql: str) -> str:
        if self._d.placeholder == "?":
            return sql
        return sql.replace("?", self._d.placeholder)

    def _exec(self, sql: str, params: tuple = ()):
        conn = self._active_conn
        cur = conn.cursor()
        cur.execute(self._ph(sql), params)
        conn.commit()
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

    def record_last_commit(self, owner: str, repo: str, sha: str, date: str) -> None:
        """Record the repo's latest commit without touching its scan status.

        Deliberately not routed through mark(), which writes `status`: listing a
        repository is not scanning it, so a `list-repos` run must never move a done
        repo back to pending.
        """
        self.upsert_pending(owner, repo)
        self._exec(
            "UPDATE repos SET last_commit_sha = ?, last_commit_date = ? "
            "WHERE owner = ? AND repo = ?",
            (sha, date, owner, repo),
        )

    def record_failure(self, owner: str, repo: str, error: str) -> None:
        self.mark(owner, repo, Status.FAILED, error=error)

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

    def clear_stats(self) -> tuple[int, int]:
        """Delete all scan history and stored findings; returns (repos, findings) deleted.

        Registered targets and GitHub issue tracking are deliberately left alone:
        wiping issue_tracking would make the next --create-issues run re-open issues
        that already exist on GitHub.
        """
        cur = self._conn.cursor()
        cur.execute("DELETE FROM findings")
        findings_deleted = cur.rowcount
        cur.execute("DELETE FROM repos")
        repos_deleted = cur.rowcount
        self._conn.commit()
        return (max(repos_deleted, 0), max(findings_deleted, 0))

    def get_findings(self, owner: str, repo: str) -> list[dict]:
        cur = self._exec(
            "SELECT * FROM findings WHERE owner = ? AND repo = ? ORDER BY id",
            (owner, repo),
        )
        return [dict(r) for r in cur.fetchall()]

    # -- GitHub users -------------------------------------------------------------

    _USER_COLS = (
        "org", "repo", "login", "source", "role", "user_id",
        "name", "email", "user_type", "site_admin", "html_url", "seen_at",
    )

    def replace_users(
        self, org: str, repo: str, users: "Iterable[GithubUser]", seen_at: str = ""
    ) -> int:
        """Replace the stored users for one scope (delete-then-insert), one transaction.

        The scope is `(org, "")` for an org-members listing and `(owner, name)` for a
        repo's collaborators. Delete-then-insert rather than upsert so somebody who left
        the org disappears from the table instead of lingering forever. Returns the
        number of rows inserted.
        """
        cur = self._conn.cursor()
        cur.execute(
            self._ph("DELETE FROM github_users WHERE org = ? AND repo = ?"), (org, repo)
        )
        rows = [
            (
                u.org, u.repo, u.login, u.source, u.role, u.user_id,
                u.name, u.email, u.user_type, int(bool(u.site_admin)), u.html_url, seen_at,
            )
            for u in users
        ]
        if rows:
            cols = ", ".join(self._USER_COLS)
            marks = ", ".join("?" for _ in self._USER_COLS)
            cur.executemany(
                self._ph(f"INSERT INTO github_users ({cols}) VALUES ({marks})"), rows
            )
        self._conn.commit()
        return len(rows)

    def get_users(self, org: str | None = None, repo: str | None = None) -> list[dict]:
        """Stored users, optionally narrowed to an org and/or a repo name."""
        sql = "SELECT * FROM github_users"
        params: list = []
        where = []
        if org is not None:
            where.append("org = ?")
            params.append(org)
        if repo is not None:
            where.append("repo = ?")
            params.append(repo)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY org, repo, login"
        return [dict(r) for r in self._exec(sql, tuple(params)).fetchall()]

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

    # -- scan targets (explicitly-added repos) ------------------------------------

    def add_target(self, owner: str, repo: str, added_at: str = "") -> bool:
        """Register a repo to scan. Returns True if newly added, False if known."""
        cur = self._exec(
            f"{self._d.insert_ignore} targets (owner, repo, added_at) VALUES (?, ?, ?)",
            (owner, repo, added_at),
        )
        return cur.rowcount > 0

    def remove_target(self, owner: str, repo: str) -> bool:
        """Unregister a repo. Returns True if a row was deleted."""
        cur = self._exec(
            "DELETE FROM targets WHERE owner = ? AND repo = ?", (owner, repo)
        )
        return cur.rowcount > 0

    def list_targets(self) -> list[tuple[str, str]]:
        cur = self._exec("SELECT owner, repo FROM targets ORDER BY owner, repo")
        return [(r["owner"], r["repo"]) for r in cur.fetchall()]

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

    # -- statistics --------------------------------------------------------------
    # Aggregates are aliased (AS n) so rows read the same via sqlite3.Row and
    # MySQL DictCursor.

    def severity_counts(self) -> dict[str, int]:
        """Stored findings grouped by severity (lowercased), e.g. {'critical': 2}."""
        cur = self._exec("SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity")
        return {str(r["severity"]).lower(): r["n"] for r in cur.fetchall()}

    def status_counts(self) -> dict[str, int]:
        """Repos grouped by scan status, e.g. {'done': 5, 'failed': 1}."""
        cur = self._exec("SELECT status, COUNT(*) AS n FROM repos GROUP BY status")
        return {r["status"]: r["n"] for r in cur.fetchall()}

    def top_repos(self, limit: int = 10) -> list[RepoRecord]:
        """Repos ordered by total findings (then critical count) descending."""
        cur = self._exec(
            "SELECT * FROM repos ORDER BY total_findings DESC, critical_count DESC, "
            "owner, repo LIMIT ?",
            (limit,),
        )
        return [self._to_record(r) for r in cur.fetchall()]

    def issue_count(self) -> int:
        """Number of GitHub issues ever created (tracked for dedup)."""
        cur = self._exec("SELECT COUNT(*) AS n FROM issue_tracking")
        return cur.fetchone()["n"]

    def last_reviewed_at(self) -> str:
        """Most recent review timestamp (ISO strings sort lexically), '' if none."""
        cur = self._exec("SELECT MAX(reviewed_at) AS m FROM repos WHERE reviewed_at != ''")
        row = cur.fetchone()
        return row["m"] or "" if row else ""

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
            last_commit_sha=row["last_commit_sha"] or "",
            last_commit_date=row["last_commit_date"] or "",
        )
