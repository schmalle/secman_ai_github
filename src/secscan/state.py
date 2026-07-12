"""Resumable state manifest backed by SQLite or MySQL/MariaDB.

One row per repository in `repos`, keyed by (owner, repo). Lets long multi-repo runs
be interrupted and resumed, and lets `secscan report` rebuild summary.csv afterwards.

The backend is chosen from the target passed to `StateStore`: a `mysql://…` (or
`mariadb://…`) URL selects MySQL/MariaDB (via mysqlclient, the `mysql` extra);
anything else is a SQLite file path (the default).
"""

from __future__ import annotations

import sqlite3
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from .findings import Finding


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


@dataclass(frozen=True)
class _Dialect:
    placeholder: str
    insert_ignore: str
    schema: tuple[str, ...]


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


def _is_mysql(target: str | Path) -> bool:
    return isinstance(target, str) and target.startswith(("mysql://", "mariadb://"))


def _dialect_for(target: str | Path) -> _Dialect:
    return _MYSQL_DIALECT if _is_mysql(target) else _SQLITE_DIALECT


def _connect_sqlite(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
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
        self._d = _dialect_for(target)
        if _is_mysql(target):
            self._conn = _connect_mysql(str(target), user=db_user, password=db_password, ssl=db_ssl)
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
