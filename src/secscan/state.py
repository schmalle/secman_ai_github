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
