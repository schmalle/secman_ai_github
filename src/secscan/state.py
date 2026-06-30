"""Resumable state manifest backed by SQLite.

One row per repository, keyed by (owner, repo). Lets long multi-repo runs be
interrupted and resumed, and lets `secscan report` rebuild summary.csv afterwards.
"""

from __future__ import annotations

import sqlite3
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


_SCHEMA = """
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


class StateStore:
    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- writes -----------------------------------------------------------------

    def upsert_pending(self, owner: str, repo: str) -> None:
        """Insert a pending row if the repo is unknown; never downgrade an existing one."""
        self._conn.execute(
            "INSERT OR IGNORE INTO repos (owner, repo, status) VALUES (?, ?, ?)",
            (owner, repo, Status.PENDING.value),
        )
        self._conn.commit()

    def mark(self, owner: str, repo: str, status: Status, **fields) -> None:
        self.upsert_pending(owner, repo)
        cols = ["status"]
        vals: list = [status.value]
        for key, value in fields.items():
            cols.append(key)
            vals.append(value)
        assignments = ", ".join(f"{c} = ?" for c in cols)
        vals.extend([owner, repo])
        self._conn.execute(
            f"UPDATE repos SET {assignments} WHERE owner = ? AND repo = ?", vals
        )
        self._conn.commit()

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
        row = self._conn.execute(
            "SELECT * FROM repos WHERE owner = ? AND repo = ?", (owner, repo)
        ).fetchone()
        return self._to_record(row) if row else None

    def is_done(self, owner: str, repo: str) -> bool:
        rec = self.get(owner, repo)
        return rec is not None and rec.status == Status.DONE

    def all_records(self) -> list[RepoRecord]:
        rows = self._conn.execute(
            "SELECT * FROM repos ORDER BY owner, repo"
        ).fetchall()
        return [self._to_record(r) for r in rows]

    @staticmethod
    def _to_record(row: sqlite3.Row) -> RepoRecord:
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
            error=row["error"],
        )
