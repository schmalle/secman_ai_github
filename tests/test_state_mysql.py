"""MySQL/MariaDB integration tests, gated behind SECSCAN_TEST_MYSQL_URL.

Run against a throwaway server, e.g.:

    docker run --rm -e MARIADB_ROOT_PASSWORD=pw -e MARIADB_DATABASE=secscan_test \
        -p 3306:3306 mariadb
    SECSCAN_TEST_MYSQL_URL=mysql://root:pw@127.0.0.1:3306/secscan_test \
        uv run pytest tests/test_state_mysql.py -v

The same URL works for MySQL and MariaDB (both use the mysqlclient driver).
Requires the `mysql` extra: `uv sync --extra mysql`.
"""

import os

import pytest

from secscan.findings import Finding
from secscan.state import StateStore, Status, _dialect_for, _MYSQL_DIALECT

MYSQL_URL = os.environ.get("SECSCAN_TEST_MYSQL_URL")


def test_mariadb_scheme_selects_mysql_dialect():
    # Not gated: pure dialect selection, no server needed.
    assert _dialect_for("mariadb://user:pass@host:3306/secscan") is _MYSQL_DIALECT


pytestmark_live = pytest.mark.skipif(
    not MYSQL_URL, reason="set SECSCAN_TEST_MYSQL_URL to run MySQL integration tests"
)


@pytest.fixture
def store():
    s = StateStore(MYSQL_URL)
    # clean slate for a deterministic test
    cur = s._conn.cursor()
    cur.execute("DELETE FROM findings")
    cur.execute("DELETE FROM targets")
    cur.execute("DELETE FROM repos")
    s._conn.commit()
    yield s
    s.close()


@pytestmark_live
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


@pytestmark_live
def test_mysql_findings_replace(store):
    f = Finding(severity="critical", title="sqli", description="d")
    store.replace_findings("octo", "repo", [f])
    store.replace_findings(
        "octo", "repo", [f, Finding(severity="high", title="xss", description="d")]
    )
    rows = store.get_findings("octo", "repo")
    assert {r["title"] for r in rows} == {"sqli", "xss"}


@pytestmark_live
def test_mysql_targets_round_trip(store):
    assert store.add_target("octo", "repo", "2026-07-01T00:00:00+00:00")
    assert not store.add_target("octo", "repo")  # idempotent
    assert store.list_targets() == [("octo", "repo")]
    assert store.remove_target("octo", "repo")
    assert store.list_targets() == []
