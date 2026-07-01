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
