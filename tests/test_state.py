import sqlite3

from secscan.findings import Finding
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


def test_upsert_and_get(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.upsert_pending("octo", "repo")
    rec = store.get("octo", "repo")
    assert rec is not None
    assert rec.status == Status.PENDING
    assert rec.full_name == "octo/repo"


def test_upsert_is_idempotent_and_preserves_status(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.upsert_pending("octo", "repo")
    store.mark("octo", "repo", Status.REVIEWING)
    store.upsert_pending("octo", "repo")  # must not reset to pending
    assert store.get("octo", "repo").status == Status.REVIEWING


def test_record_result_marks_done_with_counts(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.upsert_pending("octo", "repo")
    store.record_result(
        "octo", "repo",
        critical=2, high=3, total=5,
        duration_s=10.0, cost_usd=0.5, reviewed_at="2026-06-30T00:00:00Z",
    )
    rec = store.get("octo", "repo")
    assert rec.status == Status.DONE
    assert rec.critical_count == 2
    assert rec.high_count == 3
    assert rec.total_findings == 5
    assert rec.cost_usd == 0.5
    assert store.is_done("octo", "repo")


def test_record_last_commit_round_trip(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.record_last_commit("octo", "repo", "a1b2c3d4e5f6", "2026-07-15")
    rec = store.get("octo", "repo")
    assert rec.last_commit_sha == "a1b2c3d4e5f6"
    assert rec.last_commit_date == "2026-07-15"


def test_record_last_commit_creates_pending_row_for_unknown_repo(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.record_last_commit("octo", "unseen", "a1b2c3d4e5f6", "2026-07-15")
    assert store.get("octo", "unseen").status == Status.PENDING


def test_record_last_commit_preserves_scan_status_and_counts(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.record_result(
        "octo", "repo",
        critical=2, high=3, total=5,
        duration_s=10.0, cost_usd=0.5, reviewed_at="2026-06-30T00:00:00Z",
    )
    store.record_last_commit("octo", "repo", "a1b2c3d4e5f6", "2026-07-15")
    rec = store.get("octo", "repo")
    assert rec.status == Status.DONE  # listing a repo is not scanning it
    assert rec.critical_count == 2
    assert rec.reviewed_at == "2026-06-30T00:00:00Z"


_LEGACY_REPOS_SQLITE = """
CREATE TABLE repos (
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


def _legacy_db(path):
    """A database created before the last_commit columns existed."""
    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute(_LEGACY_REPOS_SQLITE)
    conn.execute("INSERT INTO repos (owner, repo, status) VALUES ('octo', 'old', 'done')")
    conn.commit()
    conn.close()


def test_opening_legacy_db_adds_last_commit_columns(tmp_path):
    db = tmp_path / "legacy.sqlite3"
    _legacy_db(db)
    store = StateStore(db)
    store.record_last_commit("octo", "old", "a1b2c3d4e5f6", "2026-07-15")
    rec = store.get("octo", "old")
    assert rec.last_commit_sha == "a1b2c3d4e5f6"
    assert rec.status == Status.DONE  # the pre-existing row survived the migration


def test_migration_is_idempotent_across_instances(tmp_path):
    db = tmp_path / "legacy.sqlite3"
    _legacy_db(db)
    StateStore(db).record_last_commit("octo", "old", "a1b2c3d4e5f6", "2026-07-15")
    assert StateStore(db).get("octo", "old").last_commit_date == "2026-07-15"


def test_record_failure(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.upsert_pending("octo", "repo")
    store.record_failure("octo", "repo", "clone failed")
    rec = store.get("octo", "repo")
    assert rec.status == Status.FAILED
    assert rec.error == "clone failed"
    assert not store.is_done("octo", "repo")


def test_is_done_false_for_unknown(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    assert not store.is_done("nope", "nope")


def test_all_records_sorted(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.upsert_pending("b", "two")
    store.upsert_pending("a", "one")
    names = [r.full_name for r in store.all_records()]
    assert names == ["a/one", "b/two"]


def test_persistence_across_instances(tmp_path):
    db = tmp_path / "s.sqlite3"
    StateStore(db).upsert_pending("octo", "repo")
    assert StateStore(db).get("octo", "repo") is not None


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


def test_replace_findings_scoped_to_repo(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.replace_findings("octo", "one", [_f("high", "keep")])
    store.replace_findings("octo", "two", [_f("critical", "other")])
    store.replace_findings("octo", "two", [])
    assert [r["title"] for r in store.get_findings("octo", "one")] == ["keep"]


def test_add_target_round_trip(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    assert store.add_target("octo", "repo", "2026-07-01T00:00:00+00:00") is True
    assert store.list_targets() == [("octo", "repo")]


def test_add_target_idempotent_returns_false_second_time(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    assert store.add_target("octo", "repo") is True
    assert store.add_target("octo", "repo") is False
    assert store.list_targets() == [("octo", "repo")]


def test_remove_target_true_then_false(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.add_target("octo", "repo")
    assert store.remove_target("octo", "repo") is True
    assert store.remove_target("octo", "repo") is False
    assert store.list_targets() == []


def test_list_targets_sorted(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.add_target("b", "two")
    store.add_target("a", "one")
    assert store.list_targets() == [("a", "one"), ("b", "two")]


def test_repo_record_is_dataclass_usable_for_summary():
    import dataclasses

    rec = RepoRecord(owner="octo", repo="repo", status=Status.DONE)
    d = dataclasses.asdict(rec)
    assert d["owner"] == "octo"


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


def test_active_conn_is_shared_connection_for_sqlite_across_threads(tmp_path):
    import threading

    store = StateStore(tmp_path / "s.sqlite3")
    results = {}

    def worker():
        results["conn"] = store._active_conn
        store.upsert_pending("octo", "from-thread")

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    assert results["conn"] is store._conn
    assert store.get("octo", "from-thread") is not None


def test_active_conn_opens_one_mysql_connection_per_thread(monkeypatch):
    import threading

    from secscan import state as state_module

    created = []

    class _FakeCursor:
        def execute(self, *a, **kw):
            pass

        def fetchall(self):
            return []

        def fetchone(self):
            return None

    class _FakeConn:
        def __init__(self):
            created.append(self)

        def cursor(self):
            return _FakeCursor()

        def commit(self):
            pass

        def close(self):
            pass

    def fake_connect_mysql(url, *, user=None, password=None, ssl=False):
        return _FakeConn()

    monkeypatch.setattr(state_module, "_connect_mysql", fake_connect_mysql)

    store = state_module.StateStore("mysql://u:p@h/db")
    assert store._active_conn is store._conn  # main thread reuses the __init__ connection

    results = {}

    def worker():
        results["conn1"] = store._active_conn
        results["conn2"] = store._active_conn  # same thread, second call — must be cached

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    assert results["conn1"] is not store._conn  # worker thread got its own connection
    assert results["conn1"] is results["conn2"]  # cached within that thread
    assert len(created) == 2  # one for __init__ (main thread), one for the worker thread


# -- statistics queries ----------------------------------------------------------


def _seed_stats(store: StateStore) -> None:
    store.record_result(
        "octo", "big",
        critical=2, high=1, total=5,
        duration_s=10.0, cost_usd=0.50, reviewed_at="2026-07-02T00:00:00+00:00",
    )
    store.replace_findings(
        "octo", "big",
        [
            Finding(severity="critical", title="SQLi", description="d"),
            Finding(severity="critical", title="RCE", description="d"),
            Finding(severity="high", title="XSS", description="d"),
            Finding(severity="medium", title="CSRF", description="d"),
            Finding(severity="low", title="Info leak", description="d"),
        ],
    )
    store.record_result(
        "octo", "small",
        critical=0, high=1, total=1,
        duration_s=5.0, cost_usd=0.25, reviewed_at="2026-07-01T00:00:00+00:00",
    )
    store.replace_findings(
        "octo", "small", [Finding(severity="high", title="XXE", description="d")]
    )
    store.record_failure("octo", "broken", "clone failed")
    store.record_issue_created(
        "octo", "big", "fp1", 7, "https://github.com/octo/big/issues/7", "now"
    )


def test_severity_counts_groups_all_severities(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    _seed_stats(store)
    assert store.severity_counts() == {"critical": 2, "high": 2, "medium": 1, "low": 1}


def test_severity_counts_empty_db(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    assert store.severity_counts() == {}


def test_status_counts(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    _seed_stats(store)
    assert store.status_counts() == {"done": 2, "failed": 1}


def test_top_repos_ordered_by_findings_and_limited(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    _seed_stats(store)
    top = store.top_repos(limit=2)
    assert [r.full_name for r in top] == ["octo/big", "octo/small"]
    assert store.top_repos(limit=1)[0].full_name == "octo/big"


def test_issue_count(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    assert store.issue_count() == 0
    _seed_stats(store)
    assert store.issue_count() == 1


def test_last_reviewed_at_picks_latest(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    _seed_stats(store)
    assert store.last_reviewed_at() == "2026-07-02T00:00:00+00:00"


def test_last_reviewed_at_empty_db(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    assert store.last_reviewed_at() == ""


def test_clear_stats_empties_repos_and_findings(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    _seed_stats(store)

    repos_deleted, findings_deleted = store.clear_stats()

    assert (repos_deleted, findings_deleted) == (3, 6)
    assert store.all_records() == []
    assert store.severity_counts() == {}
    assert store.last_reviewed_at() == ""


def test_clear_stats_keeps_targets_and_issue_tracking(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    _seed_stats(store)
    store.add_target("octo", "big")

    store.clear_stats()

    assert store.list_targets() == [("octo", "big")]
    assert store.find_issue("octo", "big", "fp1") is not None
    assert store.issue_count() == 1


def test_clear_stats_on_empty_db_is_a_no_op(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    assert store.clear_stats() == (0, 0)


# -- github_users -----------------------------------------------------------------


def _github_user(login, org="acme", repo="", **kw):
    from secscan.github_users import GithubUser

    defaults = dict(
        user_id=1, name="", email="", user_type="User", site_admin=False,
        source="repo" if repo else "org", role="member", html_url="",
    )
    defaults.update(kw)
    return GithubUser(login=login, org=org, repo=repo, **defaults)


def test_replace_users_round_trips(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.replace_users(
        "acme", "",
        [_github_user("alice", role="admin", site_admin=True), _github_user("bob")],
        seen_at="2026-08-09T00:00:00+00:00",
    )

    rows = store.get_users()

    assert [(r["login"], r["role"], r["source"]) for r in rows] == [
        ("alice", "admin", "org"),
        ("bob", "member", "org"),
    ]
    assert rows[0]["site_admin"] == 1
    assert rows[0]["seen_at"] == "2026-08-09T00:00:00+00:00"
    store.close()


def test_replace_users_drops_departed_members_within_the_scope(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.replace_users("acme", "", [_github_user("alice"), _github_user("bob")])

    store.replace_users("acme", "", [_github_user("alice")])

    assert [r["login"] for r in store.get_users()] == ["alice"]
    store.close()


def test_replace_users_leaves_other_scopes_alone(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.replace_users("acme", "", [_github_user("alice")])
    store.replace_users("acme", "webapp", [_github_user("bob", repo="webapp", role="write")])

    store.replace_users("acme", "", [])  # the org listing emptied

    assert [(r["repo"], r["login"]) for r in store.get_users()] == [("webapp", "bob")]
    store.close()


def test_get_users_filters_by_org_and_repo(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    store.replace_users("acme", "", [_github_user("alice")])
    store.replace_users("acme", "webapp", [_github_user("bob", repo="webapp")])
    store.replace_users("other", "", [_github_user("carol", org="other")])

    assert [r["login"] for r in store.get_users(org="acme")] == ["alice", "bob"]
    assert [r["login"] for r in store.get_users(org="acme", repo="webapp")] == ["bob"]
    assert [r["login"] for r in store.get_users(org="nobody")] == []
    store.close()


def test_github_users_table_is_created_on_a_pre_existing_database(tmp_path):
    """A database from before this feature must gain the table, not error on first use."""
    db = tmp_path / "s.sqlite3"
    StateStore(db).close()
    sqlite3.connect(db).execute("DROP TABLE github_users").connection.commit()

    store = StateStore(db)

    assert store.get_users() == []
    store.close()
