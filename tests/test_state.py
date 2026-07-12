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
