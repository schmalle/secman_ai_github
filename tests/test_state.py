from secscan.state import RepoRecord, StateStore, Status


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


def test_repo_record_is_dataclass_usable_for_summary():
    import dataclasses

    rec = RepoRecord(owner="octo", repo="repo", status=Status.DONE)
    d = dataclasses.asdict(rec)
    assert d["owner"] == "octo"
