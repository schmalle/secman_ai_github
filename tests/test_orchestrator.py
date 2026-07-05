import secscan.orchestrator as orch
from secscan.config import RunConfig
from secscan.github_app import RepoInfo
from secscan.orchestrator import _merge_scope
from secscan.state import StateStore


def _repo(owner="octo", name="repo", installation_id=1):
    return RepoInfo(
        owner=owner,
        name=name,
        full_name=f"{owner}/{name}",
        archived=False,
        fork=False,
        size_kb=100,
        default_branch="main",
        clone_url=f"https://github.com/{owner}/{name}.git",
        installation_id=installation_id,
    )


def test_merge_scope_no_allowlist_no_targets():
    repos = [_repo(name="a"), _repo(name="b")]
    in_scope, unresolved = _merge_scope(repos, None, [])
    assert in_scope == repos
    assert unresolved == []


def test_merge_scope_allowlist_filters_enumerated():
    repos = [_repo(name="keep"), _repo(name="drop")]
    in_scope, unresolved = _merge_scope(repos, {"octo/keep"}, [])
    assert [r.full_name for r in in_scope] == ["octo/keep"]
    assert unresolved == []


def test_merge_scope_targets_add_unresolved():
    repos = [_repo(name="a")]
    in_scope, unresolved = _merge_scope(repos, None, [("other", "explicit")])
    assert in_scope == repos
    assert unresolved == [("other", "explicit")]


def test_merge_scope_enumerated_target_not_duplicated():
    repos = [_repo(name="a")]
    in_scope, unresolved = _merge_scope(repos, None, [("octo", "a")])
    assert in_scope == repos
    assert unresolved == []


def test_merge_scope_allowlist_entry_not_enumerated_goes_unresolved():
    in_scope, unresolved = _merge_scope([], {"octo/wanted"}, [])
    assert in_scope == []
    assert unresolved == [("octo", "wanted")]


def test_merge_scope_target_and_allowlist_deduped():
    in_scope, unresolved = _merge_scope([], {"octo/one"}, [("octo", "one")])
    assert unresolved == [("octo", "one")]


class _FakeApp:
    def __init__(self):
        self.iter_called = False

    def iter_repositories(self, org=None, filters=None):
        self.iter_called = True
        return iter([])


class _FakeAuth:
    def __init__(self, app=None, pat=None):
        self.app = app
        self.pat = pat


async def test_run_scan_targets_only_skips_enumeration(tmp_path, monkeypatch):
    fake_app = _FakeApp()
    monkeypatch.setattr(orch, "build_auth", lambda: _FakeAuth(app=fake_app))

    processed = []

    async def fake_process_repo(repo, auth, store, cfg, sem, provider_env):
        processed.append(repo.full_name)

    monkeypatch.setattr(orch, "_process_repo", fake_process_repo)

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3")
    store = StateStore(cfg.state_target)
    store.add_target("octo", "demo")
    store.close()

    await orch.run_scan(cfg, targets_only=True)

    assert fake_app.iter_called is False
    assert processed == ["octo/demo"]


async def test_scan_repo_processes_single_repo_and_writes_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(orch, "build_auth", lambda: _FakeAuth(app=None, pat=None))

    calls = []

    async def fake_process_repo(repo, auth, store, cfg, sem, provider_env):
        calls.append(repo.full_name)
        store.record_result(
            repo.owner, repo.name,
            critical=1, high=0, total=1,
            duration_s=1.0, cost_usd=0.01, reviewed_at="now",
        )

    monkeypatch.setattr(orch, "_process_repo", fake_process_repo)

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3")

    await orch.scan_repo(cfg, "octo", "demo")

    assert calls == ["octo/demo"]
    assert (tmp_path / "summary.csv").exists()

    store = StateStore(cfg.state_target)
    record = store.get("octo", "demo")
    assert record is not None
    assert record.critical_count == 1
