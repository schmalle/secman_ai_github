import asyncio

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


def test_resolve_provider_env_upgrades_default_model_for_openrouter(monkeypatch, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-abc")
    cfg = RunConfig(model="sonnet", provider="auto")

    provider_env = orch._resolve_provider_env(cfg)

    assert provider_env.name == "openrouter"
    assert cfg.model == "anthropic/claude-sonnet-5"
    assert "hint" not in capsys.readouterr().out


def test_resolve_provider_env_leaves_anthropic_model_untouched(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    cfg = RunConfig(model="sonnet", provider="auto")

    provider_env = orch._resolve_provider_env(cfg)

    assert provider_env.name == "anthropic"
    assert cfg.model == "sonnet"


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


async def test_process_repo_forwards_timeout_to_review(tmp_path, monkeypatch):
    from secscan.reviewer import ReviewResult

    captured = {}

    async def fake_mint_token(auth, repo):
        return "tok"

    async def fake_clone(repo, token, root):
        return tmp_path / "clone"

    async def fake_review_repo(path, full_name, *, model, max_turns, max_cost_usd, extra_env, idle_timeout_s):
        captured["idle_timeout_s"] = idle_timeout_s
        return ReviewResult(repo_full_name=full_name)

    monkeypatch.setattr(orch, "_mint_token", fake_mint_token)
    monkeypatch.setattr(orch, "_clone", fake_clone)
    monkeypatch.setattr(orch, "review_repo", fake_review_repo)
    monkeypatch.setattr(orch, "cleanup", lambda path: None)

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3", timeout_s=42.0)
    store = StateStore(cfg.state_target)
    sem = asyncio.Semaphore(1)
    provider_env = orch.ProviderEnv(name="anthropic")

    await orch._process_repo(_repo(name="demo"), object(), store, cfg, sem, provider_env)

    assert captured["idle_timeout_s"] == 42.0


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
