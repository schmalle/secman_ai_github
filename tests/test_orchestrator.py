import asyncio

import pytest

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

    async def fake_clone(repo, token, root, branch=None):
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


async def test_process_repo_forwards_branch_to_clone(tmp_path, monkeypatch):
    from secscan.reviewer import ReviewResult

    captured = {}

    async def fake_mint_token(auth, repo):
        return "tok"

    async def fake_clone(repo, token, root, branch=None):
        captured["branch"] = branch
        return tmp_path / "clone"

    async def fake_review_repo(path, full_name, **kwargs):
        return ReviewResult(repo_full_name=full_name)

    monkeypatch.setattr(orch, "_mint_token", fake_mint_token)
    monkeypatch.setattr(orch, "_clone", fake_clone)
    monkeypatch.setattr(orch, "review_repo", fake_review_repo)
    monkeypatch.setattr(orch, "cleanup", lambda path: None)

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3", branch="dev")
    store = StateStore(cfg.state_target)
    sem = asyncio.Semaphore(1)
    provider_env = orch.ProviderEnv(name="anthropic")

    await orch._process_repo(_repo(name="demo"), object(), store, cfg, sem, provider_env)

    assert captured["branch"] == "dev"


async def test_process_repo_clone_defaults_to_no_branch(tmp_path, monkeypatch):
    from secscan.reviewer import ReviewResult

    captured = {}

    async def fake_mint_token(auth, repo):
        return "tok"

    async def fake_clone(repo, token, root, branch=None):
        captured["branch"] = branch
        return tmp_path / "clone"

    async def fake_review_repo(path, full_name, **kwargs):
        return ReviewResult(repo_full_name=full_name)

    monkeypatch.setattr(orch, "_mint_token", fake_mint_token)
    monkeypatch.setattr(orch, "_clone", fake_clone)
    monkeypatch.setattr(orch, "review_repo", fake_review_repo)
    monkeypatch.setattr(orch, "cleanup", lambda path: None)

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3")
    store = StateStore(cfg.state_target)
    sem = asyncio.Semaphore(1)
    provider_env = orch.ProviderEnv(name="anthropic")

    await orch._process_repo(_repo(name="demo"), object(), store, cfg, sem, provider_env)

    assert captured["branch"] is None


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


async def test_process_repo_skips_store_when_no_db(tmp_path, monkeypatch):
    from secscan.reviewer import ReviewResult

    async def fake_mint_token(auth, repo):
        return "tok"

    async def fake_clone(repo, token, root, branch=None):
        return tmp_path / "clone"

    async def fake_review_repo(path, full_name, *, model, max_turns, max_cost_usd, extra_env, idle_timeout_s):
        return ReviewResult(repo_full_name=full_name)

    monkeypatch.setattr(orch, "_mint_token", fake_mint_token)
    monkeypatch.setattr(orch, "_clone", fake_clone)
    monkeypatch.setattr(orch, "review_repo", fake_review_repo)
    monkeypatch.setattr(orch, "cleanup", lambda path: None)

    cfg = RunConfig(output_dir=tmp_path, no_db=True)
    sem = asyncio.Semaphore(1)
    provider_env = orch.ProviderEnv(name="anthropic")

    # store=None must not raise — this is the core assertion.
    await orch._process_repo(_repo(name="demo"), object(), None, cfg, sem, provider_env)

    assert (tmp_path / "octo__demo" / "findings.csv").exists()


async def _patch_clone_and_review(monkeypatch, tmp_path):
    """Stub out token minting, cloning and the review so _process_repo runs offline."""
    from secscan.reviewer import ReviewResult

    async def fake_mint_token(auth, repo):
        return "tok"

    async def fake_clone(repo, token, root, branch=None):
        return tmp_path / "clone"

    async def fake_review_repo(path, full_name, *, model, max_turns, max_cost_usd, extra_env, idle_timeout_s):
        return ReviewResult(repo_full_name=full_name)

    monkeypatch.setattr(orch, "_mint_token", fake_mint_token)
    monkeypatch.setattr(orch, "_clone", fake_clone)
    monkeypatch.setattr(orch, "review_repo", fake_review_repo)
    monkeypatch.setattr(orch, "cleanup", lambda path: None)


async def test_process_repo_records_head_commit_of_the_clone(tmp_path, monkeypatch):
    await _patch_clone_and_review(monkeypatch, tmp_path)

    async def fake_head_commit(path):
        return "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "2026-07-15"

    monkeypatch.setattr(orch, "head_commit", fake_head_commit)

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3")
    store = StateStore(cfg.state_target)
    await orch._process_repo(
        _repo(name="demo"), object(), store, cfg, asyncio.Semaphore(1),
        orch.ProviderEnv(name="anthropic"),
    )

    rec = store.get("octo", "demo")
    assert rec.last_commit_sha == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    assert rec.last_commit_date == "2026-07-15"


async def test_process_repo_unreadable_head_commit_does_not_fail_the_scan(tmp_path, monkeypatch):
    await _patch_clone_and_review(monkeypatch, tmp_path)

    async def fake_head_commit(path):
        return None

    monkeypatch.setattr(orch, "head_commit", fake_head_commit)

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3")
    store = StateStore(cfg.state_target)
    await orch._process_repo(
        _repo(name="demo"), object(), store, cfg, asyncio.Semaphore(1),
        orch.ProviderEnv(name="anthropic"),
    )

    rec = store.get("octo", "demo")
    assert rec.status == orch.Status.DONE  # review completed regardless
    assert rec.last_commit_sha == ""


async def test_run_scan_no_db_skips_summary_csv(tmp_path, monkeypatch, capsys):
    fake_app = _FakeApp()
    monkeypatch.setattr(orch, "build_auth", lambda: _FakeAuth(app=fake_app))

    async def fake_process_repo(repo, auth, store, cfg, sem, provider_env):
        pass

    monkeypatch.setattr(orch, "_process_repo", fake_process_repo)

    cfg = RunConfig(output_dir=tmp_path, no_db=True)
    await orch.run_scan(cfg, targets_only=True)

    assert not (tmp_path / "summary.csv").exists()
    assert "summary.csv skipped" in capsys.readouterr().out


@pytest.mark.parametrize(
    "prefix_kwargs, expected_title",
    [
        ({}, "secscan: high: SQLi (app.py)"),  # default prefix
        ({"issue_prefix": "[acme]"}, "[acme] high: SQLi (app.py)"),
    ],
)
async def test_process_repo_creates_issues_when_enabled(
    tmp_path, monkeypatch, prefix_kwargs, expected_title
):
    from secscan.findings import Finding
    from secscan.reviewer import ReviewResult
    import secscan.orchestrator as orch_module

    async def fake_mint_token(auth, repo):
        return "tok"

    async def fake_clone(repo, token, root, branch=None):
        return tmp_path / "clone"

    finding = Finding(severity="high", title="SQLi", description="d", file_path="app.py")

    async def fake_review_repo(path, full_name, *, model, max_turns, max_cost_usd, extra_env, idle_timeout_s):
        return ReviewResult(repo_full_name=full_name, high_critical=[finding], findings=[finding])

    created_calls = []

    class _FakeGhRepo:
        def create_issue(self, title, body, labels):
            created_calls.append(title)
            class _I:
                number = 1
                html_url = "https://github.com/octo/demo/issues/1"
            return _I()

    class _FakeGithubClient:
        def get_repo(self, full_name):
            return _FakeGhRepo()

    monkeypatch.setattr(orch, "_mint_token", fake_mint_token)
    monkeypatch.setattr(orch, "_clone", fake_clone)
    monkeypatch.setattr(orch, "review_repo", fake_review_repo)
    monkeypatch.setattr(orch, "cleanup", lambda path: None)
    monkeypatch.setattr(orch_module, "Github", lambda auth: _FakeGithubClient())

    cfg = RunConfig(
        output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3", create_issues=True,
        **prefix_kwargs,
    )
    store = StateStore(cfg.state_target)
    sem = asyncio.Semaphore(1)
    provider_env = orch.ProviderEnv(name="anthropic")

    class _FakeAuthCtx:
        def token_for(self, repo):
            return "tok"

    await orch._process_repo(_repo(name="demo"), _FakeAuthCtx(), store, cfg, sem, provider_env)

    assert created_calls == [expected_title]


async def test_process_repo_dry_run_creates_no_github_client(tmp_path, monkeypatch):
    """--create-issues --dry-run must make zero GitHub API calls: Github() itself
    must never be constructed.

    Note: _process_repo catches all exceptions internally (records a failure and
    keeps going), so a stub that merely *raises* if called would be swallowed and
    this test would pass even on unfixed code. Instead we track invocations and
    assert the counter stayed at zero.
    """
    from secscan.findings import Finding
    from secscan.reviewer import ReviewResult
    import secscan.orchestrator as orch_module

    async def fake_mint_token(auth, repo):
        return "tok"

    async def fake_clone(repo, token, root, branch=None):
        return tmp_path / "clone"

    finding = Finding(severity="high", title="SQLi", description="d", file_path="app.py")

    async def fake_review_repo(path, full_name, *, model, max_turns, max_cost_usd, extra_env, idle_timeout_s):
        return ReviewResult(repo_full_name=full_name, high_critical=[finding], findings=[finding])

    github_calls = []

    def _tracking_github(*args, **kwargs):
        github_calls.append((args, kwargs))
        raise AssertionError("Github() must not be constructed during --dry-run")

    monkeypatch.setattr(orch, "_mint_token", fake_mint_token)
    monkeypatch.setattr(orch, "_clone", fake_clone)
    monkeypatch.setattr(orch, "review_repo", fake_review_repo)
    monkeypatch.setattr(orch, "cleanup", lambda path: None)
    monkeypatch.setattr(orch_module, "Github", _tracking_github)

    cfg = RunConfig(
        output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3",
        create_issues=True, dry_run=True,
    )
    store = StateStore(cfg.state_target)
    sem = asyncio.Semaphore(1)
    provider_env = orch.ProviderEnv(name="anthropic")

    class _FakeAuthCtx:
        def token_for(self, repo):
            return "tok"

    await orch._process_repo(_repo(name="demo"), _FakeAuthCtx(), store, cfg, sem, provider_env)

    assert github_calls == []
    # Confirm the repo was still processed successfully (not silently swallowed
    # as a failure) — dry-run issue handling must run to completion.
    rec = store.get("octo", "demo")
    assert rec is not None
    assert rec.status.value == "done"


# -- auto-email after scan -------------------------------------------------------


def _email_cfg(tmp_path, **kw):
    return RunConfig(
        output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3",
        email_to=["sec@example.com"], **kw,
    )


async def _run_targets_only(monkeypatch, cfg, per_repo_result):
    """Run run_scan in targets-only mode with one seeded target and a fake reviewer."""
    monkeypatch.setattr(orch, "build_auth", lambda: _FakeAuth(app=None))

    async def fake_process_repo(repo, auth, store, cfg, sem, provider_env):
        return per_repo_result

    monkeypatch.setattr(orch, "_process_repo", fake_process_repo)

    store = StateStore(cfg.state_target)
    store.add_target("octo", "demo")
    store.close()

    await orch.run_scan(cfg, targets_only=True)


async def test_run_scan_emails_when_high_critical_found(tmp_path, monkeypatch):
    sent = {}

    def fake_send(store, email_to, **kwargs):
        sent["to"] = email_to
        sent["kwargs"] = kwargs
        return (1, 1)

    monkeypatch.setattr(orch, "send_scan_report", fake_send)

    cfg = _email_cfg(tmp_path, email_provider="gmail", email_subject="s")
    await _run_targets_only(monkeypatch, cfg, per_repo_result=(1, 0))

    assert sent["to"] == ["sec@example.com"]
    assert sent["kwargs"]["provider"] == "gmail"
    assert sent["kwargs"]["subject"] == "s"


async def test_run_scan_skips_email_when_clean(tmp_path, monkeypatch, capsys):
    called = []
    monkeypatch.setattr(orch, "send_scan_report", lambda *a, **kw: called.append(1))

    cfg = _email_cfg(tmp_path)
    await _run_targets_only(monkeypatch, cfg, per_repo_result=(0, 0))

    assert called == []
    assert "email report skipped" in capsys.readouterr().out


async def test_run_scan_email_failure_does_not_fail_run(tmp_path, monkeypatch, capsys):
    def boom(*a, **kw):
        raise RuntimeError("smtp down")

    monkeypatch.setattr(orch, "send_scan_report", boom)

    cfg = _email_cfg(tmp_path)
    await _run_targets_only(monkeypatch, cfg, per_repo_result=(0, 1))  # must not raise

    captured = capsys.readouterr()
    assert "failed to send email report" in captured.err
    assert "smtp down" in captured.err


async def test_run_scan_no_email_flag_never_sends(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(orch, "send_scan_report", lambda *a, **kw: called.append(1))

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3")
    await _run_targets_only(monkeypatch, cfg, per_repo_result=(3, 3))

    assert called == []


async def test_scan_repo_emails_when_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(orch, "build_auth", lambda: _FakeAuth(app=None, pat=None))

    async def fake_process_repo(repo, auth, store, cfg, sem, provider_env):
        return (1, 2)

    monkeypatch.setattr(orch, "_process_repo", fake_process_repo)
    sent = {}
    monkeypatch.setattr(
        orch, "send_scan_report",
        lambda store, email_to, **kw: sent.update(to=email_to) or (1, 3),
    )

    cfg = _email_cfg(tmp_path)
    await orch.scan_repo(cfg, "octo", "demo")

    assert sent["to"] == ["sec@example.com"]


# -- review (local dir) ----------------------------------------------------------


def _local_repo_dir(tmp_path):
    d = tmp_path / "demo-app"
    d.mkdir()
    return d


def _patch_local_review(monkeypatch, result):
    async def fake_review_repo(path, full_name, *, model, max_turns, max_cost_usd, extra_env, idle_timeout_s):
        return result

    monkeypatch.setattr(orch, "review_repo", fake_review_repo)

    async def fake_head_commit(path):
        return None

    monkeypatch.setattr(orch, "head_commit", fake_head_commit)


async def test_review_local_without_store_db_writes_no_state(tmp_path, monkeypatch):
    from secscan.reviewer import ReviewResult

    repo_dir = _local_repo_dir(tmp_path)
    _patch_local_review(monkeypatch, ReviewResult(repo_full_name="local/demo-app"))

    out = tmp_path / "out"
    cfg = RunConfig(output_dir=out, state_db=out / "secscan.sqlite3", no_db=True)
    await orch.review_local(cfg, repo_dir)

    assert (out / "local__demo-app" / "findings.csv").exists()
    assert not (out / "secscan.sqlite3").exists()  # default stays CSV-only
    assert not (out / "summary.csv").exists()


async def test_review_local_store_db_records_result_and_findings(tmp_path, monkeypatch):
    from secscan.findings import Finding
    from secscan.reviewer import ReviewResult

    repo_dir = _local_repo_dir(tmp_path)
    finding = Finding(severity="high", title="SQLi", description="d", file_path="app.py")
    _patch_local_review(monkeypatch, ReviewResult(
        repo_full_name="local/demo-app",
        findings=[finding], high_critical=[finding],
        critical_count=0, high_count=1, total_findings=1,
        duration_s=2.0, cost_usd=0.05,
    ))

    out = tmp_path / "out"
    cfg = RunConfig(output_dir=out, state_db=out / "secscan.sqlite3", no_db=False)
    await orch.review_local(cfg, repo_dir)

    store = StateStore(cfg.state_target)
    rec = store.get("local", "demo-app")
    assert rec is not None
    assert rec.status == orch.Status.DONE
    assert (rec.high_count, rec.critical_count, rec.total_findings) == (1, 0, 1)
    assert rec.cost_usd == 0.05
    assert rec.reviewed_at
    rows = store.get_findings("local", "demo-app")
    assert [r["title"] for r in rows] == ["SQLi"]
    assert (out / "summary.csv").exists()


async def test_review_local_store_db_records_failure(tmp_path, monkeypatch):
    from secscan.reviewer import ReviewResult

    repo_dir = _local_repo_dir(tmp_path)
    _patch_local_review(monkeypatch, ReviewResult(
        repo_full_name="local/demo-app", error="model returned no JSON",
    ))

    out = tmp_path / "out"
    cfg = RunConfig(output_dir=out, state_db=out / "secscan.sqlite3", no_db=False)
    await orch.review_local(cfg, repo_dir)

    rec = StateStore(cfg.state_target).get("local", "demo-app")
    assert rec.status == orch.Status.FAILED
    assert "no JSON" in rec.error


async def test_review_local_store_db_records_head_commit(tmp_path, monkeypatch):
    from secscan.reviewer import ReviewResult

    repo_dir = _local_repo_dir(tmp_path)
    _patch_local_review(monkeypatch, ReviewResult(repo_full_name="local/demo-app"))

    async def fake_head_commit(path):
        assert path.name == "demo-app"  # the reviewed dir, not the output dir
        return "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "2026-08-01"

    monkeypatch.setattr(orch, "head_commit", fake_head_commit)

    out = tmp_path / "out"
    cfg = RunConfig(output_dir=out, state_db=out / "secscan.sqlite3", no_db=False)
    await orch.review_local(cfg, repo_dir)

    rec = StateStore(cfg.state_target).get("local", "demo-app")
    assert rec.last_commit_sha == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    assert rec.last_commit_date == "2026-08-01"
