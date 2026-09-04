"""Unit tests for fix pull requests (secscan/pull_requests.py): remote parsing, PR
text, dedup, dry-run, and the guarded push/create path — with git pushes faked."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from secscan import dryrun, fixer, pull_requests
from secscan.config import GithubHost
from secscan.findings import Finding
from secscan.fixer import FixResult
from secscan.github_app import RepoInfo
from secscan.state import StateStore


def _finding(**overrides):
    defaults = dict(
        severity="high", title="SQL injection", description="concat", file_path="app.py",
        line_range="3", category="CWE-89", recommendation="parameterize",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _repo(clone_url="https://github.com/octo/demo.git"):
    return RepoInfo(
        owner="octo", name="demo", full_name="octo/demo", archived=False, fork=False,
        size_kb=1, default_branch="main", clone_url=clone_url, installation_id=1,
    )


class _FakePr:
    number = 7
    html_url = "https://github.com/octo/demo/pull/7"


class _FakeGhRepo:
    def __init__(self):
        self.calls = []

    def create_pull(self, **kwargs):
        self.calls.append(kwargs)
        return _FakePr()


def _git(*args, cwd):
    subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True,
        env={**fixer.GIT_IDENTITY, "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(cwd)},
    )


async def _workspace(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    _git("init", "-q", "-b", "main", cwd=src)
    (src / "app.py").write_text("bad\n")
    _git("add", "-A", cwd=src)
    _git("commit", "-q", "-m", "init", cwd=src)
    ws = await fixer.prepare_workspace(src, tmp_path / "work", "demo")
    (ws / "app.py").write_text("good\n")
    return ws


async def _result(tmp_path: Path, findings=None) -> FixResult:
    ws = await _workspace(tmp_path)
    patch, files = await fixer.diff_workspace(ws)
    return FixResult(
        patch=patch, changed_files=files, findings=findings or [_finding()], workspace=ws,
        summary={"fixes": [{"title": "SQL injection", "status": "fixed", "summary": "parameterized"}]},
    )


# --- remote parsing --------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/octo/demo.git",
        "https://github.com/octo/demo",
        "https://user@github.com/octo/demo/",
        "git@github.com:octo/demo.git",
        "ssh://git@github.com/octo/demo.git",
    ],
)
def test_parse_github_remote_accepts_common_forms(url):
    assert pull_requests.parse_github_remote(url, GithubHost()) == ("octo", "demo")


def test_parse_github_remote_rejects_other_hosts_and_shapes():
    host = GithubHost()
    assert pull_requests.parse_github_remote("https://gitlab.com/octo/demo.git", host) is None
    assert pull_requests.parse_github_remote("https://github.com/octo", host) is None
    assert pull_requests.parse_github_remote("", host) is None
    ghes = GithubHost(api_url="https://ghes.example.com/api/v3", web_url="https://ghes.example.com")
    assert pull_requests.parse_github_remote("git@ghes.example.com:octo/demo.git", ghes) == ("octo", "demo")
    assert pull_requests.parse_github_remote("git@github.com:octo/demo.git", ghes) is None


# --- text ----------------------------------------------------------------------------


def test_pr_title_and_body():
    findings = [_finding(), _finding(severity="critical", title="Hardcoded AWS key", file_path="cfg.py")]
    assert pull_requests.pr_title(findings, "secscan:") == "secscan: fix 1 critical and 1 high security findings"
    assert pull_requests.pr_title(findings[:1], "") == "fix high: SQL injection"
    result = FixResult(findings=findings, changed_files=["app.py"], summary={"fixes": [
        {"title": "SQL injection", "status": "fixed", "summary": "parameterized"},
    ]})
    body = pull_requests.pr_body(findings, result, "k" * 64)
    assert "could not run this project's build or tests" in body
    assert "**high** — SQL injection (`app.py`, 3) — _fixed_: parameterized" in body
    assert "Hardcoded AWS key" in body and "_see diff_" in body
    assert "`app.py`" in body and ("k" * 64) in body


def test_pr_text_truncates_llm_authored_fields():
    long = _finding(title="T" * 500, file_path="f" * 500)
    assert len(pull_requests.pr_title([long], "")) < 200
    body = pull_requests.pr_body([long], FixResult(findings=[long]), "k")
    assert "T" * 200 not in body and "f" * 200 not in body


# --- create_fix_pr -----------------------------------------------------------------------


async def test_dry_run_makes_no_push_and_no_api_call(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "s.sqlite3")
    result = await _result(tmp_path)

    async def explode(*a, **k):
        raise AssertionError("push must never happen in a dry run")

    monkeypatch.setattr(pull_requests, "push_fix_branch", explode)
    dryrun.activate()
    outcome = await pull_requests.create_fix_pr(
        workspace=result.workspace, repo=_repo(), base_branch="main", token="t", store=store,
        result=result, dry_run=True, gh_repo_factory=lambda: (_ for _ in ()).throw(AssertionError("no API")),
    )
    assert outcome.action == "would_create"
    assert outcome.branch.startswith("secscan/fix-")
    assert store.fix_pr_count() == 0


async def test_existing_ledger_entry_skips(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    result = await _result(tmp_path)
    store.record_fix_pr("octo", "demo", result.fix_key, 3, "https://github.com/octo/demo/pull/3", "secscan/fix-x", "now")
    outcome = await pull_requests.create_fix_pr(
        workspace=result.workspace, repo=_repo(), base_branch="main", token="t", store=store,
        result=result, dry_run=False, gh_repo_factory=lambda: None,
    )
    assert outcome.action == "skipped" and outcome.pr_url.endswith("/pull/3")


async def test_no_changes_opens_nothing(tmp_path):
    store = StateStore(tmp_path / "s.sqlite3")
    result = FixResult(findings=[_finding()], patch="", workspace=tmp_path)
    outcome = await pull_requests.create_fix_pr(
        workspace=tmp_path, repo=_repo(), base_branch="main", token="t", store=store,
        result=result, dry_run=False, gh_repo_factory=lambda: None,
    )
    assert outcome.action == "no_changes"


async def test_created_pushes_branch_opens_pr_and_records_ledger(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "s.sqlite3")
    result = await _result(tmp_path)
    pushed = {}

    async def fake_push(workspace, remote_url, branch, token, message):
        pushed.update(workspace=workspace, remote_url=remote_url, branch=branch, token=token, message=message)

    monkeypatch.setattr(pull_requests, "push_fix_branch", fake_push)
    gh = _FakeGhRepo()
    outcome = await pull_requests.create_fix_pr(
        workspace=result.workspace, repo=_repo(), base_branch="develop", token="ghs_tok",
        store=store, result=result, dry_run=False, prefix="[acme]", draft=True,
        gh_repo_factory=lambda: gh,
    )
    assert outcome.action == "created"
    assert outcome.pr_url == "https://github.com/octo/demo/pull/7"
    assert pushed["remote_url"] == "https://github.com/octo/demo.git"
    assert pushed["token"] == "ghs_tok"
    assert pushed["branch"] == outcome.branch == pull_requests.branch_name(result.fix_key)
    assert pushed["message"].startswith("[acme] fix high: SQL injection")
    call = gh.calls[0]
    assert call["head"] == outcome.branch and call["base"] == "develop" and call["draft"] is True
    assert call["title"] == "[acme] fix high: SQL injection"
    tracked = store.find_fix_pr("octo", "demo", result.fix_key)
    assert tracked is not None and tracked.pr_number == 7 and tracked.branch == outcome.branch

    # A second run with the same findings is deduped by the ledger.
    again = await pull_requests.create_fix_pr(
        workspace=result.workspace, repo=_repo(), base_branch="develop", token="ghs_tok",
        store=store, result=result, dry_run=False, gh_repo_factory=lambda: gh,
    )
    assert again.action == "skipped" and len(gh.calls) == 1


async def test_push_failure_is_reported_not_raised(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "s.sqlite3")
    result = await _result(tmp_path)

    async def fake_push(*a, **k):
        raise fixer.FixError("git push failed: remote: refusing workflow change")

    monkeypatch.setattr(pull_requests, "push_fix_branch", fake_push)
    outcome = await pull_requests.create_fix_pr(
        workspace=result.workspace, repo=_repo(), base_branch="main", token="t", store=store,
        result=result, dry_run=False, gh_repo_factory=lambda: _FakeGhRepo(),
    )
    assert outcome.action == "failed" and "workflow" in outcome.reason
    assert store.fix_pr_count() == 0


async def test_pr_api_failure_after_push_is_reported(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "s.sqlite3")
    result = await _result(tmp_path)

    async def fake_push(*a, **k):
        pass

    class _Boom:
        def create_pull(self, **kwargs):
            raise RuntimeError("422 https://x-access-token:secret@github.com boom")

    monkeypatch.setattr(pull_requests, "push_fix_branch", fake_push)
    outcome = await pull_requests.create_fix_pr(
        workspace=result.workspace, repo=_repo(), base_branch="main", token="t", store=store,
        result=result, dry_run=False, gh_repo_factory=lambda: _Boom(),
    )
    assert outcome.action == "failed" and "branch pushed" in outcome.reason
    assert "secret" not in outcome.reason


async def test_push_fix_branch_commits_on_new_branch_with_token_in_env_only(tmp_path, monkeypatch):
    ws = await _workspace(tmp_path)
    await fixer.diff_workspace(ws)  # stage
    captured = {}

    async def fake_git(*args, cwd, check=True, env=None):
        captured.setdefault("calls", []).append(args)
        if args[0] == "push":
            captured["env"] = env
            captured["cwd"] = cwd
            return ""
        return await pull_requests.git.__wrapped__(*args, cwd=cwd, check=check, env=env) if hasattr(pull_requests.git, "__wrapped__") else await fixer.git(*args, cwd=cwd, check=check, env=env)

    monkeypatch.setattr(pull_requests, "git", fake_git)
    await pull_requests.push_fix_branch(ws, "https://github.com/octo/demo.git", "secscan/fix-abc", "ghs_secret", "msg")
    push = next(c for c in captured["calls"] if c[0] == "push")
    assert "ghs_secret" not in " ".join(push)
    assert push[-1] == "HEAD:refs/heads/secscan/fix-abc"
    assert captured["env"]["GIT_CONFIG_KEY_0"] == "http.extraheader"
    assert captured["env"]["GIT_AUTHOR_NAME"] == "secscan"
    assert await fixer.current_branch(ws) == "secscan/fix-abc"
    assert not await fixer.has_uncommitted_changes(ws)


async def test_guard_blocks_push_and_pr_when_flag_not_propagated(tmp_path):
    """The dry-run backstop: a caller that forgot dry_run=True still cannot reach GitHub."""
    ws = await _workspace(tmp_path)
    dryrun.activate()
    with pytest.raises(dryrun.DryRunViolation):
        await pull_requests.push_fix_branch(ws, "https://github.com/octo/demo.git", "b", "t", "m")
    with pytest.raises(dryrun.DryRunViolation):
        pull_requests.open_pull_request(_FakeGhRepo(), title="t", body="b", head="h", base="main", draft=False)
