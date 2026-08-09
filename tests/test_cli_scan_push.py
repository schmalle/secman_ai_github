"""`scan` / `run` with --push-to-secman: config plumbing, fail-fast validation,
and the push that happens after the review."""

import pytest
import typer
from typer.testing import CliRunner

import secscan.orchestrator as orch
import secscan.secman_client as secman_client
from secscan.cli import app
from secscan.config import GithubHost, RunConfig
from secscan.findings import Finding
from secscan.state import StateStore

runner = CliRunner()


def _no_secman_env(monkeypatch):
    for var in ("SECMAN_URL", "SECMAN_USERNAME", "SECMAN_PASSWORD"):
        monkeypatch.delenv(var, raising=False)


def _capture_scan_repo(monkeypatch, captured, started):
    async def fake_scan_repo(cfg, owner, name):
        started.append((owner, name))
        captured["cfg"] = cfg

    monkeypatch.setattr(orch, "scan_repo", fake_scan_repo)


# -- CLI plumbing and validation --------------------------------------------------


def test_scan_push_flags_reach_config(tmp_path, monkeypatch):
    _no_secman_env(monkeypatch)
    captured, started = {}, []
    _capture_scan_repo(monkeypatch, captured, started)

    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path), "--push-to-secman",
         "--secman-url", "https://secman.example.com",
         "--secman-username", "vulnbot", "--secman-password", "pw"],
    )

    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.push_to_secman is True
    assert cfg.secman_url == "https://secman.example.com"
    assert cfg.secman_username == "vulnbot"
    assert cfg.secman_password == "pw"


def test_run_push_flags_reach_config(tmp_path, monkeypatch):
    _no_secman_env(monkeypatch)
    captured = {}

    async def fake_run_scan(cfg, **kwargs):
        captured["cfg"] = cfg

    monkeypatch.setattr(orch, "run_scan", fake_run_scan)

    result = runner.invoke(
        app,
        ["run", "--output-dir", str(tmp_path), "--push-to-secman",
         "--secman-url", "https://secman.example.com",
         "--secman-username", "vulnbot", "--secman-password", "pw"],
    )

    assert result.exit_code == 0, result.output
    assert captured["cfg"].push_to_secman is True
    assert captured["cfg"].secman_url == "https://secman.example.com"


def test_scan_push_credentials_come_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECMAN_URL", "https://env.example.com")
    monkeypatch.setenv("SECMAN_USERNAME", "envuser")
    monkeypatch.setenv("SECMAN_PASSWORD", "envpw")
    captured, started = {}, []
    _capture_scan_repo(monkeypatch, captured, started)

    result = runner.invoke(
        app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--push-to-secman"]
    )

    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert (cfg.secman_url, cfg.secman_username, cfg.secman_password) == (
        "https://env.example.com", "envuser", "envpw",
    )


def test_scan_push_without_credentials_fails_before_the_review(tmp_path, monkeypatch):
    """A paid LLM review must not run only to find the push unconfigured."""
    _no_secman_env(monkeypatch)
    captured, started = {}, []
    _capture_scan_repo(monkeypatch, captured, started)

    result = runner.invoke(
        app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--push-to-secman"]
    )

    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "SECMAN_URL" in result.output
    assert started == []  # the review never started


def test_run_push_without_credentials_fails_before_the_review(tmp_path, monkeypatch):
    _no_secman_env(monkeypatch)
    started = []

    async def fake_run_scan(cfg, **kwargs):
        started.append(1)

    monkeypatch.setattr(orch, "run_scan", fake_run_scan)

    result = runner.invoke(app, ["run", "--output-dir", str(tmp_path), "--push-to-secman"])

    assert result.exit_code == 1
    assert "SECMAN_URL" in result.output
    assert started == []


def test_scan_push_with_no_db_reports_clean_error(tmp_path, monkeypatch):
    _no_secman_env(monkeypatch)

    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path), "--no-db", "--push-to-secman"],
    )

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "no-db" in result.output and "push-to-secman" in result.output


def test_scan_secman_credentials_without_the_push_flag_report_clean_error(tmp_path, monkeypatch):
    """Credentials that would silently do nothing are a configuration error."""
    _no_secman_env(monkeypatch)
    captured, started = {}, []
    _capture_scan_repo(monkeypatch, captured, started)

    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path),
         "--secman-url", "https://secman.example.com"],
    )

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "push-to-secman" in result.output
    assert started == []


def test_scan_secman_env_alone_is_not_an_error(tmp_path, monkeypatch):
    """SECMAN_* is often exported process-wide; only explicit flags are an error."""
    monkeypatch.setenv("SECMAN_URL", "https://env.example.com")
    monkeypatch.setenv("SECMAN_USERNAME", "envuser")
    monkeypatch.setenv("SECMAN_PASSWORD", "envpw")
    captured, started = {}, []
    _capture_scan_repo(monkeypatch, captured, started)

    result = runner.invoke(app, ["scan", "octo/demo", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert captured["cfg"].push_to_secman is False


def test_scan_push_dry_run_needs_no_credentials(tmp_path, monkeypatch):
    _no_secman_env(monkeypatch)
    captured, started = {}, []
    _capture_scan_repo(monkeypatch, captured, started)

    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path), "--push-to-secman", "--dry-run"],
    )

    assert result.exit_code == 0, result.output
    assert started == [("octo", "demo")]
    assert captured["cfg"].push_to_secman is True


# -- the push itself --------------------------------------------------------------


class _FakeAuth:
    def __init__(self, app=None, pat=None, host=None):
        self.app = app
        self.pat = pat
        self.host = host or GithubHost()


def _record(store, owner, name):
    store.record_result(
        owner, name,
        critical=1, high=0, total=2,
        duration_s=1.0, cost_usd=0.1, reviewed_at="2026-07-01T00:00:00+00:00",
    )
    store.replace_findings(
        owner, name,
        [
            Finding(severity="critical", title="SQLi", description="d", file_path="a.py", category="CWE-89"),
            Finding(severity="medium", title="Weak crypto", description="d", file_path="c.py"),
        ],
    )


def _stub_review(monkeypatch):
    """Stand in for the whole clone+review step, recording a finding as it goes."""
    async def fake_process_repo(repo, auth, store, cfg, sem, provider_env):
        if store is not None:
            _record(store, repo.owner, repo.name)
        return (1, 0)

    monkeypatch.setattr(orch, "_process_repo", fake_process_repo)
    monkeypatch.setattr(orch, "build_auth", lambda api_url=None: _FakeAuth())
    monkeypatch.setattr(
        orch, "resolve_target",
        lambda owner, name, auth: __import__("secscan.github_app", fromlist=["RepoInfo"]).RepoInfo(
            owner=owner, name=name, full_name=f"{owner}/{name}", archived=False, fork=False,
            size_kb=1, default_branch="main",
            clone_url=f"https://github.com/{owner}/{name}.git", installation_id=1,
        ),
    )


def _stub_client(monkeypatch, pushed):
    monkeypatch.setattr(secman_client, "login", lambda url, u, p: "tok")
    monkeypatch.setattr(
        secman_client, "push_vulnerability",
        lambda url, token, **kw: pushed.append(kw) or {"operation": "CREATED"},
    )


def _push_cfg(tmp_path, **overrides):
    return RunConfig(
        output_dir=tmp_path,
        state_db=tmp_path / "secscan.sqlite3",
        push_to_secman=True,
        secman_url="https://secman.example.com",
        secman_username="vulnbot",
        secman_password="pw",
        **overrides,
    )


async def test_scan_repo_pushes_its_findings_to_secman(tmp_path, monkeypatch):
    _stub_review(monkeypatch)
    pushed = []
    _stub_client(monkeypatch, pushed)

    await orch.scan_repo(_push_cfg(tmp_path), "octo", "demo")

    assert [p["hostname"] for p in pushed] == ["octo/demo"]
    assert pushed[0]["criticality"] == "CRITICAL"  # the medium finding is not pushed


async def test_scan_repo_pushes_nothing_without_the_flag(tmp_path, monkeypatch):
    _stub_review(monkeypatch)
    pushed = []
    _stub_client(monkeypatch, pushed)

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "secscan.sqlite3")
    await orch.scan_repo(cfg, "octo", "demo")

    assert pushed == []


async def test_scan_repo_pushes_only_the_repo_it_scanned(tmp_path, monkeypatch):
    """An unrelated repo already in the state DB is push-to-secman's job, not scan's."""
    _stub_review(monkeypatch)
    pushed = []
    _stub_client(monkeypatch, pushed)

    store = StateStore(tmp_path / "secscan.sqlite3")
    _record(store, "octo", "stale")
    store.close()

    await orch.scan_repo(_push_cfg(tmp_path), "octo", "demo")

    assert [p["hostname"] for p in pushed] == ["octo/demo"]


async def test_scan_repo_dry_run_push_makes_no_calls(tmp_path, monkeypatch):
    _stub_review(monkeypatch)
    called = []
    monkeypatch.setattr(secman_client, "login", lambda *a, **kw: called.append("login") or "tok")
    monkeypatch.setattr(secman_client, "push_vulnerability", lambda *a, **kw: called.append("push"))

    await orch.scan_repo(_push_cfg(tmp_path, dry_run=True), "octo", "demo")

    assert called == []


async def test_scan_repo_login_failure_exits_non_zero(tmp_path, monkeypatch):
    """The review is already persisted; the failure must still be visible."""
    _stub_review(monkeypatch)

    def boom(url, u, p):
        raise secman_client.SecmanPushError("secman login failed: 401")

    monkeypatch.setattr(secman_client, "login", boom)

    with pytest.raises(typer.Exit) as exc:
        await orch.scan_repo(_push_cfg(tmp_path), "octo", "demo")
    assert exc.value.exit_code == 1

    # findings.csv / state were written before the push was attempted
    store = StateStore(tmp_path / "secscan.sqlite3")
    assert store.get_findings("octo", "demo") != []
    store.close()


class _FakeApp:
    def __init__(self):
        self.iter_called = False

    def iter_repositories(self, org=None, filters=None):
        self.iter_called = True
        return iter(())


async def test_run_scan_pushes_every_repo_it_reviewed(tmp_path, monkeypatch):
    _stub_review(monkeypatch)
    monkeypatch.setattr(orch, "build_auth", lambda api_url=None: _FakeAuth(app=_FakeApp()))
    pushed = []
    _stub_client(monkeypatch, pushed)

    cfg = _push_cfg(tmp_path)
    store = StateStore(cfg.state_target)
    store.add_target("octo", "one")
    store.add_target("octo", "two")
    store.close()

    await orch.run_scan(cfg, targets_only=True)

    assert sorted(p["hostname"] for p in pushed) == ["octo/one", "octo/two"]


async def test_run_scan_does_not_push_repos_skipped_by_resume(tmp_path, monkeypatch):
    _stub_review(monkeypatch)
    monkeypatch.setattr(orch, "build_auth", lambda api_url=None: _FakeAuth(app=_FakeApp()))
    pushed = []
    _stub_client(monkeypatch, pushed)

    cfg = _push_cfg(tmp_path)
    store = StateStore(cfg.state_target)
    store.add_target("octo", "one")
    store.add_target("octo", "done")
    _record(store, "octo", "done")  # already reviewed in an earlier run
    store.close()

    await orch.run_scan(cfg, targets_only=True)

    assert [p["hostname"] for p in pushed] == ["octo/one"]
