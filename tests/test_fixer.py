"""Unit tests for the fix step (secscan/fixer.py): workspace preparation, engine
dispatch, and turning the edited tree into a patch. Engines are faked."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from secscan import fixer
from secscan.config import RunConfig
from secscan.findings import Finding
from secscan.providers import ProviderEnv
from secscan.reviewer import AgentRun


def _finding(**overrides):
    defaults = dict(
        severity="high", title="SQL injection", description="concat", file_path="app.py",
        line_range="3", category="CWE-89", recommendation="parameterize",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _git(*args, cwd):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
        env={**fixer.GIT_IDENTITY, "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(cwd)},
    ).stdout


def _git_repo(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    _git("init", "-q", "-b", "main", cwd=src)
    (src / "app.py").write_text("cur.execute('SELECT ' + user_id)\n")
    _git("add", "-A", cwd=src)
    _git("commit", "-q", "-m", "init", cwd=src)
    return src


def test_fix_key_is_order_insensitive_and_content_based():
    a, b = _finding(), _finding(title="Hardcoded secret")
    assert fixer.fix_key([a, b]) == fixer.fix_key([b, a])
    assert fixer.fix_key([a]) != fixer.fix_key([a, b])
    # line drift / rewording does not change the key (same rule as issue dedup)
    assert fixer.fix_key([a]) == fixer.fix_key([_finding(line_range="99", description="other")])


def test_findings_json_carries_only_what_the_agent_needs():
    data = json.loads(fixer.findings_json([_finding()]))
    assert data[0]["severity"] == "high" and data[0]["file_path"] == "app.py"
    assert "confidence" not in data[0]


async def test_prepare_workspace_clones_a_git_repo_without_touching_it(tmp_path):
    src = _git_repo(tmp_path)
    ws = await fixer.prepare_workspace(src, tmp_path / "work", "demo")
    assert (ws / "app.py").read_text() == (src / "app.py").read_text()
    assert await fixer.is_git_repo(ws)
    assert await fixer.current_branch(ws) == "main"
    (ws / "app.py").write_text("changed\n")
    assert (src / "app.py").read_text() != "changed\n"
    assert not await fixer.has_uncommitted_changes(src)


async def test_prepare_workspace_copies_and_baselines_a_plain_directory(tmp_path):
    src = tmp_path / "plain"
    src.mkdir()
    (src / "a.txt").write_text("a\n")
    ws = await fixer.prepare_workspace(src, tmp_path / "work", "plain")
    assert await fixer.is_git_repo(ws)
    patch, files = await fixer.diff_workspace(ws)
    assert patch == "" and files == []
    (ws / "a.txt").write_text("b\n")
    patch, files = await fixer.diff_workspace(ws)
    assert "-a" in patch and "+b" in patch and files == ["a.txt"]


async def test_fix_findings_runs_engine_and_diffs(tmp_path, monkeypatch):
    src = _git_repo(tmp_path)
    ws = await fixer.prepare_workspace(src, tmp_path / "work", "demo")
    captured = {}

    async def fake_fix(repo_dir, full_name, findings_json, **kwargs):
        captured["kwargs"] = kwargs
        captured["payload"] = json.loads(findings_json)
        Path(repo_dir, "app.py").write_text("cur.execute('SELECT ?', (user_id,))\n")
        Path(repo_dir, "new.py").write_text("x\n")
        return AgentRun(
            text='```json\n{"fixes": [{"title": "SQL injection", "file_path": "app.py", "status": "fixed", "summary": "s"}]}\n```',
            cost_usd=0.02, num_turns=3, duration_s=1.0,
        )

    monkeypatch.setattr(fixer, "claude_fix_repo", fake_fix)
    cfg = RunConfig(output_dir=tmp_path, engine="claude", model="sonnet", fix=True, max_turns=7)
    result = await fixer.fix_findings(cfg, ws, "octo/demo", [_finding()], ProviderEnv(name="anthropic", env={"A": "b"}))

    assert result.error == ""
    assert sorted(result.changed_files) == ["app.py", "new.py"]
    assert "+cur.execute('SELECT ?'" in result.patch
    assert result.fixed_titles == ["SQL injection"]
    assert result.cost_usd == 0.02 and result.num_turns == 3
    assert captured["payload"][0]["title"] == "SQL injection"
    assert captured["kwargs"]["max_turns"] == 7
    assert captured["kwargs"]["extra_env"] == {"A": "b"}

    patch_path, summary_path = fixer.write_artifacts(tmp_path / "out", result)
    assert patch_path.read_text() == result.patch
    summary = json.loads(summary_path.read_text())
    assert summary["fix_key"] == result.fix_key
    assert summary["changed_files"] == result.changed_files
    assert summary["findings"][0]["title"] == "SQL injection"


async def test_fix_findings_dispatches_per_engine(tmp_path, monkeypatch):
    from secscan import codex, kimi_cli

    src = _git_repo(tmp_path)
    ws = await fixer.prepare_workspace(src, tmp_path / "work", "demo")
    called = []

    async def fake(repo_dir, full_name, findings_json, *, cfg, idle_timeout_s, skills):
        called.append(cfg)
        return AgentRun(text="")

    monkeypatch.setattr(codex, "fix_repo", fake)
    monkeypatch.setattr(kimi_cli, "fix_repo", fake)
    for engine, attr in (("codex", "codex"), ("kimi-cli", "kimi")):
        cfg = RunConfig(output_dir=tmp_path, engine=engine, fix=True, **{attr: f"{engine}-cfg"})
        result = await fixer.fix_findings(cfg, ws, "octo/demo", [_finding()], ProviderEnv(name=engine))
        assert result.patch == "" and result.error == ""
    assert called == ["codex-cfg", "kimi-cli-cfg"]


async def test_fix_findings_with_no_findings_is_a_noop(tmp_path):
    cfg = RunConfig(output_dir=tmp_path, fix=True)
    result = await fixer.fix_findings(cfg, tmp_path, "octo/demo", [], ProviderEnv(name="anthropic"))
    assert result.patch == "" and result.error == ""


async def test_fix_findings_keeps_engine_error(tmp_path, monkeypatch):
    src = _git_repo(tmp_path)
    ws = await fixer.prepare_workspace(src, tmp_path / "work", "demo")

    async def fake_fix(repo_dir, full_name, findings_json, **kwargs):
        return AgentRun(error="fix stalled: no response")

    monkeypatch.setattr(fixer, "claude_fix_repo", fake_fix)
    cfg = RunConfig(output_dir=tmp_path, fix=True)
    result = await fixer.fix_findings(cfg, ws, "octo/demo", [_finding()], ProviderEnv(name="anthropic"))
    assert result.error == "fix stalled: no response"
    assert result.patch == ""
