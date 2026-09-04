"""Unit tests for the Codex CLI engine (secscan/codex.py).

The real `codex` binary is never run: review/fix tests point `--codex-bin` at a small
Python script that reproduces `codex exec --json`'s event stream and its `-o`
last-message file, so the suite stays offline and deterministic.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
from pathlib import Path

import pytest

from secscan import codex
from secscan.codex import CodexConfig, build_command, resolve_config, subprocess_env
from secscan.config import ConfigError

_ENV_VARS = ("OPENAI_API_KEY", "OPENAI_BASE_URL", "CODEX_HOME", "CODEX_BIN", "CODEX_MODEL")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))


@pytest.fixture
def fake_bin(monkeypatch):
    monkeypatch.setattr(codex.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")


# --- resolve_config ----------------------------------------------------------------


def test_missing_binary_is_a_config_error(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    monkeypatch.setattr(codex.shutil, "which", lambda cmd: None)
    with pytest.raises(ConfigError, match="npm install -g @openai/codex"):
        resolve_config()


def test_api_key_auth(fake_bin, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    cfg = resolve_config(model="sonnet")
    assert cfg.auth == "api-key"
    assert cfg.model is None  # the Anthropic alias means "Codex's default"
    assert cfg.bin == "codex"


def test_login_auth_from_codex_home(fake_bin, tmp_path):
    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "auth.json").write_text("{}")
    cfg = resolve_config(model="gpt-5.4")
    assert cfg.auth == "login"
    assert cfg.model == "gpt-5.4"


def test_no_credentials_is_a_config_error(fake_bin):
    with pytest.raises(ConfigError, match="OPENAI_API_KEY.*codex login"):
        resolve_config()


def test_env_defaults_for_bin_and_model(fake_bin, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    monkeypatch.setenv("CODEX_BIN", "npx @openai/codex")
    monkeypatch.setenv("CODEX_MODEL", "o3")
    cfg = resolve_config(model="sonnet", extra_args=["--oss"])
    assert cfg.argv0 == ["npx", "@openai/codex"]
    assert cfg.model == "o3"
    assert cfg.extra_args == ("--oss",)


# --- build_command / env -------------------------------------------------------------


def test_review_command_is_read_only_and_ignores_agents_md(tmp_path):
    cfg = CodexConfig(model="gpt-5.4", extra_args=("-c", "x=1"))
    argv = build_command(cfg, tmp_path, tmp_path / "last.md")
    assert argv[:3] == ["codex", "exec", "--json"]
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    assert argv[argv.index("-C") + 1] == str(tmp_path)
    assert "project_doc_max_bytes=0" in argv
    assert "--skip-git-repo-check" in argv and "--ephemeral" in argv
    assert argv[argv.index("-o") + 1] == str(tmp_path / "last.md")
    assert argv[argv.index("-m") + 1] == "gpt-5.4"
    assert argv[-3:] == ["-c", "x=1", "-"]  # extra args, then the stdin marker


def test_fix_command_is_workspace_write_without_network(tmp_path):
    argv = build_command(CodexConfig(), tmp_path, tmp_path / "last.md", write=True)
    assert argv[argv.index("--sandbox") + 1] == "workspace-write"
    assert "sandbox_workspace_write.network_access=false" in argv
    assert "-m" not in argv


def test_subprocess_env_forwards_only_codex_credentials(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://gw.example")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    monkeypatch.setenv("KIMI_API_KEY", "sk-kimi")
    monkeypatch.setenv("SECMAN_PASSWORD", "pw")
    env = subprocess_env(CodexConfig())
    assert env["OPENAI_API_KEY"] == "sk-openai"
    assert env["OPENAI_BASE_URL"] == "https://gw.example"
    assert env["CODEX_HOME"]
    for name in ("GITHUB_TOKEN", "ANTHROPIC_API_KEY", "KIMI_API_KEY", "SECMAN_PASSWORD"):
        assert name not in env
    assert env["PATH"] == os.environ["PATH"]


# --- review_repo / fix_repo through a stub -----------------------------------------

_STUB = textwrap.dedent(
    '''
    import json, sys
    args = sys.argv[1:]
    out = args[args.index("-o") + 1]
    prompt = sys.stdin.read()
    assert args[-1] == "-", args
    assert "project_doc_max_bytes=0" in args
    mode = "fix" if "workspace-write" in args else "review"
    print(json.dumps({"type": "thread.started", "thread_id": "t1"}), flush=True)
    print(json.dumps({"type": "turn.started"}), flush=True)
    print(json.dumps({"type": "item.completed", "item": {"id": "i1", "type": "command_execution", "command": "rg -n execute", "exit_code": 0}}), flush=True)
    if mode == "review":
        assert "Perform a complete security review" in prompt
        final = "```json\\n" + json.dumps({"findings": [
            {"severity": "critical", "title": "SQL injection", "description": "d", "file_path": "app.py", "line_range": "24"},
            {"severity": "low", "title": "x", "description": "d", "file_path": "app.py"},
        ]}) + "\\n```"
    else:
        assert "Remediate the following security findings" in prompt
        import os
        with open("app.py", "a") as fh:
            fh.write("# fixed\\n")
        final = "```json\\n" + json.dumps({"fixes": [{"title": "SQL injection", "file_path": "app.py", "status": "fixed", "summary": "parameterized"}]}) + "\\n```"
    print(json.dumps({"type": "item.completed", "item": {"id": "i2", "type": "agent_message", "text": final}}), flush=True)
    print(json.dumps({"type": "turn.completed", "usage": {"input_tokens": 10, "output_tokens": 5}}), flush=True)
    with open(out, "w") as fh:
        fh.write(final)
    if "--fail" in args:
        print("boom: quota exceeded", file=sys.stderr)
        sys.exit(3)
    '''
)


def _stub_cfg(tmp_path: Path, *extra: str) -> CodexConfig:
    stub = tmp_path / "codex_stub.py"
    stub.write_text(_STUB)
    return CodexConfig(bin=f"{sys.executable} {stub}", extra_args=tuple(extra))


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("cur.execute('SELECT ' + user_id)\n")
    return repo


async def test_review_repo_parses_findings_from_last_message(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    res = await codex.review_repo(_repo(tmp_path), "octo/demo", cfg=_stub_cfg(tmp_path))
    assert res.error == ""
    assert res.total_findings == 2
    assert res.critical_count == 1 and res.high_count == 0
    assert res.num_turns == 2  # one command, one message
    assert res.cost_usd == 0.0  # Codex does not report spend


async def test_review_repo_reports_nonzero_exit(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    res = await codex.review_repo(_repo(tmp_path), "octo/demo", cfg=_stub_cfg(tmp_path, "--fail"))
    assert "status 3" in res.error and "quota exceeded" in res.error
    # Findings printed before the failure are still parsed.
    assert res.total_findings == 2


async def test_fix_repo_edits_workspace_and_returns_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    repo = _repo(tmp_path)
    run = await codex.fix_repo(repo, "octo/demo", "[]", cfg=_stub_cfg(tmp_path))
    assert run.error == ""
    assert (repo / "app.py").read_text().endswith("# fixed\n")
    assert "parameterized" in run.text


async def test_review_repo_idle_timeout(tmp_path):
    stub = tmp_path / "sleepy.py"
    stub.write_text("import time, sys; sys.stdin.read(); time.sleep(5)\n")
    cfg = CodexConfig(bin=f"{sys.executable} {stub}")
    res = await codex.review_repo(_repo(tmp_path), "octo/demo", cfg=cfg, idle_timeout_s=0.2)
    assert "stalled" in res.error


async def test_review_repo_missing_executable(tmp_path):
    cfg = CodexConfig(bin="/nonexistent/codex")
    res = await codex.review_repo(_repo(tmp_path), "octo/demo", cfg=cfg)
    assert "cannot start" in res.error


def test_feed_collects_errors_and_last_message():
    stream = codex._Stream()
    codex._feed(stream, "not json", "x")
    codex._feed(stream, json.dumps({"type": "error", "message": "rate limited"}), "x")
    codex._feed(stream, json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "hi"}}), "x")
    codex._feed(stream, json.dumps({"type": "turn.failed", "error": {"message": "dead"}}), "x")
    assert stream.errors == ["rate limited", "dead"]
    assert stream.last_message == "hi"
    assert stream.turns == 1
