"""Unit tests for the Kimi CLI engine (secscan/kimi_cli.py).

The real `kimi` binary is never run: review/fix tests point `--kimi-bin` at a small
Python script that reproduces `kimi --print --output-format stream-json`'s output.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
from pathlib import Path

import pytest

from secscan import kimi_cli
from secscan.config import ConfigError
from secscan.kimi_cli import (
    KIMI_CODE_BASE_URL,
    MOONSHOT_BASE_URL,
    KimiConfig,
    build_command,
    inline_config,
    resolve_config,
    subprocess_env,
    write_agent_spec,
)

_ENV_VARS = (
    "KIMI_API_KEY", "MOONSHOT_API_KEY", "KIMI_BASE_URL", "KIMI_CLI_BASE_URL", "KIMI_MODEL",
    "KIMI_SHARE_DIR", "KIMI_BIN",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("KIMI_SHARE_DIR", str(tmp_path / "kimi-share"))


@pytest.fixture
def fake_bin(monkeypatch):
    monkeypatch.setattr(kimi_cli.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")


# --- resolve_config ----------------------------------------------------------------


def test_missing_binary_is_a_config_error(monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", "sk")
    monkeypatch.setattr(kimi_cli.shutil, "which", lambda cmd: None)
    with pytest.raises(ConfigError, match="uv tool install kimi-cli"):
        resolve_config()


def test_kimi_code_key_wins_and_sets_platform_defaults(fake_bin, monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", "sk-kimi")
    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-moon")
    cfg = resolve_config(model="sonnet")
    assert cfg.auth == "kimi-code"
    assert cfg.api_key == "sk-kimi"
    assert cfg.base_url == KIMI_CODE_BASE_URL
    assert cfg.model == "kimi-for-coding"


def test_moonshot_key_uses_open_platform(fake_bin, monkeypatch):
    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-moon")
    cfg = resolve_config(model="opus")
    assert cfg.auth == "moonshot"
    assert cfg.base_url == MOONSHOT_BASE_URL
    assert cfg.model == "kimi-k2.7-code"


def test_kimi_model_env_and_explicit_model(fake_bin, monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", "sk")
    monkeypatch.setenv("KIMI_MODEL", "kimi-k3")
    assert resolve_config(model="sonnet").model == "kimi-k3"
    assert resolve_config(model="kimi-k2-thinking").model == "kimi-k2-thinking"


def test_anthropic_style_kimi_base_url_is_ignored(fake_bin, monkeypatch):
    # KIMI_BASE_URL is shared with --provider kimi, where it names the Anthropic-compatible
    # endpoint; that would be the wrong API style for the Kimi CLI.
    monkeypatch.setenv("KIMI_API_KEY", "sk")
    monkeypatch.setenv("KIMI_BASE_URL", "https://api.moonshot.cn/anthropic")
    assert resolve_config().base_url == KIMI_CODE_BASE_URL
    monkeypatch.setenv("KIMI_BASE_URL", "https://gw.example/v1/")
    assert resolve_config().base_url == "https://gw.example/v1"
    monkeypatch.setenv("KIMI_CLI_BASE_URL", "https://cli.example/v1")
    assert resolve_config().base_url == "https://cli.example/v1"


def test_login_auth_requires_a_default_model(fake_bin, tmp_path):
    share = tmp_path / "kimi-share"
    share.mkdir()
    (share / "config.toml").write_text('default_model = ""\n')
    with pytest.raises(ConfigError, match="kimi login"):
        resolve_config()
    (share / "config.toml").write_text('default_model = "kimi-for-coding"\n[models]\n')
    cfg = resolve_config(model="sonnet")
    assert cfg.auth == "login" and cfg.api_key is None and cfg.model is None
    assert resolve_config(model="my-alias").model == "my-alias"


def test_no_credentials_and_no_config_is_a_config_error(fake_bin):
    with pytest.raises(ConfigError, match="KIMI_API_KEY"):
        resolve_config()


# --- agent spec / command / env --------------------------------------------------------


def test_agent_spec_review_is_read_only_and_never_templates_agents_md(tmp_path):
    path = write_agent_spec(tmp_path / "spec", write=False, skills_prompt="\n## pack\n${evil}")
    spec = path.read_text()
    assert "ReadFile" in spec and "Grep" in spec and "Glob" in spec
    assert "WriteFile" not in spec and "Shell" not in spec and "Agent" not in spec
    system = (tmp_path / "spec" / "system.md").read_text()
    assert system.startswith("{% raw %}")
    assert "KIMI_AGENTS_MD" not in system
    assert "${evil}" in system  # inside the raw block, so not substituted


def test_agent_spec_fix_adds_file_writing_tools_only(tmp_path):
    spec = write_agent_spec(tmp_path / "spec", write=True).read_text()
    assert "WriteFile" in spec and "StrReplaceFile" in spec
    assert "Shell" not in spec and "FetchURL" not in spec and "SearchWeb" not in spec


def test_inline_config_never_contains_the_key():
    cfg = KimiConfig(model="kimi-for-coding", base_url=KIMI_CODE_BASE_URL, api_key="sk-secret", auth="kimi-code")
    toml = inline_config(cfg)
    assert "sk-secret" not in toml
    assert 'api_key = ""' in toml
    assert 'type = "kimi"' in toml and 'model = "kimi-for-coding"' in toml


def test_build_command_isolates_project_skills_and_mcp(tmp_path):
    cfg = KimiConfig(model="kimi-for-coding", base_url=KIMI_CODE_BASE_URL, api_key="sk", auth="kimi-code", extra_args=("--thinking",))
    argv = build_command(cfg, tmp_path, tmp_path / "agent.yaml", tmp_path / "none")
    assert argv[:2] == ["kimi", "--print"]
    assert argv[argv.index("--output-format") + 1] == "stream-json"
    assert argv[argv.index("--work-dir") + 1] == str(tmp_path)
    assert argv[argv.index("--agent-file") + 1] == str(tmp_path / "agent.yaml")
    assert argv[argv.index("--skills-dir") + 1] == str(tmp_path / "none")
    assert json.loads(argv[argv.index("--mcp-config") + 1]) == {"mcpServers": {}}
    assert "--config" in argv and "--model" not in argv
    assert "sk" not in " ".join(argv[argv.index("--config") + 1 :])
    assert argv[-1] == "--thinking"


def test_build_command_login_auth_passes_model_alias(tmp_path):
    argv = build_command(KimiConfig(model="alias"), tmp_path, tmp_path / "a.yaml", tmp_path / "n")
    assert "--config" not in argv
    assert argv[argv.index("--model") + 1] == "alias"


def test_subprocess_env_maps_key_and_drops_everything_else(monkeypatch):
    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-moon")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    cfg = KimiConfig(model="m", base_url=MOONSHOT_BASE_URL, api_key="sk-moon", auth="moonshot")
    env = subprocess_env(cfg)
    assert env["KIMI_API_KEY"] == "sk-moon"
    assert env["KIMI_BASE_URL"] == MOONSHOT_BASE_URL
    assert env["KIMI_SHARE_DIR"]
    for name in ("MOONSHOT_API_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        assert name not in env


# --- review_repo / fix_repo through a stub -----------------------------------------

_STUB = textwrap.dedent(
    '''
    import json, sys
    args = sys.argv[1:]
    prompt = sys.stdin.read()
    spec = open(args[args.index("--agent-file") + 1]).read()
    assert "--print" in args and "stream-json" in args
    mode = "fix" if "WriteFile" in spec else "review"
    def emit(obj):
        print(json.dumps(obj), flush=True)
    emit({"role": "assistant", "content": [{"type": "text", "text": "Looking around."}],
          "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "Grep", "arguments": "{}"}}]})
    emit({"role": "tool", "tool_call_id": "c1", "content": [{"type": "text", "text": "app.py:1"}]})
    if mode == "review":
        assert "Perform a complete security review" in prompt
        final = "```json\\n" + json.dumps({"findings": [
            {"severity": "high", "title": "SQL injection", "description": "d", "file_path": "app.py"}
        ]}) + "\\n```"
    else:
        assert "Remediate the following security findings" in prompt
        with open("app.py", "a") as fh:
            fh.write("# fixed\\n")
        final = "```json\\n" + json.dumps({"fixes": [{"title": "SQL injection", "file_path": "app.py", "status": "fixed", "summary": "ok"}]}) + "\\n```"
    if "--llm-not-set" in args:
        print("LLM not set")
        print("To resume this session: kimi -r abc")
        sys.exit(1)
    emit({"role": "assistant", "content": [{"type": "text", "text": final}]})
    '''
)


def _stub_cfg(tmp_path: Path, *extra: str) -> KimiConfig:
    stub = tmp_path / "kimi_stub.py"
    stub.write_text(_STUB)
    return KimiConfig(
        bin=f"{sys.executable} {stub}", model="kimi-for-coding", base_url=KIMI_CODE_BASE_URL,
        api_key="sk", auth="kimi-code", extra_args=tuple(extra),
    )


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("cur.execute('SELECT ' + user_id)\n")
    return repo


async def test_review_repo_parses_last_assistant_message(tmp_path):
    res = await kimi_cli.review_repo(_repo(tmp_path), "octo/demo", cfg=_stub_cfg(tmp_path))
    assert res.error == ""
    assert res.high_count == 1 and res.total_findings == 1
    assert res.num_turns == 2


async def test_review_repo_surfaces_kimi_plain_text_errors(tmp_path):
    res = await kimi_cli.review_repo(_repo(tmp_path), "octo/demo", cfg=_stub_cfg(tmp_path, "--llm-not-set"))
    assert "status 1" in res.error and "LLM not set" in res.error
    assert "To resume" not in res.error


async def test_fix_repo_edits_workspace(tmp_path):
    repo = _repo(tmp_path)
    run = await kimi_cli.fix_repo(repo, "octo/demo", "[]", cfg=_stub_cfg(tmp_path))
    assert run.error == ""
    assert (repo / "app.py").read_text().endswith("# fixed\n")
    assert '"status": "fixed"' in run.text


async def test_review_repo_idle_timeout(tmp_path):
    stub = tmp_path / "sleepy.py"
    stub.write_text("import time, sys; sys.stdin.read(); time.sleep(5)\n")
    cfg = KimiConfig(bin=f"{sys.executable} {stub}", model="m", base_url=KIMI_CODE_BASE_URL, api_key="sk", auth="kimi-code")
    res = await kimi_cli.review_repo(_repo(tmp_path), "octo/demo", cfg=cfg, idle_timeout_s=0.2)
    assert "stalled" in res.error
