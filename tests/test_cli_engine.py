"""CLI tests for --engine and the --codescanai-* flags on run / scan / review."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from secscan import codescanai
from secscan.cli import app
from secscan.findings import Severity

runner = CliRunner()

_ENV_VARS = (
    "OPENAI_API_KEY", "OPENAI_BASE_URL", "GEMINI_API_KEY", "GOOGLE_API_KEY", "SECSCAN_ENGINE",
    "CODESCANAI_PROVIDER", "CODESCANAI_MODEL", "CODESCANAI_HOST", "CODESCANAI_PORT",
    "CODESCANAI_ENDPOINT", "CODESCANAI_TOKEN", "CODESCANAI_BIN", "CODESCANAI_DEFAULT_SEVERITY",
    "OPENROUTER_API_KEY", "MOONSHOT_API_KEY", "KIMI_API_KEY",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def fake_bin(monkeypatch):
    monkeypatch.setattr(codescanai.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")


@pytest.fixture
def captured(monkeypatch):
    import secscan.orchestrator

    box = {}

    async def fake_scan_repo(cfg, owner, name):
        box["cfg"] = cfg

    async def fake_run_scan(cfg, **kwargs):
        box["cfg"] = cfg

    async def fake_review_local(cfg, path):
        box["cfg"] = cfg

    monkeypatch.setattr(secscan.orchestrator, "scan_repo", fake_scan_repo)
    monkeypatch.setattr(secscan.orchestrator, "run_scan", fake_run_scan)
    monkeypatch.setattr(secscan.orchestrator, "review_local", fake_review_local)
    return box


def test_engine_defaults_to_claude(tmp_path, captured):
    result = runner.invoke(app, ["scan", "octo/demo", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["cfg"].engine == "claude"
    assert captured["cfg"].codescanai is None


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "octo/demo"],
        ["run", "--targets-only"],
        ["review", "."],
    ],
)
def test_engine_codescanai_flags_reach_config(argv, tmp_path, captured, fake_bin, monkeypatch):
    monkeypatch.setenv("CODESCANAI_TOKEN", "tok")
    result = runner.invoke(
        app,
        argv + [
            "--output-dir", str(tmp_path), "--engine", "codescanai",
            "--codescanai-provider", "custom", "--codescanai-host", "http://localhost",
            "--codescanai-port", "11434", "--codescanai-endpoint", "/v1",
            "--model", "llama3", "--codescanai-bin", "uvx codescanai",
            "--codescanai-arg=--changes_only", "--codescanai-default-severity", "high",
        ],
    )
    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.engine == "codescanai"
    cs = cfg.codescanai
    assert cs.provider == "custom"
    assert cs.base_url == "http://localhost:11434/v1"
    assert cs.token == "tok"
    assert cs.model == "llama3"
    assert cs.bin == "uvx codescanai"
    assert cs.extra_args == ("--changes_only",)
    assert cs.default_severity is Severity.HIGH


def test_engine_from_env(tmp_path, captured, fake_bin, monkeypatch):
    monkeypatch.setenv("SECSCAN_ENGINE", "codescanai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    result = runner.invoke(app, ["review", ".", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["cfg"].engine == "codescanai"
    assert captured["cfg"].codescanai.provider == "openai"
    assert captured["cfg"].codescanai.model is None  # "sonnet" default -> provider default


def test_unknown_engine_is_a_clean_error(tmp_path, captured):
    result = runner.invoke(
        app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--engine", "semgrep"]
    )
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "--engine" in result.output and "semgrep" in result.output
    assert "cfg" not in captured


def test_codescanai_flags_without_the_engine_are_an_error(tmp_path, captured):
    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path), "--codescanai-provider", "openai"],
    )
    assert result.exit_code == 1
    assert "--codescanai-provider" in result.output and "--engine codescanai" in result.output
    assert "cfg" not in captured


def test_codescanai_env_alone_is_not_an_error(tmp_path, captured, monkeypatch):
    # CODESCANAI_* is often exported process-wide; it must not break the default engine.
    monkeypatch.setenv("CODESCANAI_PROVIDER", "openai")
    monkeypatch.setenv("CODESCANAI_HOST", "http://localhost")
    result = runner.invoke(app, ["scan", "octo/demo", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["cfg"].engine == "claude"


def test_missing_api_key_fails_before_any_review(tmp_path, captured, fake_bin):
    result = runner.invoke(
        app, ["run", "--targets-only", "--output-dir", str(tmp_path), "--engine", "codescanai"]
    )
    assert result.exit_code == 1
    assert "OPENAI_API_KEY" in result.output
    assert "cfg" not in captured


def test_missing_binary_fails_before_any_review(tmp_path, captured, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    monkeypatch.setattr(codescanai.shutil, "which", lambda cmd: None)
    result = runner.invoke(
        app, ["review", ".", "--output-dir", str(tmp_path), "--engine", "codescanai"]
    )
    assert result.exit_code == 1
    assert "pip install codescanai" in result.output
    assert "cfg" not in captured


def test_skill_with_codescanai_is_an_error(tmp_path, captured, fake_bin, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    result = runner.invoke(
        app,
        ["review", ".", "--output-dir", str(tmp_path), "--engine", "codescanai",
         "--skill", "owasp-top10"],
    )
    assert result.exit_code == 1
    assert "--skill" in result.output and "--engine claude" in result.output
    assert "cfg" not in captured


def test_claude_provider_with_codescanai_is_an_error(tmp_path, captured, fake_bin, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path), "--engine", "codescanai",
         "--provider", "openrouter"],
    )
    assert result.exit_code == 1
    assert "--codescanai-provider" in result.output
    assert "cfg" not in captured


def test_codescanai_ignores_claude_provider_keys(tmp_path, captured, fake_bin, monkeypatch):
    # An OpenRouter key in the shell must not turn into a Claude provider error here.
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or")
    monkeypatch.setenv("GEMINI_API_KEY", "gm")
    result = runner.invoke(
        app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--engine", "codescanai"]
    )
    assert result.exit_code == 0, result.output
    assert captured["cfg"].codescanai.provider == "gemini"


def test_codescanai_token_flag_does_not_exist(tmp_path):
    """A value-taking --codescanai-token flag would put the server token into argv
    (visible via ps / /proc/<pid>/cmdline). CODESCANAI_TOKEN is env-only."""
    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path), "--engine", "codescanai",
         "--codescanai-token", "tok"],
    )
    assert result.exit_code != 0
    assert "no such option" in result.output.lower()


def test_help_mentions_engine_on_all_three_commands():
    for cmd in ("run", "scan", "review"):
        # A wide terminal keeps rich from wrapping the long option names.
        result = runner.invoke(app, [cmd, "--help"], env={"COLUMNS": "200"})
        assert result.exit_code == 0
        assert "--engine" in result.output, cmd
        assert "--codescanai-provider" in result.output, cmd
