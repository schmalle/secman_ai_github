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


# --- codex / kimi-cli engines ------------------------------------------------------------


@pytest.fixture
def codex_ready(monkeypatch):
    from secscan import codex as codex_mod

    monkeypatch.setattr(codex_mod.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
    monkeypatch.setenv("OPENAI_API_KEY", "sk")


@pytest.fixture
def kimi_ready(monkeypatch):
    from secscan import kimi_cli as kimi_mod

    monkeypatch.setattr(kimi_mod.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
    monkeypatch.setenv("KIMI_API_KEY", "sk-kimi")


@pytest.fixture(autouse=True)
def _clean_cli_engine_env(monkeypatch):
    for var in ("CODEX_BIN", "CODEX_MODEL", "KIMI_BIN", "KIMI_MODEL", "KIMI_API_KEY",
                "KIMI_SHARE_DIR", "CODEX_HOME"):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize("argv", [["scan", "octo/demo"], ["run", "--targets-only"], ["review", "."]])
def test_engine_codex_flags_reach_config(argv, tmp_path, captured, codex_ready):
    result = runner.invoke(
        app,
        argv + ["--output-dir", str(tmp_path), "--engine", "codex", "--codex-bin", "npx @openai/codex",
                "--codex-arg=--oss", "--model", "gpt-5.4", "--skill", "owasp-top10"],
    )
    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.engine == "codex" and cfg.codescanai is None and cfg.kimi is None
    assert cfg.codex.bin == "npx @openai/codex"
    assert cfg.codex.extra_args == ("--oss",)
    assert cfg.codex.model == "gpt-5.4"
    assert [s.name for s in cfg.skills] == ["owasp-top10"]  # skills go into the prompt


def test_engine_kimi_cli_flags_reach_config(tmp_path, captured, kimi_ready):
    result = runner.invoke(
        app,
        ["scan", "octo/demo", "--output-dir", str(tmp_path), "--engine", "kimi-cli",
         "--kimi-bin", "uvx kimi-cli", "--kimi-arg=--thinking"],
    )
    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.engine == "kimi-cli" and cfg.codex is None
    assert cfg.kimi.bin == "uvx kimi-cli" and cfg.kimi.extra_args == ("--thinking",)
    assert cfg.kimi.model == "kimi-for-coding" and cfg.kimi.api_key == "sk-kimi"


def test_engine_flags_are_checked_against_the_engine(tmp_path, captured, codex_ready):
    result = runner.invoke(
        app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--engine", "codex", "--kimi-bin", "kimi"],
    )
    assert result.exit_code == 1 and "--kimi-bin" in result.output and "--engine kimi-cli" in result.output
    result = runner.invoke(app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--codex-arg=--oss"])
    assert result.exit_code == 1 and "--engine codex" in result.output
    assert "cfg" not in captured


def test_claude_provider_with_codex_is_an_error(tmp_path, captured, codex_ready):
    result = runner.invoke(
        app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--engine", "codex", "--provider", "openrouter"],
    )
    assert result.exit_code == 1 and "--provider" in result.output and "cfg" not in captured


def test_codex_missing_credentials_fails_before_any_review(tmp_path, captured, monkeypatch):
    from secscan import codex as codex_mod

    monkeypatch.setattr(codex_mod.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "nohome"))
    result = runner.invoke(app, ["review", ".", "--output-dir", str(tmp_path), "--engine", "codex"])
    assert result.exit_code == 1 and "codex login" in result.output and "cfg" not in captured


def test_kimi_missing_credentials_fails_before_any_review(tmp_path, captured, monkeypatch):
    from secscan import kimi_cli as kimi_mod

    monkeypatch.setattr(kimi_mod.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
    monkeypatch.setenv("KIMI_SHARE_DIR", str(tmp_path / "share"))
    result = runner.invoke(app, ["review", ".", "--output-dir", str(tmp_path), "--engine", "kimi-cli"])
    assert result.exit_code == 1 and "kimi login" in result.output and "cfg" not in captured


def test_engine_env_alone_is_not_an_error(tmp_path, captured, monkeypatch):
    monkeypatch.setenv("CODEX_BIN", "/opt/codex")
    monkeypatch.setenv("KIMI_BIN", "/opt/kimi")
    result = runner.invoke(app, ["scan", "octo/demo", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["cfg"].engine == "claude"


# --- --fix / --create-fix-prs -------------------------------------------------------------


def test_fix_flags_reach_config(tmp_path, captured):
    result = runner.invoke(
        app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--create-fix-prs", "--pr-draft", "--pr-prefix", "[acme]"],
    )
    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.fix is True and cfg.create_fix_prs is True  # --create-fix-prs implies --fix
    assert cfg.pr_draft is True and cfg.pr_prefix == "[acme]"


def test_fix_alone_does_not_open_prs(tmp_path, captured):
    result = runner.invoke(app, ["run", "--targets-only", "--output-dir", str(tmp_path), "--fix"])
    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.fix is True and cfg.create_fix_prs is False and cfg.pr_prefix == "secscan:"


def test_fix_defaults_off(tmp_path, captured):
    result = runner.invoke(app, ["scan", "octo/demo", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert captured["cfg"].fix is False and captured["cfg"].create_fix_prs is False


def test_create_fix_prs_needs_the_db(tmp_path, captured):
    result = runner.invoke(app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--no-db", "--create-fix-prs"])
    assert result.exit_code == 1 and "--no-db" in result.output and "--create-fix-prs" in result.output
    result = runner.invoke(app, ["review", ".", "--output-dir", str(tmp_path), "--create-fix-prs"])
    assert result.exit_code == 1 and "--store-db" in result.output
    assert "cfg" not in captured


def test_pr_draft_requires_create_fix_prs(tmp_path, captured):
    result = runner.invoke(app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--pr-draft"])
    assert result.exit_code == 1 and "--pr-draft" in result.output and "cfg" not in captured


def test_fix_with_codescanai_is_an_error(tmp_path, captured, fake_bin, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    result = runner.invoke(app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--engine", "codescanai", "--fix"])
    assert result.exit_code == 1 and "--fix" in result.output and "codescanai" in result.output
    assert "cfg" not in captured


def test_review_create_fix_prs_with_store_db_and_dry_run(tmp_path, captured):
    result = runner.invoke(
        app, ["review", ".", "--output-dir", str(tmp_path), "--store-db", "--create-fix-prs", "--dry-run",
              "--github-api-url", "https://ghes.example.com"],
    )
    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.create_fix_prs and cfg.dry_run and cfg.no_db is False
    assert cfg.github_api_url == "https://ghes.example.com"
    from secscan import dryrun

    assert dryrun.is_active()


def test_help_mentions_fix_and_engines_on_all_three_commands():
    for cmd in ("run", "scan", "review"):
        result = runner.invoke(app, [cmd, "--help"], env={"COLUMNS": "200"})
        assert result.exit_code == 0
        for flag in ("--fix", "--create-fix-prs", "--codex-bin", "--kimi-bin", "--pr-prefix"):
            assert flag in result.output, (cmd, flag)
