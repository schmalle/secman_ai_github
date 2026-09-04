"""Unit tests for the CodeScanAI review engine (secscan/codescanai.py).

The real `codescanai` CLI is never run: `review_repo` tests point `--codescanai-bin`
at a small Python script that reproduces CodeScanAI 0.1.4's stdout/stderr shape
(one `Scanning file:` log line per file, per-file Markdown finding blocks), so the
suite stays offline and deterministic.
"""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest

from secscan import codescanai
from secscan.codescanai import (
    CUSTOM_PLACEHOLDER_TOKEN,
    CodeScanAIConfig,
    build_command,
    map_severity,
    parse_report,
    resolve_config,
    review_repo,
    subprocess_env,
)
from secscan.config import ConfigError
from secscan.findings import Severity

_ENV_VARS = (
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "CODESCANAI_PROVIDER",
    "CODESCANAI_MODEL",
    "CODESCANAI_HOST",
    "CODESCANAI_PORT",
    "CODESCANAI_ENDPOINT",
    "CODESCANAI_TOKEN",
    "CODESCANAI_BIN",
    "CODESCANAI_DEFAULT_SEVERITY",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def fake_bin(monkeypatch):
    """Pretend `codescanai` is installed so resolve_config's PATH check passes."""
    monkeypatch.setattr(codescanai.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")


# --- exactly what CodeScanAI 0.1.4 printed against a fake OpenAI-compatible server
SAMPLE_REPORT = textwrap.dedent(
    """\

    --- Vulnerabilities found in app.py ---
      - **Line 3: [Critical] SQL Injection**
      - **Issue**: User input concatenated into SQL.
    Second line of description.
      - **Fix**: Use parameters.
      - **[moderate] Missing Authorization**
      - **Issue**: No auth on find().
      - **Fix**: Add auth.


    --- Vulnerabilities found in lib/crypto.js ---
      - **Line 12: [High] Weak Hashing**
      - **Issue**: MD5 used for passwords.
      - **Fix**: Use bcrypt.
    """
)


# --- resolve_config -----------------------------------------------------------------


def test_auto_prefers_openai_when_key_present(monkeypatch, fake_bin):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    monkeypatch.setenv("GEMINI_API_KEY", "gm")
    cfg = resolve_config()
    assert cfg.provider == "openai"
    assert cfg.model is None  # CodeScanAI's own default
    assert cfg.bin == "codescanai"
    assert cfg.default_severity is Severity.MEDIUM


def test_auto_falls_back_to_gemini(monkeypatch, fake_bin):
    monkeypatch.setenv("GEMINI_API_KEY", "gm")
    assert resolve_config().provider == "gemini"


def test_auto_accepts_google_api_key_alias(monkeypatch, fake_bin):
    monkeypatch.setenv("GOOGLE_API_KEY", "gm")
    assert resolve_config().provider == "gemini"


def test_auto_without_any_key_is_a_config_error(fake_bin):
    with pytest.raises(ConfigError, match="OPENAI_API_KEY"):
        resolve_config()


def test_auto_never_picks_custom(monkeypatch, fake_bin):
    monkeypatch.setenv("CODESCANAI_HOST", "http://localhost")
    with pytest.raises(ConfigError):
        resolve_config()


def test_forced_openai_without_key_raises(fake_bin):
    with pytest.raises(ConfigError, match="OPENAI_API_KEY"):
        resolve_config(provider="openai")


def test_forced_gemini_without_key_raises(fake_bin):
    with pytest.raises(ConfigError, match="GEMINI_API_KEY"):
        resolve_config(provider="gemini")


def test_unknown_provider_raises(fake_bin):
    with pytest.raises(ConfigError, match="codescanai-provider"):
        resolve_config(provider="anthropic")


def test_provider_from_env(monkeypatch, fake_bin):
    monkeypatch.setenv("CODESCANAI_PROVIDER", "custom")
    monkeypatch.setenv("CODESCANAI_HOST", "http://localhost")
    monkeypatch.setenv("CODESCANAI_PORT", "11434")
    monkeypatch.setenv("CODESCANAI_ENDPOINT", "/v1")
    monkeypatch.setenv("CODESCANAI_TOKEN", "tok")
    monkeypatch.setenv("CODESCANAI_MODEL", "llama3")
    cfg = resolve_config()
    assert cfg.provider == "custom"
    assert (cfg.host, cfg.port, cfg.endpoint, cfg.token, cfg.model) == (
        "http://localhost", 11434, "/v1", "tok", "llama3"
    )
    assert cfg.base_url == "http://localhost:11434/v1"


def test_flags_win_over_env(monkeypatch, fake_bin):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    monkeypatch.setenv("CODESCANAI_PROVIDER", "gemini")
    monkeypatch.setenv("CODESCANAI_MODEL", "gpt-4o-mini")
    cfg = resolve_config(provider="openai", model="gpt-4o")
    assert cfg.provider == "openai"
    assert cfg.model == "gpt-4o"


def test_anthropic_alias_means_provider_default(monkeypatch, fake_bin):
    # secscan's --model defaults to "sonnet"; CodeScanAI has no such alias.
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    assert resolve_config(model="sonnet").model is None
    monkeypatch.setenv("CODESCANAI_MODEL", "gpt-4o")
    assert resolve_config(model="sonnet").model == "gpt-4o"
    assert resolve_config(model="gpt-4.1").model == "gpt-4.1"


def test_custom_requires_host(fake_bin):
    with pytest.raises(ConfigError, match="codescanai-host"):
        resolve_config(provider="custom")


def test_custom_host_needs_scheme(fake_bin):
    with pytest.raises(ConfigError, match="http://"):
        resolve_config(provider="custom", host="localhost")


def test_host_flags_only_apply_to_custom(monkeypatch, fake_bin):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    with pytest.raises(ConfigError, match="only apply"):
        resolve_config(provider="openai", host="http://localhost")


def test_bad_port_is_a_config_error(fake_bin):
    with pytest.raises(ConfigError, match="codescanai-port"):
        resolve_config(provider="custom", host="http://h", port="abc")
    with pytest.raises(ConfigError, match="codescanai-port"):
        resolve_config(provider="custom", host="http://h", port=70000)


def test_base_url_without_port_or_endpoint(fake_bin):
    cfg = resolve_config(provider="custom", host="https://llm.internal/")
    assert cfg.base_url == "https://llm.internal"
    cfg = resolve_config(provider="custom", host="https://llm.internal", endpoint="v1/")
    assert cfg.base_url == "https://llm.internal/v1"


def test_default_severity_validated(monkeypatch, fake_bin):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    assert resolve_config(default_severity="HIGH").default_severity is Severity.HIGH
    monkeypatch.setenv("CODESCANAI_DEFAULT_SEVERITY", "low")
    assert resolve_config().default_severity is Severity.LOW
    with pytest.raises(ConfigError, match="default-severity"):
        resolve_config(default_severity="urgent")


def test_missing_binary_is_a_config_error(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    monkeypatch.setattr(codescanai.shutil, "which", lambda cmd: None)
    with pytest.raises(ConfigError, match="pip install codescanai"):
        resolve_config()


def test_bin_may_be_a_command_line(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    seen = {}
    monkeypatch.setattr(codescanai.shutil, "which", lambda cmd: seen.setdefault("cmd", cmd))
    cfg = resolve_config(bin="python3 -m core.runner_v2")
    assert seen["cmd"] == "python3"  # only the executable is looked up
    assert cfg.argv0 == ["python3", "-m", "core.runner_v2"]


def test_bin_from_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    monkeypatch.setenv("CODESCANAI_BIN", "/opt/tools/codescanai")
    monkeypatch.setattr(codescanai.shutil, "which", lambda cmd: cmd)
    assert resolve_config().bin == "/opt/tools/codescanai"


# --- build_command / subprocess_env -------------------------------------------------


def test_build_command_shape():
    cfg = CodeScanAIConfig(provider="openai", model="gpt-4o", extra_args=("--changes_only",))
    argv = build_command(cfg, Path("/work/repo"))
    assert argv == [
        "codescanai", "--provider", "openai", "--directory", "/work/repo",
        "--model", "gpt-4o", "--changes_only",
    ]


def test_build_command_never_puts_host_or_token_on_argv():
    cfg = CodeScanAIConfig(
        provider="custom", host="http://localhost", port=11434, endpoint="/v1", token="secret"
    )
    argv = build_command(cfg, Path("/work/repo"))
    assert "secret" not in " ".join(argv)
    assert "--host" not in argv and "--token" not in argv and "--port" not in argv


def test_subprocess_env_forwards_only_the_active_providers_credential(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    monkeypatch.setenv("GEMINI_API_KEY", "gm")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("SECMAN_PASSWORD", "pw")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    env = subprocess_env(CodeScanAIConfig(provider="openai"))
    assert env["OPENAI_API_KEY"] == "sk-openai"
    for name in ("GEMINI_API_KEY", "GITHUB_TOKEN", "SECMAN_PASSWORD", "ANTHROPIC_API_KEY"):
        assert name not in env
    assert env["PYTHONUNBUFFERED"] == "1"
    assert env["PATH"] == os.environ["PATH"]


def test_subprocess_env_gemini(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    monkeypatch.setenv("GEMINI_API_KEY", "gm")
    env = subprocess_env(CodeScanAIConfig(provider="gemini"))
    assert env["GEMINI_API_KEY"] == "gm"
    assert "OPENAI_API_KEY" not in env


def test_subprocess_env_custom_injects_base_url_and_token(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-openai-key")
    cfg = CodeScanAIConfig(
        provider="custom", host="http://localhost", port=11434, endpoint="/v1", token="tok"
    )
    env = subprocess_env(cfg)
    assert env["OPENAI_BASE_URL"] == "http://localhost:11434/v1"
    assert env["OPENAI_API_KEY"] == "tok"  # the real OpenAI key never reaches a custom server


def test_subprocess_env_custom_without_token_uses_placeholder(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-openai-key")
    env = subprocess_env(CodeScanAIConfig(provider="custom", host="http://localhost"))
    assert env["OPENAI_API_KEY"] == CUSTOM_PLACEHOLDER_TOKEN


def test_subprocess_env_keeps_proxy_and_ca_settings(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy:3128")
    monkeypatch.setenv("SSL_CERT_FILE", "/etc/ca.pem")
    env = subprocess_env(CodeScanAIConfig(provider="openai"))
    assert env["HTTPS_PROXY"] == "http://proxy:3128"
    assert env["SSL_CERT_FILE"] == "/etc/ca.pem"


# --- map_severity / parse_report --------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Critical", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        (" medium ", Severity.MEDIUM),
        ("Low", Severity.LOW),
        ("Info", Severity.INFO),
        ("Moderate", Severity.MEDIUM),
        ("Severe", Severity.HIGH),
        ("Informational", Severity.INFO),
        ("HIGH SEVERITY", Severity.HIGH),
        ("critical/high", Severity.CRITICAL),
        ("Medium-High", Severity.HIGH),
        ("", Severity.MEDIUM),
        (None, Severity.MEDIUM),
        ("P1", Severity.MEDIUM),
    ],
)
def test_map_severity(text, expected):
    assert map_severity(text) is expected


def test_map_severity_default_is_configurable():
    assert map_severity("P1", default=Severity.HIGH) is Severity.HIGH


def test_parse_report_reads_v2_blocks():
    findings = parse_report(SAMPLE_REPORT)
    assert [(f.file_path, f.severity, f.title, f.line_range) for f in findings] == [
        ("app.py", Severity.CRITICAL, "SQL Injection", "3"),
        ("app.py", Severity.MEDIUM, "Missing Authorization", ""),
        ("lib/crypto.js", Severity.HIGH, "Weak Hashing", "12"),
    ]
    sqli = findings[0]
    assert sqli.description == "User input concatenated into SQL.\nSecond line of description."
    assert sqli.recommendation == "Use parameters."
    assert sqli.category == "SQL Injection"
    assert sqli.confidence == "medium"


def test_parse_report_default_severity_applies_to_unmapped_text():
    report = (
        "--- Vulnerabilities found in a.py ---\n"
        "  - **[P1] Thing**\n  - **Issue**: i\n  - **Fix**: f\n"
    )
    assert parse_report(report)[0].severity is Severity.MEDIUM
    assert parse_report(report, Severity.HIGH)[0].severity is Severity.HIGH


def test_parse_report_empty_and_prose_only():
    assert parse_report("") == []
    assert parse_report("2026-09-04 INFO No vulnerabilities found in x.\n") == []


def test_parse_report_header_without_items_is_not_json_fallback():
    # A file header with nothing under it means "parsed, zero findings" — do not go
    # hunting for JSON in the text.
    assert parse_report("--- Vulnerabilities found in a.py ---\n{\"findings\": []}") == []


def test_parse_report_falls_back_to_secscan_json_contract():
    text = (
        "some log\n```json\n{\"findings\": [{\"severity\": \"high\", \"title\": \"t\", "
        "\"description\": \"d\", \"file_path\": \"x.py\"}]}\n```"
    )
    findings = parse_report(text)
    assert len(findings) == 1 and findings[0].severity is Severity.HIGH


def test_parse_report_item_missing_issue_still_yields_a_finding():
    report = "--- Vulnerabilities found in a.py ---\n  - **Line 7: [High] Bad thing**\n"
    (f,) = parse_report(report)
    assert f.title == "Bad thing" and f.description == "Bad thing" and f.line_range == "7"


def test_parse_report_redacts_secret_material_in_descriptions():
    report = (
        "--- Vulnerabilities found in cfg.py ---\n"
        "  - **[High] Hardcoded credential**\n"
        "  - **Issue**: AWS key AKIAIOSFODNN7EXAMPLE is committed\n"
        "  - **Fix**: rotate it\n"
    )
    (f,) = parse_report(report)
    assert "AKIAIOSFODNN7EXAMPLE" not in f.description


# --- review_repo with a fake codescanai executable --------------------------------------

_FAKE_SCANNER = textwrap.dedent(
    """\
    import argparse, os, sys, time
    p = argparse.ArgumentParser()
    p.add_argument("--provider", required=True)
    p.add_argument("--directory", default=".")
    p.add_argument("--model")
    p.add_argument("--changes_only", action="store_true")
    a = p.parse_args()
    mode = os.environ.get("FAKE_MODE", "ok")
    # record how we were invoked, for the assertions
    with open(os.environ["FAKE_LOG"], "w") as fh:
        fh.write(repr({"argv": sys.argv[1:], "cwd": os.getcwd(),
                       "env": {k: v for k, v in os.environ.items()
                               if k.startswith(("OPENAI", "GEMINI", "GITHUB", "SECMAN"))},
                       "files": sorted(os.path.relpath(os.path.join(r, f), a.directory)
                                       for r, _, fs in os.walk(a.directory) for f in fs)}))
    if mode == "crash":
        sys.stderr.write("Traceback...\\nValueError: OpenAI API key is not set\\n")
        sys.exit(1)
    if mode == "stall":
        time.sleep(30)
    files = sorted(os.path.relpath(os.path.join(r, f), a.directory)
                   for r, _, fs in os.walk(a.directory) for f in fs)
    for name in files:
        sys.stderr.write(f"2026-09-04 07:22:49,942 - INFO - Scanning file: {name} ...\\n")
        if mode == "all_errors" or (mode == "some_errors" and name.endswith(".md")):
            sys.stderr.write(f"2026-09-04 07:22:50,871 - ERROR - Error scanning {name}: Connection error.\\n")
            continue
        if name.endswith("app.py"):
            print("\\n--- Vulnerabilities found in app.py ---")
            print("  - **Line 3: [Critical] SQL Injection**")
            print("  - **Issue**: concat")
            print("  - **Fix**: params")
            print("  - **[moderate] Missing Authorization**")
            print("  - **Issue**: none")
            print("  - **Fix**: add")
            print()
        else:
            sys.stderr.write(f"2026-09-04 07:22:50,070 - INFO - No vulnerabilities found in {name}.\\n")
    """
)


@pytest.fixture
def fake_scanner(tmp_path, monkeypatch):
    script = tmp_path / "fake_codescanai.py"
    script.write_text(_FAKE_SCANNER)
    log = tmp_path / "invocation.log"
    monkeypatch.setenv("FAKE_LOG", str(log))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    (repo / "README.md").write_text("hi\n")
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("[core]\n")

    def make(**overrides):
        kwargs = dict(provider="openai", bin=f"{sys.executable} {script}")
        kwargs.update(overrides)
        return CodeScanAIConfig(**kwargs)

    def read_log():
        return eval(log.read_text())

    return repo, make, read_log


# FAKE_LOG/FAKE_MODE must reach the script: extend the allowlist for these tests only.
@pytest.fixture(autouse=True)
def _allow_fake_vars(monkeypatch):
    monkeypatch.setattr(
        codescanai, "_ENV_ALLOWLIST", codescanai._ENV_ALLOWLIST | {"FAKE_LOG", "FAKE_MODE"}
    )


async def test_review_repo_parses_findings_and_writes_report(fake_scanner, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    repo, make, read_log = fake_scanner
    report = tmp_path / "out" / "codescanai-report.md"

    res = await review_repo(repo, "octo/repo", cfg=make(), report_path=report)

    assert res.error == ""
    assert res.total_findings == 2
    assert res.critical_count == 1 and res.high_count == 0
    assert [f.severity for f in res.findings] == [Severity.CRITICAL, Severity.MEDIUM]
    assert res.num_turns == 2  # files scanned: app.py + README.md
    assert res.cost_usd == 0.0
    assert res.duration_s > 0
    assert "SQL Injection" in report.read_text()


async def test_review_repo_scans_a_copy_without_dot_git(fake_scanner, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    repo, make, read_log = fake_scanner

    await review_repo(repo, "octo/repo", cfg=make())

    log = read_log()
    assert log["files"] == ["README.md", "app.py"]  # .git/config not scanned
    scanned = Path(log["argv"][log["argv"].index("--directory") + 1])
    assert scanned != repo and not scanned.exists()  # temp copy, cleaned up
    assert log["env"]["OPENAI_API_KEY"] == "sk"
    assert "GITHUB_TOKEN" not in log["env"]


async def test_review_repo_scans_in_place_without_dot_git(fake_scanner, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    repo, make, read_log = fake_scanner
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "app.py").write_text("x\n")

    await review_repo(plain, "local/plain", cfg=make())

    log = read_log()
    assert Path(log["argv"][log["argv"].index("--directory") + 1]) == plain


async def test_review_repo_custom_provider_env_injection(fake_scanner, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-must-not-leak")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_must_not_leak")
    repo, make, read_log = fake_scanner
    cfg = make(provider="custom", host="http://localhost", port=11434, endpoint="/v1", token="tok")

    res = await review_repo(repo, "octo/repo", cfg=cfg)

    assert res.error == ""
    log = read_log()
    assert log["env"]["OPENAI_BASE_URL"] == "http://localhost:11434/v1"
    assert log["env"]["OPENAI_API_KEY"] == "tok"
    assert "GITHUB_TOKEN" not in log["env"]
    assert "--host" not in log["argv"] and "tok" not in log["argv"]
    assert log["argv"][:2] == ["--provider", "custom"]


async def test_review_repo_passes_model_and_extra_args(fake_scanner, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    repo, make, read_log = fake_scanner

    await review_repo(repo, "octo/repo", cfg=make(model="gpt-4o", extra_args=("--changes_only",)))

    argv = read_log()["argv"]
    assert argv[argv.index("--model") + 1] == "gpt-4o"
    assert argv[-1] == "--changes_only"


async def test_review_repo_nonzero_exit_is_an_error(fake_scanner, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    monkeypatch.setenv("FAKE_MODE", "crash")
    repo, make, _ = fake_scanner

    res = await review_repo(repo, "octo/repo", cfg=make())

    assert "status 1" in res.error
    assert "OpenAI API key is not set" in res.error
    assert res.total_findings == 0


async def test_review_repo_every_file_failing_is_an_error_despite_exit_zero(fake_scanner, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    monkeypatch.setenv("FAKE_MODE", "all_errors")
    repo, make, _ = fake_scanner

    res = await review_repo(repo, "octo/repo", cfg=make())

    assert "could not scan any file" in res.error
    assert "Connection error" in res.error


async def test_review_repo_partial_file_errors_are_a_warning_not_an_error(fake_scanner, monkeypatch, capsys):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    monkeypatch.setenv("FAKE_MODE", "some_errors")
    repo, make, _ = fake_scanner

    res = await review_repo(repo, "octo/repo", cfg=make())

    assert res.error == ""
    assert res.critical_count == 1
    assert "1 of 2 files could not be scanned" in capsys.readouterr().out


async def test_review_repo_idle_timeout_kills_a_stalled_scan(fake_scanner, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk")
    monkeypatch.setenv("FAKE_MODE", "stall")
    repo, make, _ = fake_scanner

    res = await review_repo(repo, "octo/repo", cfg=make(), idle_timeout_s=0.5)

    assert "stalled" in res.error
    assert res.duration_s < 20


async def test_review_repo_missing_executable_is_an_error(fake_scanner):
    repo, make, _ = fake_scanner

    res = await review_repo(repo, "octo/repo", cfg=make(bin="/nonexistent/codescanai"))

    assert "cannot start CodeScanAI" in res.error
    assert res.total_findings == 0
