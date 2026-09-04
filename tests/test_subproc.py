"""Unit tests for the shared streaming subprocess runner (secscan/subproc.py)."""

from __future__ import annotations

import sys

from secscan.subproc import BASE_ENV_ALLOWLIST, minimal_env, run_streaming


async def test_run_streaming_feeds_stdin_and_collects_both_streams(tmp_path):
    script = tmp_path / "s.py"
    script.write_text(
        "import sys\n"
        "data = sys.stdin.read()\n"
        "print('got', len(data))\n"
        "print('warn', file=sys.stderr)\n"
        "sys.exit(4)\n"
    )
    lines = []
    res = await run_streaming(
        [sys.executable, str(script)], cwd=tmp_path, env={"PATH": "/usr/bin"},
        idle_timeout_s=5, stdin_text="x" * 100_000, on_line=lambda tag, ln: lines.append((tag, ln)),
    )
    assert res.returncode == 4 and not res.timed_out
    assert res.stdout == ["got 100000"] and res.stderr == ["warn"]
    assert ("out", "got 100000") in lines and res.stderr_tail == "warn"


async def test_run_streaming_idle_timeout_kills_the_child(tmp_path):
    script = tmp_path / "s.py"
    script.write_text("import time; print('a', flush=True); time.sleep(10)\n")
    res = await run_streaming([sys.executable, str(script)], cwd=tmp_path, env={}, idle_timeout_s=0.2)
    assert res.timed_out and res.stdout == ["a"]
    assert res.returncode is not None


async def test_run_streaming_reports_missing_executable(tmp_path):
    res = await run_streaming(["/nonexistent/bin"], cwd=tmp_path, env={}, idle_timeout_s=1)
    assert res.start_error and res.returncode is None


def test_minimal_env_copies_only_allowlisted_and_requested(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy:3128")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("MY_KEY", "k")
    env = minimal_env({"MY_KEY"})
    assert env["PATH"] == "/usr/bin" and env["HTTPS_PROXY"] == "http://proxy:3128"
    assert env["MY_KEY"] == "k" and "GITHUB_TOKEN" not in env
    assert "GITHUB_TOKEN" not in BASE_ENV_ALLOWLIST
