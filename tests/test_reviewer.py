"""Unit tests for review_repo's message handling, parsing, and counting.

The Claude Agent SDK `query` is replaced with a fake async generator so these tests
are deterministic and never hit the network.
"""

import asyncio
import os

import secscan.reviewer as reviewer
from secscan.reviewer import review_repo, _subprocess_env


class FakeText:
    def __init__(self, text):
        self.text = text


class FakeAssistant:
    def __init__(self, content):
        self.content = content


class FakeResult:
    def __init__(self, result, cost, turns, is_error=False, errors=None, structured_output=None):
        self.result = result
        self.total_cost_usd = cost
        self.num_turns = turns
        self.is_error = is_error
        self.errors = errors
        self.structured_output = structured_output


def _patch(monkeypatch, messages, captured=None):
    async def fake_query(*, prompt, options):
        if captured is not None:
            captured["options"] = options
        for m in messages:
            yield m

    monkeypatch.setattr(reviewer, "AssistantMessage", FakeAssistant)
    monkeypatch.setattr(reviewer, "ResultMessage", FakeResult)
    monkeypatch.setattr(reviewer, "TextBlock", FakeText)
    monkeypatch.setattr(reviewer, "query", fake_query)


async def test_review_counts_high_and_critical(tmp_path, monkeypatch):
    result_json = (
        "```json\n"
        '{"findings": ['
        '{"severity":"critical","title":"SQLi","description":"d","file_path":"app.py"},'
        '{"severity":"high","title":"secret","description":"d","file_path":"app.py"},'
        '{"severity":"low","title":"x","description":"d","file_path":"app.py"}'
        "]}\n```"
    )
    _patch(monkeypatch, [
        FakeAssistant([FakeText("reviewing...")]),
        FakeResult(result=result_json, cost=0.012, turns=4),
    ])

    res = await review_repo(tmp_path, "octo/repo")
    assert res.total_findings == 3
    assert res.critical_count == 1
    assert res.high_count == 1
    assert len(res.high_critical) == 2
    assert res.cost_usd == 0.012
    assert res.num_turns == 4
    assert res.error == ""


async def test_review_falls_back_to_structured_output(tmp_path, monkeypatch):
    structured = {"findings": [{"severity": "high", "title": "t", "description": "d", "file_path": "a"}]}
    _patch(monkeypatch, [
        FakeResult(result="", cost=0.0, turns=1, structured_output=structured),
    ])
    res = await review_repo(tmp_path, "octo/repo")
    assert res.high_count == 1


async def test_review_records_agent_error(tmp_path, monkeypatch):
    _patch(monkeypatch, [
        FakeResult(result="", cost=0.0, turns=1, is_error=True, errors=["boom"]),
    ])
    res = await review_repo(tmp_path, "octo/repo")
    assert "boom" in res.error
    assert res.total_findings == 0


async def test_review_uses_result_text_when_errors_list_is_empty(tmp_path, monkeypatch):
    # e.g. an invalid --model: the CLI reports is_error=True with no `errors`
    # entries, but a diagnostic `result` string. That's the useful message —
    # don't fall back to the generic "agent reported error".
    _patch(monkeypatch, [
        FakeResult(
            result="There's an issue with the selected model (z-ai/glm-5.2).",
            cost=0.0, turns=1, is_error=True, errors=[],
        ),
    ])
    res = await review_repo(tmp_path, "octo/repo")
    assert "z-ai/glm-5.2" in res.error


async def test_review_keeps_result_error_over_later_stream_exception(tmp_path, monkeypatch):
    # The SDK replaces a post-error-result ProcessError with its own generic
    # text (e.g. "Claude Code returned an error result: success"). Once the
    # ResultMessage has already given us the real diagnostic, a later
    # exception from the stream shouldn't clobber it.
    async def fake_query(*, prompt, options):
        yield FakeResult(
            result="There's an issue with the selected model (z-ai/glm-5.2).",
            cost=0.0, turns=1, is_error=True, errors=[],
        )
        raise RuntimeError("Claude Code returned an error result: success")

    monkeypatch.setattr(reviewer, "AssistantMessage", FakeAssistant)
    monkeypatch.setattr(reviewer, "ResultMessage", FakeResult)
    monkeypatch.setattr(reviewer, "TextBlock", FakeText)
    monkeypatch.setattr(reviewer, "query", fake_query)

    res = await review_repo(tmp_path, "octo/repo")
    assert "z-ai/glm-5.2" in res.error
    assert "success" not in res.error


async def test_review_passes_env_overrides_to_options(tmp_path, monkeypatch):
    # ClaudeAgentOptions is constructed for real here, so this also verifies the
    # installed SDK accepts an `env` field.
    captured = {}
    _patch(monkeypatch, [FakeResult(result="", cost=0.0, turns=1)], captured)
    extra = {"ANTHROPIC_BASE_URL": "https://openrouter.ai/api", "ANTHROPIC_AUTH_TOKEN": "sk-or-x"}
    await review_repo(tmp_path, "octo/repo", extra_env=extra)
    # extra_env always wins over the base allowlisted env (see _subprocess_env).
    result_env = captured["options"].env
    assert result_env["ANTHROPIC_BASE_URL"] == "https://openrouter.ai/api"
    assert result_env["ANTHROPIC_AUTH_TOKEN"] == "sk-or-x"


async def test_review_omits_env_when_no_overrides(tmp_path, monkeypatch):
    captured = {}
    _patch(monkeypatch, [FakeResult(result="", cost=0.0, turns=1)], captured)
    await review_repo(tmp_path, "octo/repo")
    # `env` is always set explicitly now (never left unset), but with no
    # provider override it should just be the base allowlisted env.
    result_env = captured["options"].env
    assert result_env  # non-empty: PATH/HOME etc. from the allowlist
    assert result_env.get("PATH") == os.environ.get("PATH")


async def test_review_times_out_when_agent_stalls(tmp_path, monkeypatch):
    # e.g. the agent is waiting on a permission prompt with no interactive
    # terminal to answer it: no more messages ever arrive.
    async def fake_query(*, prompt, options):
        await asyncio.sleep(10)
        yield FakeResult(result="", cost=0.0, turns=1)  # pragma: no cover

    monkeypatch.setattr(reviewer, "AssistantMessage", FakeAssistant)
    monkeypatch.setattr(reviewer, "ResultMessage", FakeResult)
    monkeypatch.setattr(reviewer, "TextBlock", FakeText)
    monkeypatch.setattr(reviewer, "query", fake_query)

    res = await review_repo(tmp_path, "octo/repo", idle_timeout_s=0.05)
    assert "stalled" in res.error
    assert "0" in res.error  # includes the timeout duration
    assert res.total_findings == 0


async def test_review_idle_timeout_disabled_by_zero(tmp_path, monkeypatch):
    _patch(monkeypatch, [FakeResult(result="", cost=0.0, turns=1)])
    res = await review_repo(tmp_path, "octo/repo", idle_timeout_s=0)
    assert res.error == ""


# --- Finding 2: the review subprocess must never inherit secscan's full
# environment. A prompt injection in a scanned repo runs against a
# Read/Grep/Glob-only agent, but that agent still inherits whatever env the
# subprocess is handed -- so a secret-like var that leaks in here could be
# read back out as "evidence" in a finding. See _ENV_ALLOWLIST in reviewer.py
# for why blanking (not just omitting a key) is required, given that the SDK
# itself always merges the full parent os.environ underneath `env`.


def test_subprocess_env_blanks_arbitrary_secret_like_vars(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_supersecrettoken1234567890")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----")
    monkeypatch.setenv("SECMAN_PASSWORD", "secman-admin-password")
    monkeypatch.setenv("SMTP_PASSWORD", "smtp-password-value")
    monkeypatch.setenv("DB_PASSWORD", "db-password-value")
    monkeypatch.setenv("SOME_RANDOM_SECRET_NOT_ON_ANY_ALLOWLIST", "should-never-reach-the-subprocess")

    env = _subprocess_env(extra_env=None)

    for name in (
        "GITHUB_TOKEN",
        "GITHUB_APP_PRIVATE_KEY",
        "SECMAN_PASSWORD",
        "SMTP_PASSWORD",
        "DB_PASSWORD",
        "SOME_RANDOM_SECRET_NOT_ON_ANY_ALLOWLIST",
    ):
        assert env.get(name, "") == "", f"{name} leaked into the review subprocess env: {env.get(name)!r}"


def test_subprocess_env_keeps_allowlisted_vars(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("HOME", "/home/reviewer")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real-key")

    env = _subprocess_env(extra_env=None)

    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == "/home/reviewer"
    assert env["ANTHROPIC_API_KEY"] == "sk-ant-real-key"


def test_subprocess_env_applies_extra_env_on_top_of_allowlist(monkeypatch):
    # extra_env (provider routing, see providers.py) must still be able to
    # both set new vars and override/neutralize allowlisted ones (e.g. the
    # "usecc" provider clears ANTHROPIC_API_KEY to "").
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real-key")
    monkeypatch.setenv("SOME_UNRELATED_SECRET", "must-not-leak")

    env = _subprocess_env(
        extra_env={
            "ANTHROPIC_API_KEY": "",
            "ANTHROPIC_BASE_URL": "https://openrouter.ai/api",
            "ANTHROPIC_AUTH_TOKEN": "sk-or-x",
        }
    )

    assert env["ANTHROPIC_API_KEY"] == ""
    assert env["ANTHROPIC_BASE_URL"] == "https://openrouter.ai/api"
    assert env["ANTHROPIC_AUTH_TOKEN"] == "sk-or-x"
    assert env.get("SOME_UNRELATED_SECRET", "") == ""


async def test_review_subprocess_options_never_leak_arbitrary_env_var(tmp_path, monkeypatch):
    # End-to-end through review_repo -> _build_options: a secret-shaped var
    # present in the process at review time must not show up in the options
    # handed to the SDK, even though _build_options always sets `env` now.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-required-for-default-provider")
    monkeypatch.setenv("SOME_OTHER_APP_SECRET_TOKEN", "must-not-reach-the-review-subprocess")

    captured = {}
    _patch(monkeypatch, [FakeResult(result="", cost=0.0, turns=1)], captured)
    await review_repo(tmp_path, "octo/repo")

    result_env = captured["options"].env
    assert result_env is not None  # env is always set explicitly now
    assert result_env["ANTHROPIC_API_KEY"] == "sk-ant-required-for-default-provider"
    assert result_env.get("SOME_OTHER_APP_SECRET_TOKEN", "") == ""
