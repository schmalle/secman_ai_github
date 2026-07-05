"""Unit tests for review_repo's message handling, parsing, and counting.

The Claude Agent SDK `query` is replaced with a fake async generator so these tests
are deterministic and never hit the network.
"""

import secscan.reviewer as reviewer
from secscan.reviewer import review_repo


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


async def test_review_passes_env_overrides_to_options(tmp_path, monkeypatch):
    # ClaudeAgentOptions is constructed for real here, so this also verifies the
    # installed SDK accepts an `env` field.
    captured = {}
    _patch(monkeypatch, [FakeResult(result="", cost=0.0, turns=1)], captured)
    extra = {"ANTHROPIC_BASE_URL": "https://openrouter.ai/api", "ANTHROPIC_AUTH_TOKEN": "sk-or-x"}
    await review_repo(tmp_path, "octo/repo", extra_env=extra)
    assert captured["options"].env == extra


async def test_review_omits_env_when_no_overrides(tmp_path, monkeypatch):
    captured = {}
    _patch(monkeypatch, [FakeResult(result="", cost=0.0, turns=1)], captured)
    await review_repo(tmp_path, "octo/repo")
    assert not captured["options"].env  # unset/empty: Anthropic path untouched
