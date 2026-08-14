"""Run an autonomous Claude Code security review over a local repo directory.

The agent is restricted to read-only tools and a hermetic settings context, so untrusted
repository code is never executed and the host's user settings/CLAUDE.md do not leak in.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    query,
)

from .findings import Finding, filter_high_critical, parse_findings
from .prompts import SYSTEM_PROMPT, task_prompt

# Read-only tool allowlist. Everything else is denied (defense in depth + permission_mode).
# Agent/Task must stay denied: left open, the review model spawns sub-agents to explore
# the repo, which isn't bounded by max_turns the same way and made runs unpredictably slow.
READ_ONLY_TOOLS = ["Read", "Grep", "Glob"]
DENIED_TOOLS = ["Bash", "Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch", "Agent", "Task"]

# Default guard against a stalled agent (e.g. waiting on a permission prompt with
# no interactive terminal to answer it) hanging the review forever. This bounds
# the gap between messages, not total review duration, since reviews legitimately
# vary widely in length.
DEFAULT_IDLE_TIMEOUT_S = 900.0


@dataclass
class ReviewResult:
    findings: list[Finding] = field(default_factory=list)
    high_critical: list[Finding] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    total_findings: int = 0
    cost_usd: float = 0.0
    duration_s: float = 0.0
    num_turns: int = 0
    error: str = ""


def _build_options(
    repo_dir: Path,
    model: str,
    max_turns: int,
    max_cost_usd: float | None,
    extra_env: dict[str, str] | None = None,
) -> ClaudeAgentOptions:
    kwargs = dict(
        cwd=str(repo_dir),
        system_prompt=SYSTEM_PROMPT,
        allowed_tools=READ_ONLY_TOOLS,
        disallowed_tools=DENIED_TOOLS,
        permission_mode="default",
        model=model,
        max_turns=max_turns,
        setting_sources=[],  # hermetic: do not load host settings/CLAUDE.md
    )
    if max_cost_usd is not None:
        kwargs["max_budget_usd"] = max_cost_usd
    if extra_env:
        kwargs["env"] = extra_env  # e.g. OpenRouter base URL + auth token
    return ClaudeAgentOptions(**kwargs)


async def _iter_with_idle_timeout(
    messages: AsyncIterator, timeout_s: float
) -> AsyncIterator:
    """Re-yield messages, raising TimeoutError if none arrives within timeout_s.

    Bounds the gap between messages rather than total stream duration.
    """
    it = messages.__aiter__()
    while True:
        try:
            yield await asyncio.wait_for(it.__anext__(), timeout=timeout_s)
        except StopAsyncIteration:
            return


async def review_repo(
    repo_dir: Path,
    repo_full_name: str,
    *,
    model: str = "sonnet",
    max_turns: int = 60,
    max_cost_usd: float | None = None,
    extra_env: dict[str, str] | None = None,
    idle_timeout_s: float | None = DEFAULT_IDLE_TIMEOUT_S,
) -> ReviewResult:
    """Review one repository directory and return validated findings + run metadata."""
    result = ReviewResult()
    options = _build_options(Path(repo_dir), model, max_turns, max_cost_usd, extra_env)

    text_chunks: list[str] = []
    final_text = ""
    structured = None
    started = time.perf_counter()

    messages = query(prompt=task_prompt(repo_full_name), options=options)
    if idle_timeout_s:
        messages = _iter_with_idle_timeout(messages, idle_timeout_s)

    turn_count = 0
    try:
        async for message in messages:
            if isinstance(message, AssistantMessage):
                turn_count += 1
                tool_names = [b.name for b in message.content if isinstance(b, ToolUseBlock)]
                print(
                    f"    [{repo_full_name}] turn {turn_count}/{max_turns}: "
                    f"{', '.join(tool_names) if tool_names else 'thinking'}",
                    flush=True,
                )
                for block in message.content:
                    if isinstance(block, TextBlock):
                        text_chunks.append(block.text)
            elif isinstance(message, ResultMessage):
                result.cost_usd = message.total_cost_usd or 0.0
                result.num_turns = message.num_turns or 0
                final_text = message.result or ""
                structured = getattr(message, "structured_output", None)
                if message.is_error:
                    result.error = "; ".join(message.errors or []) or final_text or "agent reported error"
    except asyncio.TimeoutError:
        if not result.error:
            result.error = f"review stalled: no response from the agent for {idle_timeout_s:.0f}s"
    except Exception as exc:  # SDK / transport failure
        if not result.error:
            result.error = f"{type(exc).__name__}: {exc}"

    result.duration_s = time.perf_counter() - started

    # Prefer structured output, then the final result text, then accumulated assistant text.
    findings: list[Finding] = []
    for candidate in (structured, final_text, "\n".join(text_chunks)):
        if not candidate:
            continue
        findings = parse_findings(candidate)
        if findings:
            break

    result.findings = findings
    result.high_critical = filter_high_critical(findings)
    result.total_findings = len(findings)
    result.critical_count = sum(1 for f in result.high_critical if f.severity.value == "critical")
    result.high_count = sum(1 for f in result.high_critical if f.severity.value == "high")
    return result
