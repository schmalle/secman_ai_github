"""Run an autonomous Claude Code security review over a local repo directory.

The agent is restricted to read-only tools and a hermetic settings context, so untrusted
repository code is never executed and the host's user settings/CLAUDE.md do not leak in.
"""

from __future__ import annotations

import asyncio
import os
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

# Environment variables from secscan's own process that the review subprocess is
# allowed to see. Kept deliberately small: PATH/HOME so the `claude` CLI binary
# and its on-disk credentials (a logged-in claude.ai subscription) can be found,
# locale/tmp-dir plumbing that carries no secret material, and the three
# Anthropic-compatible provider-routing vars so `--provider anthropic` (the
# default, whose `extra_env` is empty) still authenticates via ANTHROPIC_API_KEY
# when no subscription login is present. `extra_env` (see providers.py) always
# overrides these on top for every other provider.
#
# IMPORTANT: the underlying SDK
# (`claude_agent_sdk._internal.transport.subprocess_cli.SubprocessCLITransport.connect`)
# unconditionally merges the *entire* parent process environment underneath
# whatever `ClaudeAgentOptions.env` we pass it -- `inherited_env = {k: v for k, v
# in os.environ.items() if k != "CLAUDECODE"}` is always the base layer, and our
# dict only overrides on top of that. So handing the SDK a small `env` dict does
# not, by itself, withhold anything from the untrusted review subprocess -- the
# only way to actually keep a variable out is to explicitly override it to ""
# ourselves, which is what `_subprocess_env` does below for every variable not
# on this allowlist. This is the control standing between a prompt injection in
# a scanned repo and secscan's own GITHUB_TOKEN, GITHUB_APP_PRIVATE_KEY,
# SECMAN_PASSWORD, SMTP_PASSWORD, DB_PASSWORD, etc.
_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "TZ",
        "TMPDIR",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_AUTH_TOKEN",
    }
)


def _subprocess_env(extra_env: dict[str, str] | None) -> dict[str, str]:
    """Build the explicit, minimal env for the review subprocess.

    Every variable currently set in secscan's own process is blanked to ""
    unless it is on `_ENV_ALLOWLIST` above or is one of the provider-routing
    overrides in `extra_env` (which always wins). See `_ENV_ALLOWLIST` for why
    blanking -- not simply omitting a key -- is required given how the SDK
    merges environments.
    """
    env = {name: "" for name in os.environ if name not in _ENV_ALLOWLIST}
    env.update({name: os.environ[name] for name in _ENV_ALLOWLIST if name in os.environ})
    if extra_env:
        env.update(extra_env)
    return env


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
        # Always set explicitly -- never leave unset -- so the subprocess never
        # falls back to the SDK's full-environment-inheritance default. See
        # `_subprocess_env` / `_ENV_ALLOWLIST` above.
        env=_subprocess_env(extra_env),
    )
    if max_cost_usd is not None:
        kwargs["max_budget_usd"] = max_cost_usd
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
