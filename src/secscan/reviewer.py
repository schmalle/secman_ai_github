"""Run an autonomous Claude Code security review over a local repo directory.

The agent is restricted to read-only tools and a hermetic settings context, so untrusted
repository code is never executed and the host's user settings/CLAUDE.md do not leak in.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    query,
)

from .findings import Finding, filter_high_critical, parse_findings
from .prompts import SYSTEM_PROMPT, task_prompt

# Read-only tool allowlist. Everything else is denied (defense in depth + permission_mode).
READ_ONLY_TOOLS = ["Read", "Grep", "Glob"]
DENIED_TOOLS = ["Bash", "Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch"]


@dataclass
class ReviewResult:
    repo_full_name: str
    findings: list[Finding] = field(default_factory=list)
    high_critical: list[Finding] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    total_findings: int = 0
    cost_usd: float = 0.0
    duration_s: float = 0.0
    num_turns: int = 0
    raw_text: str = ""
    error: str = ""


def _build_options(repo_dir: Path, model: str, max_turns: int, max_cost_usd: float | None) -> ClaudeAgentOptions:
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
    return ClaudeAgentOptions(**kwargs)


async def review_repo(
    repo_dir: Path,
    repo_full_name: str,
    *,
    model: str = "sonnet",
    max_turns: int = 60,
    max_cost_usd: float | None = None,
) -> ReviewResult:
    """Review one repository directory and return validated findings + run metadata."""
    result = ReviewResult(repo_full_name=repo_full_name)
    options = _build_options(Path(repo_dir), model, max_turns, max_cost_usd)

    text_chunks: list[str] = []
    final_text = ""
    structured = None
    started = time.perf_counter()

    try:
        async for message in query(prompt=task_prompt(repo_full_name), options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        text_chunks.append(block.text)
            elif isinstance(message, ResultMessage):
                result.cost_usd = message.total_cost_usd or 0.0
                result.num_turns = message.num_turns or 0
                final_text = message.result or ""
                structured = getattr(message, "structured_output", None)
                if message.is_error:
                    result.error = "; ".join(message.errors or []) or "agent reported error"
    except Exception as exc:  # SDK / transport failure
        result.error = f"{type(exc).__name__}: {exc}"

    result.duration_s = time.perf_counter() - started
    result.raw_text = final_text or "\n".join(text_chunks)

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
