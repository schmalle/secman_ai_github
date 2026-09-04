"""OpenAI Codex CLI as a review/fix engine (`--engine codex`).

[Codex CLI](https://github.com/openai/codex) (`npm install -g @openai/codex`) is
OpenAI's terminal coding agent. `codex exec` runs it non-interactively: the prompt
goes in, the agent explores the directory with its own tools, and its final message
comes out. This module drives that over the same clone the other engines get, with
secscan's prompt and JSON contract, and returns the same `ReviewResult` (review) or
`AgentRun` (fix) the rest of the pipeline consumes.

What is pinned here, and why:

- **Read-only sandbox for reviews, workspace-write for fixes.** `codex exec` has no
  way to remove its shell tool, so unlike the Claude engine the model *can* run
  commands. `--sandbox read-only` confines them to Codex's own OS sandbox (no writes,
  no network); `workspace-write` (the fix step) allows writes under the repository
  only — `.git/` stays protected and network stays off. Approvals are `never` in exec
  mode, so nothing can block waiting for a human. This is weaker isolation than the
  Claude engine's tool-restricted agent; the README says so.
- **The repository's `AGENTS.md` is never loaded.** Codex reads project instruction
  files from the working directory by default — for a scanned repo, that is
  attacker-controlled text placed straight into the agent's instructions.
  `-c project_doc_max_bytes=0` turns it off. `--ephemeral` keeps the run out of the
  session store, `--skip-git-repo-check` lets non-git directories be reviewed.
- **Nothing secret on argv.** Auth is `OPENAI_API_KEY` or the `codex login` state in
  `$CODEX_HOME/auth.json`; the prompt (which can be large once skill packs are
  appended) goes through stdin (`-`), never as an argument.
- **Minimal environment.** Only `subproc.BASE_ENV_ALLOWLIST` plus `OPENAI_API_KEY`,
  `OPENAI_BASE_URL` and `CODEX_HOME` reach the subprocess; secscan's GitHub/DB/secman/
  SMTP secrets and the other engines' keys do not.
- **The final message is read from a file, not scraped.** `-o <file>` receives the
  agent's last message verbatim; `--json` streams events to stdout, which is what
  drives the progress lines and the idle timeout. If the file is empty, the last
  `agent_message` event is used instead.

Model names are Codex/OpenAI model IDs (`gpt-5.4`, `o3`, …); secscan's default
`sonnet` alias means "Codex's own default model" unless `CODEX_MODEL` is set.
Anything else — a custom `model_provider`, reasoning effort, an OSS provider via
`--oss` — is passed through with `--codex-arg`, matching how Codex itself is
configured. Tested against Codex CLI 0.153; `exec`, `--json`, `-o`, `-C`, `-s`,
`--skip-git-repo-check` and `-c` have been stable across the 0.x line.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .config import ConfigError, _env
from .findings import Finding, Severity, filter_high_critical, parse_findings
from .prompts import fix_prompt_for_cli, review_prompt_for_cli
from .reviewer import DEFAULT_IDLE_TIMEOUT_S, AgentRun, ReviewResult
from .skills import Skill, render_skills_prompt
from .subproc import minimal_env, run_streaming

ENGINE_NAME = "codex"
DEFAULT_BIN = "codex"
DEFAULT_CODEX_HOME = "~/.codex"

_ANTHROPIC_ALIASES = ("sonnet", "opus", "haiku")
_ENV_EXTRA = frozenset({"OPENAI_API_KEY", "OPENAI_BASE_URL", "CODEX_HOME"})


@dataclass(frozen=True)
class CodexConfig:
    """Resolved Codex settings (flags first, then CODEX_* env)."""

    bin: str = DEFAULT_BIN  # command line (shlex-split), e.g. "npx @openai/codex"
    model: str | None = None  # None = Codex's default model
    extra_args: tuple[str, ...] = ()  # raw pass-through after secscan's own flags
    auth: str = "api-key"  # "api-key" (OPENAI_API_KEY) or "login" (codex login)

    @property
    def argv0(self) -> list[str]:
        return shlex.split(self.bin)

    @property
    def endpoint_label(self) -> str:
        base = _env("OPENAI_BASE_URL")
        where = f" ({base})" if base else ""
        return f"Codex CLI, {self.auth}{where}"


def codex_home() -> Path:
    return Path(_env("CODEX_HOME") or DEFAULT_CODEX_HOME).expanduser()


def resolve_config(
    bin: str | None = None,
    model: str | None = None,
    extra_args: Sequence[str] | None = None,
) -> CodexConfig:
    """Resolve flags against the environment and fail fast on anything unusable.

    Runs before any clone, so a missing executable or a Codex that has neither an
    API key nor a stored login is a clean config error, not a failed repo record.
    """
    command = (bin or _env("CODEX_BIN") or DEFAULT_BIN).strip()
    try:
        argv0 = shlex.split(command)
    except ValueError as exc:
        raise ConfigError(f"--codex-bin is not a valid command line: {exc}") from exc
    if not argv0:
        raise ConfigError("--codex-bin must name the codex executable")
    if shutil.which(argv0[0]) is None:
        raise ConfigError(
            f"Codex CLI executable not found: {argv0[0]!r}. Install it with "
            "`npm install -g @openai/codex`, or point --codex-bin / CODEX_BIN at it"
        )

    if _env("OPENAI_API_KEY"):
        auth = "api-key"
    elif (codex_home() / "auth.json").is_file():
        auth = "login"
    else:
        raise ConfigError(
            "--engine codex needs credentials: set OPENAI_API_KEY, or run `codex login` "
            f"(no auth.json under {codex_home()})"
        )

    if model in _ANTHROPIC_ALIASES:
        model = None
    model = model or _env("CODEX_MODEL") or None

    return CodexConfig(
        bin=command, model=model, extra_args=tuple(extra_args or ()), auth=auth
    )


def build_command(
    cfg: CodexConfig, directory: Path, last_message_path: Path, *, write: bool = False
) -> list[str]:
    """The argv for one `codex exec`; the prompt itself arrives on stdin (`-`)."""
    argv = list(cfg.argv0)
    argv += [
        "exec",
        "--json",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox", "workspace-write" if write else "read-only",
        "-C", str(directory),
        # Never read the scanned repository's AGENTS.md into the instructions.
        "-c", "project_doc_max_bytes=0",
        "-o", str(last_message_path),
    ]
    if write:
        argv += ["-c", "sandbox_workspace_write.network_access=false"]
    if cfg.model:
        argv += ["-m", cfg.model]
    argv += list(cfg.extra_args)
    argv.append("-")
    return argv


def subprocess_env(cfg: CodexConfig) -> dict[str, str]:
    """Minimal environment for the Codex subprocess (see module docstring)."""
    env = minimal_env(_ENV_EXTRA)
    env.setdefault("NO_COLOR", "1")
    return env


# --- event stream ------------------------------------------------------------------


def _item_summary(item: dict) -> str:
    kind = item.get("type", "")
    if kind == "command_execution":
        cmd = " ".join(str(item.get("command", "")).split())
        return f"shell: {cmd[:80]}"
    if kind == "file_change":
        changes = item.get("changes") or []
        paths = [str(c.get("path", "")) for c in changes if isinstance(c, dict)]
        return "edit: " + ", ".join(p for p in paths if p)[:80]
    if kind == "agent_message":
        return "message"
    if kind == "reasoning":
        return "thinking"
    return kind or "event"


@dataclass
class _Stream:
    turns: int = 0
    last_message: str = ""
    errors: list[str] = None  # type: ignore[assignment]
    usage: dict | None = None

    def __post_init__(self) -> None:
        self.errors = []


def _feed(stream: _Stream, line: str, label: str) -> None:
    try:
        event = json.loads(line)
    except ValueError:
        return  # a log line on stdout, not an event
    if not isinstance(event, dict):
        return
    kind = event.get("type", "")
    if kind == "item.completed":
        item = event.get("item") or {}
        if not isinstance(item, dict):
            return
        if item.get("type") == "agent_message":
            stream.last_message = str(item.get("text") or "")
        if item.get("type") == "error":
            stream.errors.append(str(item.get("message") or "error"))
            return
        if item.get("type") in ("command_execution", "file_change", "agent_message"):
            stream.turns += 1
            print(f"    [{label}] step {stream.turns}: {_item_summary(item)}", flush=True)
    elif kind == "error":
        stream.errors.append(str(event.get("message") or "error"))
    elif kind == "turn.failed":
        err = event.get("error") or {}
        stream.errors.append(str(err.get("message") if isinstance(err, dict) else err))
    elif kind == "turn.completed":
        usage = event.get("usage")
        if isinstance(usage, dict):
            stream.usage = usage


async def _run(
    cfg: CodexConfig,
    repo_dir: Path,
    prompt: str,
    *,
    label: str,
    idle_timeout_s: float | None,
    write: bool,
) -> AgentRun:
    run = AgentRun()
    started = time.perf_counter()
    stream = _Stream()
    repo_dir = Path(repo_dir).resolve()
    tmp = tempfile.mkdtemp(prefix="secscan-codex-")
    last_path = Path(tmp) / "last-message.md"
    try:
        argv = build_command(cfg, Path(repo_dir), last_path, write=write)

        def on_line(tag: str, line: str) -> None:
            if tag == "out":
                _feed(stream, line, label)

        res = await run_streaming(
            argv,
            cwd=repo_dir,
            env=subprocess_env(cfg),
            idle_timeout_s=idle_timeout_s,
            stdin_text=prompt,
            on_line=on_line,
        )
        if res.start_error:
            run.error = f"cannot start Codex CLI: {res.start_error}"
            return run

        text = ""
        if last_path.is_file():
            text = last_path.read_text(encoding="utf-8", errors="replace").strip()
        run.text = text or stream.last_message
        run.num_turns = stream.turns

        if res.timed_out:
            run.error = f"review stalled: no output from Codex CLI for {idle_timeout_s:.0f}s"
        elif res.returncode != 0:
            detail = stream.errors[-1] if stream.errors else res.stderr_tail
            run.error = f"Codex CLI exited with status {res.returncode}" + (
                f": {detail}" if detail else ""
            )
        elif not run.text and stream.errors:
            run.error = f"Codex CLI produced no result: {stream.errors[-1]}"
        return run
    finally:
        run.duration_s = time.perf_counter() - started
        shutil.rmtree(tmp, ignore_errors=True)


def _review_result(run: AgentRun) -> ReviewResult:
    findings: list[Finding] = parse_findings(run.text) if run.text else []
    result = ReviewResult(
        cost_usd=run.cost_usd, duration_s=run.duration_s, num_turns=run.num_turns,
        error=run.error,
    )
    result.findings = findings
    result.high_critical = filter_high_critical(findings)
    result.total_findings = len(findings)
    result.critical_count = sum(1 for f in result.high_critical if f.severity is Severity.CRITICAL)
    result.high_count = sum(1 for f in result.high_critical if f.severity is Severity.HIGH)
    return result


async def review_repo(
    repo_dir: Path,
    repo_full_name: str,
    *,
    cfg: CodexConfig,
    idle_timeout_s: float | None = DEFAULT_IDLE_TIMEOUT_S,
    skills: Sequence[Skill] = (),
) -> ReviewResult:
    """Review one directory with Codex CLI (read-only sandbox) and return a ReviewResult."""
    prompt = review_prompt_for_cli(repo_full_name, render_skills_prompt(skills))
    run = await _run(
        cfg, Path(repo_dir), prompt, label=repo_full_name,
        idle_timeout_s=idle_timeout_s, write=False,
    )
    return _review_result(run)


async def fix_repo(
    repo_dir: Path,
    repo_full_name: str,
    findings_json: str,
    *,
    cfg: CodexConfig,
    idle_timeout_s: float | None = DEFAULT_IDLE_TIMEOUT_S,
    skills: Sequence[Skill] = (),
) -> AgentRun:
    """Let Codex CLI edit `repo_dir` (workspace-write sandbox, no network) to fix findings."""
    prompt = fix_prompt_for_cli(repo_full_name, findings_json, render_skills_prompt(skills))
    run = await _run(
        cfg, Path(repo_dir), prompt, label=f"{repo_full_name} fix",
        idle_timeout_s=idle_timeout_s, write=True,
    )
    if run.error.startswith("review stalled"):
        run.error = run.error.replace("review stalled", "fix stalled", 1)
    return run
