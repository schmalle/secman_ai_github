"""Kimi Code CLI as a review/fix engine (`--engine kimi-cli`).

[Kimi CLI](https://github.com/MoonshotAI/kimi-cli) (`uv tool install kimi-cli`) is
Moonshot AI's terminal coding agent. `kimi --print` runs it non-interactively over a
working directory; this module drives that with secscan's prompt and JSON contract
and returns the same `ReviewResult` / `AgentRun` as the other engines.

Not to be confused with `--provider kimi` on the Claude engine, which bills *Claude
Code* through Moonshot's Anthropic-compatible endpoint. This engine runs Moonshot's
own agent and its own tools.

What is pinned here, and why:

- **secscan supplies the agent specification.** Kimi lets an `--agent-file` define
  the system prompt and the exact tool list. The review spec allows only
  `ReadFile`/`Glob`/`Grep`; the fix spec adds `WriteFile`/`StrReplaceFile`. Neither
  includes `Shell`, the web tools, background tasks or sub-agents, so — like the
  Claude engine — repository code is never executed.
- **The repository's `AGENTS.md` never reaches the model.** Kimi merges project
  `AGENTS.md` files into a template variable of the system prompt; secscan's own
  system prompt template simply does not reference it. Project-level skills
  (`.kimi/skills`, `.claude/skills`, `.agents/skills` in the scanned repo) are
  disabled by pointing `--skills-dir` at an empty directory, and the user's global
  MCP servers by passing an empty `--mcp-config`.
- **Credentials stay in the environment.** With `KIMI_API_KEY` (Kimi Code platform)
  or `MOONSHOT_API_KEY` (Moonshot open platform) set, secscan hands Kimi an inline
  provider config with an *empty* `api_key` and lets Kimi's own `KIMI_API_KEY`
  environment override fill it in — the key is never on argv. Without either, the
  engine relies on a prior `kimi login` (the default model in `~/.kimi/config.toml`)
  and fails fast when there is none.
- **Minimal environment.** `subproc.BASE_ENV_ALLOWLIST` plus the Kimi variables
  secscan sets itself (`KIMI_API_KEY`, `KIMI_BASE_URL`, `KIMI_SHARE_DIR`); nothing
  else from secscan's process.
- **Output is `--output-format stream-json`.** One JSON message per line drives the
  progress lines and the idle timeout; the last assistant message is the result.
  Kimi prints its own errors ("LLM not set", "Connection error.") as plain lines,
  which are captured for the error message.

Model names are Moonshot model IDs. The default `sonnet` alias resolves to
`kimi-for-coding` on the Kimi Code platform and `kimi-k2.7-code` on the Moonshot
open platform, overridable with `KIMI_MODEL` (shared with `--provider kimi`). With a
`kimi login` account and no key, `--model` is passed to Kimi as-is and must be a
model alias from its own config. Tested against kimi-cli 1.50.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .config import ConfigError, _env
from .findings import Finding, Severity, filter_high_critical, parse_findings
from .prompts import FIX_SYSTEM_PROMPT, SYSTEM_PROMPT, fix_task_prompt, task_prompt
from .reviewer import DEFAULT_IDLE_TIMEOUT_S, AgentRun, ReviewResult
from .skills import Skill, render_skills_prompt
from .subproc import minimal_env, run_streaming

ENGINE_NAME = "kimi-cli"
DEFAULT_BIN = "kimi"

KIMI_CODE_BASE_URL = "https://api.kimi.com/coding/v1"
MOONSHOT_BASE_URL = "https://api.moonshot.ai/v1"
KIMI_CODE_DEFAULT_MODEL = "kimi-for-coding"
MOONSHOT_DEFAULT_MODEL = "kimi-k2.7-code"
DEFAULT_CONTEXT_SIZE = 262_144

_ANTHROPIC_ALIASES = ("sonnet", "opus", "haiku")
_ENV_EXTRA = frozenset({"KIMI_SHARE_DIR"})

# Tool names are kimi-cli's own import paths (see its agents/default/agent.yaml).
REVIEW_TOOLS = (
    "kimi_cli.tools.file:ReadFile",
    "kimi_cli.tools.file:Glob",
    "kimi_cli.tools.file:Grep",
)
FIX_TOOLS = REVIEW_TOOLS + (
    "kimi_cli.tools.file:WriteFile",
    "kimi_cli.tools.file:StrReplaceFile",
)


@dataclass(frozen=True)
class KimiConfig:
    """Resolved Kimi CLI settings (flags first, then KIMI_* env)."""

    bin: str = DEFAULT_BIN
    model: str | None = None  # model ID (key auth) or Kimi config alias (login auth)
    extra_args: tuple[str, ...] = ()
    auth: str = "login"  # "kimi-code" | "moonshot" | "login"
    api_key: str | None = None  # never on argv; forwarded as KIMI_API_KEY
    base_url: str | None = None

    @property
    def argv0(self) -> list[str]:
        return shlex.split(self.bin)

    @property
    def uses_inline_config(self) -> bool:
        return self.api_key is not None

    @property
    def endpoint_label(self) -> str:
        if self.auth == "login":
            return "Kimi CLI, kimi login account"
        return f"Kimi CLI, {self.auth} ({self.base_url})"


def share_dir() -> Path:
    return Path(_env("KIMI_SHARE_DIR") or "~/.kimi").expanduser()


def _login_default_model() -> str:
    """The `default_model` of the user's own Kimi config, or "" when unset."""
    config = share_dir() / "config.toml"
    if not config.is_file():
        return ""
    m = re.search(r'^\s*default_model\s*=\s*"([^"]*)"', config.read_text(encoding="utf-8"), re.M)
    return m.group(1).strip() if m else ""


def _base_url_from_env(default: str) -> str:
    """`KIMI_CLI_BASE_URL` wins; a `KIMI_BASE_URL` that is the Anthropic-compatible
    endpoint used by `--provider kimi` is ignored, since Kimi CLI speaks OpenAI-style."""
    explicit = _env("KIMI_CLI_BASE_URL")
    if explicit:
        return explicit.rstrip("/")
    shared = _env("KIMI_BASE_URL")
    if shared and not shared.rstrip("/").endswith("/anthropic"):
        return shared.rstrip("/")
    return default


def resolve_config(
    bin: str | None = None,
    model: str | None = None,
    extra_args: Sequence[str] | None = None,
) -> KimiConfig:
    """Resolve flags against the environment and fail fast on anything unusable."""
    command = (bin or _env("KIMI_BIN") or DEFAULT_BIN).strip()
    try:
        argv0 = shlex.split(command)
    except ValueError as exc:
        raise ConfigError(f"--kimi-bin is not a valid command line: {exc}") from exc
    if not argv0:
        raise ConfigError("--kimi-bin must name the kimi executable")
    if shutil.which(argv0[0]) is None:
        raise ConfigError(
            f"Kimi CLI executable not found: {argv0[0]!r}. Install it with "
            "`uv tool install kimi-cli` (Python 3.12+), or point --kimi-bin / KIMI_BIN at it"
        )

    alias = model in _ANTHROPIC_ALIASES
    if alias:
        model = None

    kimi_key = _env("KIMI_API_KEY")
    moonshot_key = _env("MOONSHOT_API_KEY")
    if kimi_key:
        auth, api_key = "kimi-code", kimi_key
        base_url = _base_url_from_env(KIMI_CODE_BASE_URL)
        model = model or _env("KIMI_MODEL") or KIMI_CODE_DEFAULT_MODEL
    elif moonshot_key:
        auth, api_key = "moonshot", moonshot_key
        base_url = _base_url_from_env(MOONSHOT_BASE_URL)
        model = model or _env("KIMI_MODEL") or MOONSHOT_DEFAULT_MODEL
    else:
        auth, api_key, base_url = "login", None, None
        if not _login_default_model():
            raise ConfigError(
                "--engine kimi-cli needs credentials: set KIMI_API_KEY (Kimi Code platform) "
                "or MOONSHOT_API_KEY (Moonshot open platform), or run `kimi login` "
                f"(no default_model in {share_dir() / 'config.toml'})"
            )
        model = model or None  # a Kimi config alias, passed through as-is

    return KimiConfig(
        bin=command, model=model, extra_args=tuple(extra_args or ()),
        auth=auth, api_key=api_key, base_url=base_url,
    )


def inline_config(cfg: KimiConfig) -> str:
    """TOML handed to `--config` when a key is set: one provider, one model, no key.

    `api_key` is deliberately empty here — Kimi's own `KIMI_API_KEY` environment
    override (see `subprocess_env`) supplies it, so the key is never part of argv.
    """
    assert cfg.model and cfg.base_url
    return (
        'default_model = "secscan"\n'
        "telemetry = false\n"
        "[providers.secscan]\n"
        'type = "kimi"\n'
        f"base_url = {json.dumps(cfg.base_url)}\n"
        'api_key = ""\n'
        "[models.secscan]\n"
        'provider = "secscan"\n'
        f"model = {json.dumps(cfg.model)}\n"
        f"max_context_size = {DEFAULT_CONTEXT_SIZE}\n"
    )


def write_agent_spec(directory: Path, *, write: bool, skills_prompt: str = "") -> Path:
    """Write the agent spec (`agent.yaml` + `system.md`) secscan runs Kimi with.

    The system prompt is wrapped in a Jinja `raw` block: Kimi renders `system.md` as
    a template with `${...}` variables, and neither secscan's prompt nor an operator
    skill pack should be interpreted that way. Only the variables in the template are
    substituted — `KIMI_AGENTS_MD` (the scanned repo's AGENTS.md) is not among them.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    body = FIX_SYSTEM_PROMPT if write else SYSTEM_PROMPT
    if skills_prompt:
        body += skills_prompt
    (directory / "system.md").write_text(
        "{% raw %}" + body + "{% endraw %}\n\nWorking directory: ${KIMI_WORK_DIR}\n",
        encoding="utf-8",
    )
    tools = FIX_TOOLS if write else REVIEW_TOOLS
    spec = (
        "version: 1\n"
        "agent:\n"
        f"  name: {'secscan-fix' if write else 'secscan-review'}\n"
        "  system_prompt_path: ./system.md\n"
        "  tools:\n"
        + "".join(f"    - {json.dumps(t)}\n" for t in tools)
        + "  subagents: {}\n"
    )
    path = directory / "agent.yaml"
    path.write_text(spec, encoding="utf-8")
    return path


def build_command(
    cfg: KimiConfig, directory: Path, agent_file: Path, empty_skills_dir: Path
) -> list[str]:
    """The argv for one non-interactive Kimi run; the prompt arrives on stdin."""
    argv = list(cfg.argv0)
    argv += [
        "--print",
        "--output-format", "stream-json",
        "--yolo",
        "--work-dir", str(directory),
        "--agent-file", str(agent_file),
        "--skills-dir", str(empty_skills_dir),
        "--mcp-config", '{"mcpServers": {}}',
    ]
    if cfg.uses_inline_config:
        argv += ["--config", inline_config(cfg)]
    elif cfg.model:
        argv += ["--model", cfg.model]
    argv += list(cfg.extra_args)
    return argv


def subprocess_env(cfg: KimiConfig) -> dict[str, str]:
    """Minimal environment for the Kimi subprocess (see module docstring)."""
    env = minimal_env(_ENV_EXTRA)
    env.setdefault("NO_COLOR", "1")
    env["PYTHONUNBUFFERED"] = "1"
    if cfg.api_key:
        env["KIMI_API_KEY"] = cfg.api_key
        env["KIMI_BASE_URL"] = cfg.base_url or ""
    return env


# --- stream-json -----------------------------------------------------------------


def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return "".join(parts)
    return ""


@dataclass
class _Stream:
    turns: int = 0
    last_text: str = ""
    plain_lines: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.plain_lines = []


def _feed(stream: _Stream, line: str, label: str) -> None:
    if not line.strip():
        return
    try:
        msg = json.loads(line)
    except ValueError:
        stream.plain_lines.append(line.strip())  # "LLM not set", "Connection error.", …
        return
    if not isinstance(msg, dict) or msg.get("role") != "assistant":
        return
    stream.turns += 1
    text = _text_of(msg.get("content"))
    if text.strip():
        stream.last_text = text
    calls = msg.get("tool_calls") or []
    names = []
    for call in calls:
        if isinstance(call, dict):
            fn = call.get("function") or {}
            name = fn.get("name") if isinstance(fn, dict) else None
            names.append(str(name or call.get("name") or "tool"))
    print(f"    [{label}] turn {stream.turns}: {', '.join(names) if names else 'thinking'}", flush=True)


async def _run(
    cfg: KimiConfig,
    repo_dir: Path,
    prompt: str,
    *,
    label: str,
    idle_timeout_s: float | None,
    write: bool,
    skills_prompt: str,
) -> AgentRun:
    run = AgentRun()
    started = time.perf_counter()
    stream = _Stream()
    repo_dir = Path(repo_dir).resolve()
    tmp = Path(tempfile.mkdtemp(prefix="secscan-kimi-"))
    try:
        agent_file = write_agent_spec(tmp / "agent", write=write, skills_prompt=skills_prompt)
        empty_skills = tmp / "no-skills"
        empty_skills.mkdir()
        argv = build_command(cfg, Path(repo_dir), agent_file, empty_skills)

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
            run.error = f"cannot start Kimi CLI: {res.start_error}"
            return run

        run.text = stream.last_text
        run.num_turns = stream.turns
        noise = ("To resume this session",)
        plain = [ln for ln in stream.plain_lines if not ln.startswith(noise)]
        detail = plain[-1] if plain else res.stderr_tail

        if res.timed_out:
            run.error = f"review stalled: no output from Kimi CLI for {idle_timeout_s:.0f}s"
        elif res.returncode != 0:
            run.error = f"Kimi CLI exited with status {res.returncode}" + (
                f": {detail}" if detail else ""
            )
        elif not run.text and detail:
            run.error = f"Kimi CLI produced no result: {detail}"
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
    cfg: KimiConfig,
    idle_timeout_s: float | None = DEFAULT_IDLE_TIMEOUT_S,
    skills: Sequence[Skill] = (),
) -> ReviewResult:
    """Review one directory with Kimi CLI (read-only tool set) and return a ReviewResult."""
    run = await _run(
        cfg, Path(repo_dir), task_prompt(repo_full_name), label=repo_full_name,
        idle_timeout_s=idle_timeout_s, write=False, skills_prompt=render_skills_prompt(skills),
    )
    return _review_result(run)


async def fix_repo(
    repo_dir: Path,
    repo_full_name: str,
    findings_json: str,
    *,
    cfg: KimiConfig,
    idle_timeout_s: float | None = DEFAULT_IDLE_TIMEOUT_S,
    skills: Sequence[Skill] = (),
) -> AgentRun:
    """Let Kimi CLI edit `repo_dir` (file tools only, no shell) to fix findings."""
    run = await _run(
        cfg, Path(repo_dir), fix_task_prompt(repo_full_name, findings_json),
        label=f"{repo_full_name} fix", idle_timeout_s=idle_timeout_s, write=True,
        skills_prompt=render_skills_prompt(skills),
    )
    if run.error.startswith("review stalled"):
        run.error = run.error.replace("review stalled", "fix stalled", 1)
    return run
