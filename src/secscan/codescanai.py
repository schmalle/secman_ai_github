"""CodeScanAI as an alternative review engine (`--engine codescanai`).

[CodeScanAI](https://github.com/codescan-ai/codescan) is a separate open-source
scanner (`pip install codescanai`) that sends every file of a directory, one at a
time, to an LLM — OpenAI, Google Gemini, or any OpenAI-compatible server such as
Ollama — and prints the vulnerabilities it reports. This module drives its CLI as a
subprocess over the same clone the Claude Code reviewer would get, turns its report
into secscan `Finding`s, and returns the same `ReviewResult` the rest of the
pipeline (CSV, state DB, issues, secman push, email) already consumes.

Design points, in the order they matter:

- **Nothing here is Claude-specific.** `--provider`/`--model` routing in
  providers.py selects the endpoint the Claude Code reviewer bills to; CodeScanAI
  has its own provider set (`openai` / `gemini` / `custom`), configured through the
  `--codescanai-*` flags and `CODESCANAI_*` variables resolved by `resolve_config`.
- **Secrets never reach argv.** CodeScanAI's own `--token` flag would put a bearer
  token into the subprocess command line, visible to every local process via `ps`
  or `/proc/<pid>/cmdline` — the exposure this project already engineers around
  for the git clone token and the DB/secman passwords. So a custom server's URL and
  token are handed over through the `OPENAI_BASE_URL` / `OPENAI_API_KEY`
  environment variables that CodeScanAI's OpenAI-compatible client reads, and
  `--host`/`--port`/`--token` are never passed on the command line. (Passing
  `--host` would also make CodeScanAI overwrite the key with a placeholder.)
- **The subprocess sees a minimal environment.** Only the variables on
  `_ENV_ALLOWLIST` plus the chosen provider's own credential are forwarded, so
  secscan's GitHub App key, PAT, DB/secman/SMTP passwords never reach a process
  that ships file contents to a third-party API.
- **Its report is parsed, not trusted.** CodeScanAI prints one block per file in a
  fixed Markdown shape (see `parse_report`); severities are free text chosen by the
  model, mapped onto secscan's rubric with `map_severity` and falling back to
  `--codescanai-default-severity`. The raw report is also written next to
  `findings.csv` (`codescanai-report.md`) so nothing is lost when the mapping is
  lossy. If a build of CodeScanAI (or a custom server) emits secscan's own JSON
  contract instead, `findings.parse_findings` picks that up as a fallback.
- **Failure is detected from the log, not the exit code.** CodeScanAI exits 0 even
  when every file failed (e.g. no API key reachable, connection refused); a run in
  which every scanned file errored is reported as a review error so the repo is
  recorded as failed rather than as "0 findings".

Not supported with this engine, by construction: `--skill` (CodeScanAI's prompt is
not configurable), `--max-turns`/`--max-cost-usd` (no turns, no cost reporting —
`cost_usd` is always 0), and the Claude-side `--provider`.
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from .config import ConfigError, _env
from .findings import Finding, Severity, filter_high_critical, parse_findings
from .reviewer import DEFAULT_IDLE_TIMEOUT_S, ReviewResult

ENGINE_NAME = "codescanai"
DEFAULT_BIN = "codescanai"
PROVIDERS = ("auto", "openai", "gemini", "custom")
DEFAULT_SEVERITY = Severity.MEDIUM
REPORT_FILENAME = "codescanai-report.md"

# What CodeScanAI itself sends as the API key when a custom server has no token:
# its OpenAI-compatible client refuses an empty key even for servers that don't
# authenticate. Mirrored here so `--codescanai-provider custom` without
# CODESCANAI_TOKEN behaves exactly like a bare `codescanai --provider custom`.
CUSTOM_PLACEHOLDER_TOKEN = "dummy"

# Bare Anthropic aliases secscan's `--model` defaults to; CodeScanAI has no
# equivalent, so they mean "the provider's own default model" here.
_ANTHROPIC_ALIASES = ("sonnet", "opus", "haiku")

# Variables from secscan's own process that the CodeScanAI subprocess may see:
# PATH/HOME to find the executable and its Python, locale/tmp plumbing, proxy and
# CA-bundle settings (CodeScanAI talks HTTPS to its provider), and the pieces that
# let it run from a source checkout or virtualenv. Provider credentials are added
# per provider by `subprocess_env`, never wholesale.
_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TMPDIR",
        "VIRTUAL_ENV",
        "PYTHONPATH",
        "PYTHONIOENCODING",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    }
)

# Provider credentials, forwarded only for the provider actually in use.
_PROVIDER_ENV = {
    "openai": ("OPENAI_API_KEY", "OPENAI_BASE_URL"),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "custom": (),  # computed from host/port/endpoint/token, see subprocess_env
}


@dataclass(frozen=True)
class CodeScanAIConfig:
    """Resolved CodeScanAI settings (flags first, then CODESCANAI_* env)."""

    provider: str = "openai"
    model: str | None = None  # None = CodeScanAI's per-provider default
    host: str | None = None  # custom provider only
    port: int | None = None
    endpoint: str | None = None
    token: str | None = None  # CODESCANAI_TOKEN only — never a CLI flag
    bin: str = DEFAULT_BIN  # command line (shlex-split), e.g. "python3 -m core.runner_v2"
    extra_args: tuple[str, ...] = ()  # raw pass-through, e.g. ("--changes_only",)
    default_severity: Severity = DEFAULT_SEVERITY

    @property
    def argv0(self) -> list[str]:
        return shlex.split(self.bin)

    @property
    def base_url(self) -> str | None:
        """The custom server URL, built the way CodeScanAI builds it: host[:port][endpoint]."""
        if self.provider != "custom" or not self.host:
            return None
        url = self.host.rstrip("/")
        if self.port:
            url += f":{self.port}"
        if self.endpoint:
            url += "/" + self.endpoint.strip("/")
        return url

    @property
    def endpoint_label(self) -> str:
        """Human-readable target for run banners; never includes the token."""
        if self.provider == "custom":
            return self.base_url or "custom server"
        override = _env("OPENAI_BASE_URL") if self.provider == "openai" else None
        return f"{self.provider} ({override})" if override else self.provider


def _gemini_key() -> str | None:
    return _env("GEMINI_API_KEY") or _env("GOOGLE_API_KEY")


def _auto_provider() -> str:
    if _env("OPENAI_API_KEY"):
        return "openai"
    if _gemini_key():
        return "gemini"
    raise ConfigError(
        "--engine codescanai needs a provider: set OPENAI_API_KEY (openai) or "
        "GEMINI_API_KEY (gemini), or pass --codescanai-provider custom with "
        "--codescanai-host (or CODESCANAI_HOST) for a self-hosted server"
    )


def resolve_config(
    provider: str | None = None,
    model: str | None = None,
    host: str | None = None,
    port: int | str | None = None,
    endpoint: str | None = None,
    bin: str | None = None,
    extra_args: Sequence[str] | None = None,
    default_severity: str | None = None,
) -> CodeScanAIConfig:
    """Resolve flags against the environment and fail fast on anything unusable.

    Called by the CLI before any clone or review starts, so a missing API key, an
    unknown provider, or a `codescanai` binary that isn't installed is a clean
    config error instead of a failed repo record after an expensive clone.
    """
    provider = (provider or _env("CODESCANAI_PROVIDER") or "auto").strip().lower()
    if provider not in PROVIDERS:
        raise ConfigError(
            f"--codescanai-provider must be one of {', '.join(PROVIDERS)}; got {provider!r}"
        )
    if provider == "auto":
        provider = _auto_provider()

    # secscan's `--model` defaults to a bare Anthropic alias; for CodeScanAI that
    # means "use the provider's default" unless CODESCANAI_MODEL says otherwise.
    if model in _ANTHROPIC_ALIASES:
        model = None
    model = model or _env("CODESCANAI_MODEL") or None

    host = host or _env("CODESCANAI_HOST") or None
    endpoint = endpoint or _env("CODESCANAI_ENDPOINT") or None
    raw_port = port if port not in (None, "") else _env("CODESCANAI_PORT")
    port_int: int | None = None
    if raw_port not in (None, ""):
        try:
            port_int = int(raw_port)
        except (TypeError, ValueError):
            raise ConfigError(f"--codescanai-port must be an integer; got {raw_port!r}")
        if not 1 <= port_int <= 65535:
            raise ConfigError(f"--codescanai-port must be 1-65535; got {port_int}")

    if provider == "openai" and not _env("OPENAI_API_KEY"):
        raise ConfigError("OPENAI_API_KEY is required for --codescanai-provider openai")
    if provider == "gemini" and not _gemini_key():
        raise ConfigError(
            "GEMINI_API_KEY (or GOOGLE_API_KEY) is required for --codescanai-provider gemini"
        )
    if provider == "custom":
        if not host:
            raise ConfigError(
                "--codescanai-host (or CODESCANAI_HOST) is required for "
                "--codescanai-provider custom, e.g. http://localhost with "
                "--codescanai-port 11434 --codescanai-endpoint /v1 for Ollama"
            )
        if not re.match(r"^https?://", host):
            raise ConfigError(
                f"--codescanai-host must start with http:// or https:// (got {host!r})"
            )
    elif host or port_int or endpoint:
        raise ConfigError(
            "--codescanai-host/--codescanai-port/--codescanai-endpoint only apply to "
            "--codescanai-provider custom"
        )

    sev_text = (default_severity or _env("CODESCANAI_DEFAULT_SEVERITY") or "").strip().lower()
    if sev_text:
        try:
            severity = Severity(sev_text)
        except ValueError:
            raise ConfigError(
                "--codescanai-default-severity must be one of "
                f"{', '.join(s.value for s in Severity)}; got {sev_text!r}"
            )
    else:
        severity = DEFAULT_SEVERITY

    command = (bin or _env("CODESCANAI_BIN") or DEFAULT_BIN).strip()
    try:
        argv0 = shlex.split(command)
    except ValueError as exc:
        raise ConfigError(f"--codescanai-bin is not a valid command line: {exc}") from exc
    if not argv0:
        raise ConfigError("--codescanai-bin must name the codescanai executable")
    if shutil.which(argv0[0]) is None:
        raise ConfigError(
            f"CodeScanAI executable not found: {argv0[0]!r}. Install it with "
            "`pip install codescanai` (or `uv tool install codescanai`), or point "
            "--codescanai-bin / CODESCANAI_BIN at it"
        )

    return CodeScanAIConfig(
        provider=provider,
        model=model,
        host=host,
        port=port_int,
        endpoint=endpoint,
        token=_env("CODESCANAI_TOKEN"),
        bin=command,
        extra_args=tuple(extra_args or ()),
        default_severity=severity,
    )


def build_command(cfg: CodeScanAIConfig, directory: Path) -> list[str]:
    """The argv for one scan. Host/port/token deliberately never appear here."""
    argv = list(cfg.argv0)
    argv += ["--provider", cfg.provider, "--directory", str(directory)]
    if cfg.model:
        argv += ["--model", cfg.model]
    argv += list(cfg.extra_args)
    return argv


def subprocess_env(cfg: CodeScanAIConfig) -> dict[str, str]:
    """Minimal environment for the CodeScanAI subprocess (see module docstring)."""
    env = {name: os.environ[name] for name in _ENV_ALLOWLIST if name in os.environ}
    # Its progress log goes to stderr and the report to stdout; unbuffered output
    # is what makes the idle timeout below meaningful when stdout is a pipe.
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("PYTHONIOENCODING", "utf-8")
    for name in _PROVIDER_ENV.get(cfg.provider, ()):
        value = os.environ.get(name)
        if value:
            env[name] = value
    if cfg.provider == "custom":
        env["OPENAI_BASE_URL"] = cfg.base_url or ""
        env["OPENAI_API_KEY"] = cfg.token or CUSTOM_PLACEHOLDER_TOKEN
    return env


# --- report parsing ------------------------------------------------------------

# CodeScanAI's V2 scanner (the `codescanai` entry point since 0.1.2) prints, per
# file with findings:
#
#   --- Vulnerabilities found in path/to/file.py ---
#     - **Line 37: [Critical] SQL Injection**
#     - **Issue**: <description, may span lines>
#     - **Fix**: <remediation, may span lines>
#     - **[High] Hardcoded credential**          (no line for architectural issues)
#     - **Issue**: ...
#     - **Fix**: ...
_HEADER_RE = re.compile(r"^--- Vulnerabilities found in (.+?) ---\s*$")
_ITEM_RE = re.compile(r"^\s*- \*\*(?:Line (\d+): )?\[([^\]]*)\]\s*(.*?)\*\*\s*$")
_ISSUE_RE = re.compile(r"^\s*- \*\*Issue\*\*:\s?(.*)$")
_FIX_RE = re.compile(r"^\s*- \*\*Fix\*\*:\s?(.*)$")

# stderr log lines the scanner emits per file.
_SCANNING_RE = re.compile(r"Scanning file: (.+?) \.\.\.\s*$")
_FILE_ERROR_RE = re.compile(r"ERROR - (Error scanning .+)$")

_SEVERITY_SYNONYMS = {
    "blocker": Severity.CRITICAL,
    "urgent": Severity.CRITICAL,
    "severe": Severity.HIGH,
    "major": Severity.HIGH,
    "important": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "minor": Severity.LOW,
    "trivial": Severity.LOW,
    "negligible": Severity.LOW,
    "informational": Severity.INFO,
    "information": Severity.INFO,
    "informative": Severity.INFO,
    "note": Severity.INFO,
}


def map_severity(text: str | None, default: Severity = DEFAULT_SEVERITY) -> Severity:
    """Map CodeScanAI's free-text severity onto secscan's rubric.

    The model is asked for "Low, Medium, High, Critical" but returns whatever it
    likes ("Moderate", "HIGH SEVERITY", "critical/high"); exact values and common
    synonyms are mapped, a rubric word anywhere in the text wins next (most severe
    first), and anything else gets `default`.
    """
    s = (text or "").strip().lower()
    if not s:
        return default
    try:
        return Severity(s)
    except ValueError:
        pass
    if s in _SEVERITY_SYNONYMS:
        return _SEVERITY_SYNONYMS[s]
    words = set(re.findall(r"[a-z]+", s))
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        if sev.value in words:
            return sev
    for word, sev in _SEVERITY_SYNONYMS.items():
        if word in words:
            return sev
    return default


def _finding(item: dict, default_severity: Severity) -> Finding | None:
    kind = " ".join(item.get("type", "").split()) or "Unspecified vulnerability"
    description = item.get("description", "").strip()
    recommendation = item.get("recommendation", "").strip()
    try:
        return Finding(
            severity=map_severity(item.get("severity"), default_severity),
            title=kind,
            description=description or kind,
            file_path=item.get("file", ""),
            line_range=item.get("line", ""),
            category=kind,
            recommendation=recommendation,
            confidence="medium",
        )
    except Exception:
        return None  # the schema rejected it (e.g. empty title); drop it


def parse_report(text: str, default_severity: Severity = DEFAULT_SEVERITY) -> list[Finding]:
    """Turn CodeScanAI's stdout into Findings.

    Parses the V2 per-file Markdown blocks; if there are none, falls back to
    secscan's JSON contract (`findings.parse_findings`) so a custom server or a
    future CodeScanAI build that emits `{"findings": [...]}` works unchanged.
    """
    findings: list[Finding] = []
    current_file = ""
    item: dict | None = None
    open_field: str | None = None
    saw_header = False

    def flush() -> None:
        nonlocal item, open_field
        if item is not None:
            f = _finding(item, default_severity)
            if f is not None:
                findings.append(f)
        item, open_field = None, None

    for line in text.splitlines():
        m = _HEADER_RE.match(line)
        if m:
            flush()
            current_file = m.group(1).strip()
            saw_header = True
            continue
        m = _ITEM_RE.match(line)
        if m:
            flush()
            item = {
                "file": current_file,
                "line": m.group(1) or "",
                "severity": m.group(2),
                "type": m.group(3),
                "description": "",
                "recommendation": "",
            }
            continue
        if item is None:
            continue
        m = _ISSUE_RE.match(line)
        if m:
            item["description"] = m.group(1)
            open_field = "description"
            continue
        m = _FIX_RE.match(line)
        if m:
            item["recommendation"] = m.group(1)
            open_field = "recommendation"
            continue
        if open_field:
            # A description/remediation the model wrote across several lines.
            item[open_field] += "\n" + line
    flush()

    if findings or saw_header:
        return findings
    return parse_findings(text)


# --- running it ----------------------------------------------------------------


def _export_tree(repo_dir: Path) -> tuple[Path, str | None]:
    """A `.git`-free copy of the tree to scan, or the directory itself.

    CodeScanAI walks every file under `--directory`, and each text file is one model
    call: a fresh clone's `.git/` (config, hook samples, refs) would cost a dozen
    calls per repo and can only produce noise. Directories without `.git` are
    scanned in place.
    """
    if not (repo_dir / ".git").exists():
        return repo_dir, None
    tmp = tempfile.mkdtemp(prefix="secscan-codescanai-")
    dest = Path(tmp) / (repo_dir.name or "repo")
    shutil.copytree(
        repo_dir, dest, symlinks=True, ignore=shutil.ignore_patterns(".git")
    )
    return dest, tmp


async def _pump(stream: asyncio.StreamReader, tag: str, queue: asyncio.Queue) -> None:
    try:
        while True:
            raw = await stream.readline()
            if not raw:
                break
            await queue.put((tag, raw.decode("utf-8", "replace").rstrip("\r\n")))
    finally:
        await queue.put((tag, None))


@dataclass
class _Run:
    stdout: list[str] = field(default_factory=list)
    stderr: list[str] = field(default_factory=list)
    files_scanned: int = 0
    file_errors: list[str] = field(default_factory=list)


async def review_repo(
    repo_dir: Path,
    repo_full_name: str,
    *,
    cfg: CodeScanAIConfig,
    idle_timeout_s: float | None = DEFAULT_IDLE_TIMEOUT_S,
    report_path: Path | None = None,
) -> ReviewResult:
    """Scan one directory with CodeScanAI and return a ReviewResult.

    `idle_timeout_s` has the same meaning as for the Claude reviewer: the run is
    aborted if the scanner prints nothing (no progress line, no finding) for that
    long — a stall guard, not a cap on total duration. `report_path`, when given,
    receives CodeScanAI's raw stdout verbatim.
    """
    result = ReviewResult()
    started = time.perf_counter()
    run = _Run()
    scan_dir, tmp = _export_tree(Path(repo_dir))
    proc: asyncio.subprocess.Process | None = None
    try:
        argv = build_command(cfg, scan_dir)
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(scan_dir),
                env=subprocess_env(cfg),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
            )
        except OSError as exc:
            result.error = f"cannot start CodeScanAI ({argv[0]}): {exc}"
            return result

        queue: asyncio.Queue = asyncio.Queue()
        pumps = [
            asyncio.create_task(_pump(proc.stdout, "out", queue)),
            asyncio.create_task(_pump(proc.stderr, "err", queue)),
        ]
        open_streams = 2
        try:
            while open_streams:
                if idle_timeout_s:
                    tag, line = await asyncio.wait_for(queue.get(), timeout=idle_timeout_s)
                else:
                    tag, line = await queue.get()
                if line is None:
                    open_streams -= 1
                    continue
                if tag == "out":
                    run.stdout.append(line)
                    continue
                run.stderr.append(line)
                m = _SCANNING_RE.search(line)
                if m:
                    run.files_scanned += 1
                    print(
                        f"    [{repo_full_name}] file {run.files_scanned}: {m.group(1)}",
                        flush=True,
                    )
                    continue
                m = _FILE_ERROR_RE.search(line)
                if m:
                    run.file_errors.append(m.group(1))
                    print(f"    [{repo_full_name}] {m.group(1)}", flush=True)
        except asyncio.TimeoutError:
            result.error = (
                f"review stalled: no output from CodeScanAI for {idle_timeout_s:.0f}s"
            )
            proc.kill()
        finally:
            for t in pumps:
                t.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
        returncode = await proc.wait()

        report = "\n".join(run.stdout).strip()
        if report_path is not None:
            report_path = Path(report_path)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report + ("\n" if report else ""), encoding="utf-8")

        findings = parse_report(report, cfg.default_severity)
        if not result.error:
            if returncode != 0:
                tail = next((ln for ln in reversed(run.stderr) if ln.strip()), "")
                result.error = f"CodeScanAI exited with status {returncode}" + (
                    f": {tail}" if tail else ""
                )
            elif run.file_errors and len(run.file_errors) >= run.files_scanned:
                # Exit status 0, but not a single file was actually analysed.
                result.error = f"CodeScanAI could not scan any file: {run.file_errors[0]}"
            elif run.file_errors:
                print(
                    f"    [{repo_full_name}] warning: {len(run.file_errors)} of "
                    f"{run.files_scanned} files could not be scanned",
                    flush=True,
                )

        result.findings = findings
        result.high_critical = filter_high_critical(findings)
        result.total_findings = len(findings)
        result.critical_count = sum(
            1 for f in result.high_critical if f.severity is Severity.CRITICAL
        )
        result.high_count = sum(1 for f in result.high_critical if f.severity is Severity.HIGH)
        result.num_turns = run.files_scanned  # one model call per file
        return result
    finally:
        result.duration_s = time.perf_counter() - started
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)
