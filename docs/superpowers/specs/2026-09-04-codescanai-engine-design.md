# CodeScanAI as a pluggable review engine (`--engine codescanai`)

**Date:** 2026-09-04
**Status:** Implemented

## Problem

secscan's pipeline — enumerate → clone → review → CSV/state → issues/secman/email — has
exactly one review implementation: an autonomous Claude Code agent (`reviewer.py`).
`--provider` varies the endpoint that bills the tokens, but the reviewer is always
Claude Code, and so is the prerequisite (Node + the Claude Code CLI + an Anthropic-
compatible credential).

[CodeScanAI](https://github.com/codescan-ai/codescan) (`pip install codescanai`, MIT)
is an open-source scanner that sends each file of a directory to an LLM — OpenAI,
Google Gemini, or any OpenAI-compatible server such as Ollama — and reports the
vulnerabilities it finds. Operators who already have OpenAI/Gemini keys, who must keep
source on a self-hosted model, or who want a second opinion next to the Claude review
asked for it to be usable *through* secscan, so its findings land in the same CSV,
state DB, GitHub issues, secman push and email report.

## What CodeScanAI is (as of 0.1.4, PyPI == GitHub `main`)

- CLI: `codescanai --provider {openai,gemini,custom} [--directory D] [--model M]
  [--changes_only] [--repo R --pr_number N --github_token T] [--host H --port P
  --token T --endpoint E]`. Argument names use underscores.
- The console entry point is the "V2" `AgentScanner`: it walks `--directory`, runs a
  pydantic-ai `Agent` per file with a `FileScanResult` output type, logs
  `Scanning file: X ...` / `No vulnerabilities found in X.` / `Error scanning X: …`
  to stderr, and prints, per file with findings, to stdout:

  ```
  --- Vulnerabilities found in path/to/file.py ---
    - **Line 37: [Critical] SQL Injection**
    - **Issue**: <description, may span lines>
    - **Fix**: <remediation>
    - **[High] Hardcoded credential**            (no line for architectural issues)
  ```

  Severity is free text chosen by the model (`Low, Medium, High, Critical` requested).
- Providers: `openai` reads `OPENAI_API_KEY` (and the OpenAI SDK's `OPENAI_BASE_URL`);
  `gemini` reads `GEMINI_API_KEY`; `custom` sets `OPENAI_BASE_URL = host[:port][endpoint]`
  and `OPENAI_API_KEY = token or "dummy"` and routes through the OpenAI-compatible
  client. It exits 0 even when every file errored, and reports no cost.
- Verified empirically against a fake OpenAI-compatible server: with `--provider
  custom` and **no** `--host`, the client honours `OPENAI_BASE_URL`/`OPENAI_API_KEY`
  from the environment (bearer token intact); with `--host` on argv the key is
  overwritten with `dummy` unless `--token` is also on argv. `gemini` is broken with
  current pydantic-ai (`Unknown model: gemini:…`) — an upstream issue.

## Design

### 1. Engine abstraction

- `RunConfig.engine: str = "claude"` and `RunConfig.codescanai: CodeScanAIConfig | None`.
- `orchestrator._review(cfg, path, full_name, provider_env, out_dir)` is the single
  dispatch point used by `_process_repo` (run/scan) and `review_local` (review). Both
  engines return `reviewer.ReviewResult`, so nothing downstream changes.
- `_resolve_provider_env` short-circuits for `codescanai` (no OpenRouter/Kimi
  auto-detection, no alias rewriting) and prints the CodeScanAI target instead.
- New module `src/secscan/codescanai.py`: `CodeScanAIConfig`, `resolve_config`,
  `build_command`, `subprocess_env`, `map_severity`, `parse_report`, `review_repo`.

### 2. CLI surface (run / scan / review)

| Flag | Env | Meaning |
|---|---|---|
| `--engine claude\|codescanai` | `SECSCAN_ENGINE` | which reviewer |
| `--codescanai-provider auto\|openai\|gemini\|custom` | `CODESCANAI_PROVIDER` | auto = openai if `OPENAI_API_KEY`, else gemini if `GEMINI_API_KEY`/`GOOGLE_API_KEY`; custom never auto |
| `--model` (existing) | `CODESCANAI_MODEL` | passed through; a bare Anthropic alias (the default `sonnet`) means "CodeScanAI's provider default" |
| `--codescanai-host/-port/-endpoint` | `CODESCANAI_HOST/PORT/ENDPOINT` | custom server, assembled as `host[:port][endpoint]` |
| *(none)* | `CODESCANAI_TOKEN` | custom server bearer token — env-only by design |
| `--codescanai-bin` | `CODESCANAI_BIN` | executable or full command line (`shlex.split`) |
| `--codescanai-arg` (repeatable) | — | verbatim pass-through (`--codescanai-arg=--changes_only`) |
| `--codescanai-default-severity` | `CODESCANAI_DEFAULT_SEVERITY` | severity for unmapped free-text labels; default `medium` |

Validation in `cli._resolve_engine`, before any clone: unknown engine; `--skill` or a
non-default `--provider` with codescanai; any `--codescanai-*` flag with claude
(`CODESCANAI_*` env is never an error); and `codescanai.resolve_config` checks the
provider's key, the custom host (scheme required), port range, severity value, and
that the executable is on `PATH`.

### 3. Secrets and isolation

- CodeScanAI's `--token`/`--host`/`--port`/`--endpoint` are **never** passed on argv.
  For `custom`, secscan sets `OPENAI_BASE_URL` and `OPENAI_API_KEY` (= token, or the
  same `dummy` placeholder CodeScanAI uses) in the subprocess environment. This keeps
  the token out of `ps`/`/proc/<pid>/cmdline`, matching the project's existing
  `DB_PASSWORD`/`SECMAN_PASSWORD`/git-token handling, and also prevents a real
  `OPENAI_API_KEY` from the shell reaching a custom server.
- The subprocess environment is built from an allowlist (`PATH`, `HOME`, locale, tmp,
  `VIRTUAL_ENV`/`PYTHONPATH`, proxy and CA-bundle variables) plus only the active
  provider's credential, with `PYTHONUNBUFFERED=1` so progress lines stream.
- The clone is scanned from a temporary copy without `.git/` (one model call per file
  otherwise goes to hook samples, refs and config). Directories without `.git` are
  scanned in place.

### 4. Report → findings

`parse_report` reads the V2 blocks above into `Finding`s: header → `file_path`,
`Line N` → `line_range`, vulnerability type → `title` and `category`, `Issue` →
`description`, `Fix` → `recommendation`, `confidence = "medium"`. Multi-line
descriptions are joined. Severity goes through `map_severity`: exact rubric value →
synonym table (`moderate`, `severe`, `informational`, …) → any rubric word in the text
(most severe first) → the configured default. `Finding`'s validators still redact
secret material. If the text has no V2 header at all, `findings.parse_findings` is
tried, so a server or build that emits secscan's own JSON contract works unchanged.
The raw stdout is written verbatim to `<output-dir>/<owner>__<repo>/codescanai-report.md`.

### 5. Failure semantics

- Non-zero exit → `ReviewResult.error` with the last stderr line.
- Exit 0 but every `Scanning file:` was followed by `Error scanning` → error
  ("could not scan any file: …"), so the repo is recorded as failed, not as clean.
- Some files errored → warning printed, findings kept.
- `--timeout` is an idle timeout on subprocess output (same semantics as the Claude
  engine); on stall the process is killed.
- Executable missing at run time → error (normally caught earlier by `resolve_config`).
- `cost_usd` is always 0; `num_turns` is the number of files scanned.

## Non-goals

- No change to the Claude engine, the JSON contract, or the severity rubric.
- No attempt to add secscan's prompt/skills to CodeScanAI (its prompt is fixed).
- No use of CodeScanAI's PR mode (`--repo/--pr_number/--github_token`): secscan scans
  whole clones, and that flag set would put a GitHub token on argv. `--codescanai-arg`
  remains available for operators who accept that.
- No vendoring or Python-API import of CodeScanAI: it is a separate install driven
  through its documented CLI, so any version with the same output shape works, and
  `--codescanai-bin`/`--codescanai-arg` cover source checkouts and future flags.

## Testing

- `tests/test_codescanai.py`: config resolution (auto/forced providers, env
  fallbacks, validation, binary lookup), command building (no host/token on argv),
  subprocess env (allowlist, per-provider credential, custom injection, placeholder),
  severity mapping, report parsing (the exact 0.1.4 output, multi-line, unmapped
  severity, JSON fallback, redaction), and `review_repo` against a stub scanner script
  (success, `.git` exclusion via temp copy, custom env injection, model/extra args,
  non-zero exit, all-files-error, partial errors, idle timeout, missing executable).
- `tests/test_cli_engine.py`: flags/env reach `RunConfig` on run/scan/review,
  conflicts and fail-fast paths, and that `--codescanai-token` does not exist.
- `tests/test_orchestrator.py`: dispatch for `_process_repo` and `review_local`, and
  provider resolution being skipped for the engine.
- Manually verified end to end with CodeScanAI 0.1.4 from PyPI against a fake
  OpenAI-compatible server: bearer token delivered via env, secrets absent from the
  subprocess, findings in `findings.csv`/state, dead server recorded as a failure.

## Also fixed in the same change

`secscan run`, `scan` and `review` crashed on every invocation (`_run_config() got an
unexpected keyword argument 'db_password'`, then `UnboundLocalError: secman_password`)
after the `--db-password`/`--secman-password` flag removal; `review` also dropped
`--skill` and reported config errors as tracebacks. 37 existing tests covered this and
were failing on `main`; they pass again.
