# Claude Code Agent Context

`secscan` — reviews a local checkout, one remote repository (App/PAT clone), or every
GitHub App/PAT-reachable repository with an autonomous coding agent, writes
High/Critical findings as CSV (+ optional SQLite/MySQL state, GitHub issues, secman
push), and can remediate them: `--fix` produces `fixes.patch`, `--create-fix-prs`
pushes a branch and opens a pull request.

## Dry run — an invariant, not a convenience

`--dry-run` (and `SECSCAN_DRY_RUN=1`) promises that a command performs **no
external writes**: no GitHub issue is opened, no fix branch is pushed, no pull
request is opened, nothing is pushed to secman. The CLI arms a process-wide guard
(`src/secscan/dryrun.py`) and every call site that reaches the outside world calls
`dryrun.guard(...)` before writing (`issues.process_finding`,
`pull_requests.push_fix_branch`, `pull_requests.open_pull_request`, the secman
client), so a path that forgets to honor the flag raises `DryRunViolation` instead
of silently performing the write.

**If you add a new outward-facing write** — another GitHub API call, a second
secman endpoint, a webhook, an issue comment — call `dryrun.guard("<what it
would do>")` immediately before it, and cover it in `tests/test_dryrun.py`.
Skipping this doesn't fail any existing test; it just quietly makes the flag a
lie. The guard is a backstop for exactly that mistake, and it only works if new
code opts into it.

Deliberately *not* covered: the review itself, the fix agent run and its local
`fixes.patch`/`fixes.json`, `findings.csv`/state DB writes, and `--email-to`
delivery. Widening that scope is a product decision — ask first, and update the
README's "Dry run" section in the same change.

## Fix step (`--fix`, `--create-fix-prs`)

`fixer.py` re-runs the configured engine in write mode over a **disposable git
checkout** and turns `git diff` into the patch; `pull_requests.py` commits, pushes
and opens the PR. Invariants:

- **Never edit the user's directory.** `review ./dir` always works on a clone/copy
  from `fixer.prepare_workspace`; only `scan`/`run` edit their own clone in place.
- **Still no code execution.** Claude: `FIX_TOOLS` in `reviewer.py` adds
  `Edit`/`Write`/`MultiEdit`, `Bash` stays denied, `permission_mode="acceptEdits"`.
  Kimi: `kimi_cli.FIX_TOOLS` adds only `WriteFile`/`StrReplaceFile`. Codex:
  `--sandbox workspace-write` with network off. Widening any of these is a security
  decision, not a convenience.
- **The diff is the output.** Never trust the agent's `{"fixes": [...]}` summary for
  what changed; it only annotates the PR body.
- **One PR per finding set.** `fixer.fix_key` (sorted finding fingerprints) keys the
  `fix_prs` ledger in `state.py`; the orchestrator checks it *before* running the
  fixer so a repeated set costs nothing. `--create-fix-prs` therefore needs the DB.
- **Token never on argv.** The push reuses `cloner._auth_env` (`GIT_CONFIG_*`
  extraheader). Errors that could carry a URL go through `redact_url`.

## secman integration

`secscan` pushes findings into [secman](https://github.com/schmalle/secman), a
separate security requirement/vulnerability management platform, via its
`POST /api/vulnerabilities/cli-add` endpoint. Whenever code touching that
integration changes (the secman push command, its client, credential handling,
or the request/response shape), **check the `secman` repository** — its API
contract, auth requirements, or `cli-add` behavior may have moved — before
assuming the existing integration still matches.

## Security skills

`--skill` appends operator-chosen `SKILL.md` packs (`src/secscan/skills.py`;
bundled ones under `src/secscan/skills/<name>/`) to the reviewer's system prompt
(for the Codex and Kimi engines: to the single prompt / the Kimi agent spec, see
`prompts.review_prompt_for_cli` and `kimi_cli.write_agent_spec`).
Two rules keep this safe: skills are loaded **only** from paths named on the CLI —
never via `setting_sources`/`plugins`/Claude Code skill discovery, which would also
load the scanned repo's attacker-controlled `.claude/` directory — and they **never
widen the tool set** (the reviewer stays `Read`/`Grep`/`Glob`). A bundled skill
must be pure reasoning guidance (no "run semgrep", no report writing), keep the JSON
contract and severity rubric from `prompts.py`, and stay concise (it is re-sent every
turn). `tests/test_skills.py` checks every bundled skill loads; the evaluation of
external skills and the rationale live in `docs/SECURITY_SKILLS.md` — update it when
adding or changing a bundled skill.

## Review engines

`--engine` (`RunConfig.engine`, resolved in `cli._resolve_engine`) picks what performs
the review step; `orchestrator._review` is the single dispatch point for reviews and
`fixer._run_engine` for fixes, and everything around them (clone, CSV, state, issues,
PRs, secman, email) is engine-agnostic. `claude` (default) is `reviewer.review_repo`;
`codex` is `codex.review_repo` (`codex exec --json` as a subprocess, final message via
`-o`); `kimi-cli` is `kimi_cli.review_repo` (`kimi --print --output-format stream-json`
with a secscan-written `--agent-file`); `codescanai` is `codescanai.review_repo`, which
runs the [CodeScanAI](https://github.com/codescan-ai/codescan) CLI as a subprocess and
parses its per-file Markdown report (format pinned in `codescanai.parse_report`, from
CodeScanAI 0.1.4's `core/code_scanner/agent_scanner.py`). All return
`reviewer.ReviewResult`; the fix variants return `reviewer.AgentRun`. The subprocess
engines share `subproc.run_streaming` (idle timeout, stdin prompt) and
`subproc.minimal_env`.

Rules that must survive changes to the Codex and Kimi engines:

- **The scanned repo's instruction files never reach the agent.** Codex:
  `-c project_doc_max_bytes=0` (AGENTS.md). Kimi: the system prompt template written
  by `write_agent_spec` must not reference `${KIMI_AGENTS_MD}`, `--skills-dir` points
  at an empty directory, `--mcp-config` is empty. Tests pin all of this.
- **Tool sets are ours.** Kimi's agent spec lists tools explicitly (no `Shell`, no
  web, no `Agent`); Codex reviews use `--sandbox read-only`, fixes `workspace-write`
  with `sandbox_workspace_write.network_access=false`.
- **No secret on argv, minimal env.** Prompts go in via stdin; Kimi's inline
  `--config` carries an empty `api_key` and the key travels as `KIMI_API_KEY` in the
  subprocess env; only `subproc.BASE_ENV_ALLOWLIST` plus the engine's own variables
  are forwarded.
- **Check upstream when touching the invocation**: `codex exec` flags and the
  `--json` event shape live in `openai/codex`; Kimi's CLI flags, agent-spec format,
  env overrides and stream-json shape in `MoonshotAI/kimi-cli`. Tested versions are
  recorded in each module's docstring.

Rules that must survive changes to the CodeScanAI engine:

- **No secret on argv.** CodeScanAI's own `--token`/`--host` are never passed; the
  custom server URL and token go through `OPENAI_BASE_URL`/`OPENAI_API_KEY` in the
  subprocess env (`codescanai.subprocess_env`), and `CODESCANAI_TOKEN` is env-only —
  there is deliberately no `--codescanai-token` flag (`tests/test_cli_engine.py`
  pins this, like the `--db-password`/`--secman-password` tests).
- **Minimal subprocess env.** Only `codescanai._ENV_ALLOWLIST` plus the active
  provider's credential is forwarded; GitHub/DB/secman/SMTP secrets must not reach a
  process that uploads file contents to a third party.
- **Fail from the log, not the exit code.** CodeScanAI exits 0 when every file
  errored; `review_repo` turns "all files errored" into `ReviewResult.error`.
- **Engine-specific flags are errors on the other engine** (`--skill`/`--provider`
  with codescanai, `--codescanai-*` with claude); `CODESCANAI_*` env never is.
- **Check CodeScanAI upstream** when touching the parser or the invocation: its output
  shape, argument names (`--changes_only`, underscores) and provider wiring live in
  `codescan-ai/codescan`, and the PyPI release may lag or lead the repo.

When adding another engine, add it to `cli._ENGINES` (and `_SKILL_ENGINES` /
`_FIX_ENGINES` if it supports those), dispatch in `orchestrator._review` and
`fixer._run_engine`, keep the `ReviewResult`/`AgentRun` contracts, and cover the
fail-fast config path in `tests/test_cli_engine.py`.

## Claude provider plumbing

`providers.py` only changes the Claude Code subprocess environment. Two things keep
the "via OpenRouter" and "via Claude Code license" paths working: gateways get every
model the CLI may call pinned (`gateway_model_env`: `ANTHROPIC_MODEL`,
`ANTHROPIC_DEFAULT_*_MODEL`, `ANTHROPIC_SMALL_FAST_MODEL`) because bare aliases like
`haiku` do not exist there, and the subscription path (`anthropic`/`usecc`) relies on
`reviewer._ENV_ALLOWLIST` forwarding `HOME`/`CLAUDE_CONFIG_DIR` (where the login
lives) and proxy/CA variables while blanking everything else. Don't add secrets to
that allowlist; add provider-routing variables to `providers.py` instead.
