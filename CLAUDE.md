# Claude Code Agent Context

`secscan` — enumerates GitHub App/PAT-reachable repositories, runs autonomous Claude
Code security reviews over them, and writes High/Critical findings as CSV (+ optional
SQLite/MySQL state, GitHub issues, secman push).

## Dry run — an invariant, not a convenience

`--dry-run` (and `SECSCAN_DRY_RUN=1`) promises that a command performs **no
external writes**: no GitHub issue is opened, nothing is pushed to secman. The
CLI arms a process-wide guard (`src/secscan/dryrun.py`) and every call site that
reaches the outside world calls `dryrun.guard(...)` before writing, so a path
that forgets to honor the flag raises `DryRunViolation` instead of silently
performing the write.

**If you add a new outward-facing write** — another GitHub API call, a second
secman endpoint, a webhook, an issue comment — call `dryrun.guard("<what it
would do>")` immediately before it, and cover it in `tests/test_dryrun.py`.
Skipping this doesn't fail any existing test; it just quietly makes the flag a
lie. The guard is a backstop for exactly that mistake, and it only works if new
code opts into it.

Deliberately *not* covered: the review itself, `findings.csv`/state DB writes,
and `--email-to` delivery. Widening that scope is a product decision — ask
first, and update the README's "Dry run" section in the same change.

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
bundled ones under `src/secscan/skills/<name>/`) to the reviewer's system prompt.
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
the review step; `orchestrator._review` is the single dispatch point and everything
around it (clone, CSV, state, issues, secman, email) is engine-agnostic. `claude`
(default) is `reviewer.review_repo`; `codescanai` is `codescanai.review_repo`, which
runs the [CodeScanAI](https://github.com/codescan-ai/codescan) CLI as a subprocess and
parses its per-file Markdown report (format pinned in `codescanai.parse_report`, from
CodeScanAI 0.1.4's `core/code_scanner/agent_scanner.py`). Both return
`reviewer.ReviewResult`.

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

When adding a third engine, add it to `cli._ENGINES`, dispatch in
`orchestrator._review`, keep the `ReviewResult` contract, and cover the fail-fast
config path in `tests/test_cli_engine.py`.
