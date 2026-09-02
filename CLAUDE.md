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
