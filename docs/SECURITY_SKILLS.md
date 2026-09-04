# Security skills for the secscan reviewer

secscan's reviewer is a Claude Code agent with a fixed system prompt
(`src/secscan/prompts.py`). *Skills* let an operator add methodology to that
prompt without forking the tool: a checklist for a technology the base prompt
only mentions in passing, a stricter false-positive bar before findings become
GitHub issues, or an organization's own review conventions.

This document records **which security skills published on GitHub fit this
project**, why the others do not, what secscan bundles as a result, and how to use
or bring your own.

- [What makes a skill fit](#what-makes-a-skill-fit)
- [Evaluation of GitHub-hosted security skills](#evaluation-of-github-hosted-security-skills)
- [Bundled skills](#bundled-skills)
- [Using skills: `--skill`](#using-skills---skill)
- [Bringing an external skill](#bringing-an-external-skill)
- [Writing your own](#writing-your-own)
- [How skills reach the agent, and the trust model](#how-skills-reach-the-agent-and-the-trust-model)
- [Cost](#cost)
- [Gaps a skill cannot close](#gaps-a-skill-cannot-close)

## What makes a skill fit

The reviewer runs under constraints that most published skills were not written
for. A skill is a fit only if it survives all of them:

| Constraint | Why it exists | Consequence for skills |
|---|---|---|
| **Read-only tools** — `Read`, `Grep`, `Glob` only; `Bash`, `Write`, `Edit`, `WebFetch`, `WebSearch`, `Agent`/`Task` are denied | Untrusted repository code must never execute, and sub-agents made runs unbounded | Anything that shells out (semgrep, CodeQL, gitleaks, osv-scanner, `gh`), writes reports to disk, or orchestrates sub-agents cannot work inside the review |
| **No network** in the agent | Same reason; also keeps cost predictable | No CVE lookups, no fetching advisories, no calling GitHub APIs from the skill |
| **Hermetic settings** — `setting_sources=[]` | The clone's `.claude/` directory is attacker-controlled | Skills are never auto-discovered from the repo or the host; the operator names them on the command line |
| **Fixed output contract** — one JSON object, `high`/`critical` filtered into CSV, issues and secman | Everything downstream parses that JSON | A skill may refine *how* to look; it must not change *what* is emitted |
| **Whole-repository scope**, not a PR diff | secscan audits entire codebases | Diff-oriented skills need adaptation |
| **Per-turn cost** | The system prompt is re-sent every turn, up to `--max-turns` per repo | A 15,000-word skill is a cost multiplier across a whole org; concise checklists win |

A skill that is pure reasoning guidance in the Agent Skills format
(`SKILL.md` with `name`/`description` frontmatter, optional reference files) and
needs no tools passes all six.

## Evaluation of GitHub-hosted security skills

Reviewed September 2026. Licenses matter because secscan *vendors* adapted content
into its own MIT-compatible package; CC-BY-SA material is referenced, not copied.

| Skill / repo | License | Needs Bash, scripts or network? | Fit | Verdict |
|---|---|---|---|---|
| [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) — Anthropic's security-review GitHub Action; also the built-in `/security-review` command | MIT | No (pure prompt; the Action runs its own FP filter with a second model call) | **High.** Its exploitability bar, 16 hard exclusions and precedent rules are exactly what keeps issue/secman noise down. Written for PR diffs and Medium+ findings | **Adapted** into the bundled `false-positive-filter`, re-scoped to whole-repo review and to secscan's High/Critical rubric. One deliberate divergence: upstream excludes on-disk secrets ("handled by other processes"); secscan has no secret scanner in the loop, so hardcoded credentials stay reportable |
| [ez-lbz/claude-code-security-skills](https://github.com/ez-lbz/claude-code-security-skills) — the same Anthropic content repackaged as a standalone skill | MIT | No | High (same content as above, spec-format `SKILL.md`) | Usable directly with `--skill <path>`; the bundled adaptation covers the same ground with secscan's rubric |
| [agamm/claude-code-owasp](https://github.com/agamm/claude-code-owasp) — OWASP Top 10:2025, ASVS 5.0, LLM Top 10, Agentic AI, 20+ language quirks | MIT | No | **High.** Pure reference, spec-format skill, on-demand `reference/` files. Written for a coding assistant, so it mixes secure-coding *patterns* (how to write) with review guidance; ~5,500 words plus large references | **Referenced.** Its structure informed the bundled `owasp-top10` and `llm-app-security`, which are written as *reviewer* checklists (what to grep for, evidence bar, severity mapping). Load the original with `--skill` when you want the language-quirk references |
| [trailofbits/skills](https://github.com/trailofbits/skills) — 40+ plugins from a leading audit firm | CC-BY-SA-4.0 | Mixed | Reasoning-only plugins fit; tool-driven ones do not. See the breakdown below | **Referenced, not vendored** (ShareAlike). Individual skills can be loaded with `--skill` after cloning |
| ↳ `insecure-defaults`, `sharp-edges`, `agentic-actions-auditor` | | Reasoning (sharp-edges also defines a sub-agent, which will be ignored) | Good: fallback secrets, fail-open switches, dangerous API defaults, AI-agent-in-CI injection | Concepts informed the bundled `cicd-and-iac`; load the originals for the full checklists |
| ↳ `fp-check` | | Reasoning; Bash optional | Good as a verification mindset; written to verify *one* claimed bug interactively | Partly reflected in `false-positive-filter`'s "before you emit" step |
| ↳ `audit-context-building`, `differential-review`, `variant-analysis` | | Sub-agents, file writes, `git` | No: needs `Task`/`Write`/`Bash` | Not usable in-loop |
| ↳ `static-analysis`, `semgrep-*`, `supply-chain-risk-auditor`, `testing-handbook-skills` | | CodeQL/Semgrep binaries, network | No | Run separately; see [gaps](#gaps-a-skill-cannot-close) |
| [Consensys/repo-security-review](https://github.com/Consensys/repo-security-review) — six-phase repo audit | No license file found at review time | Yes: `gitleaks`, `osv-scanner`, `semgrep`, `jq`, sub-agents, writes `.security-review/` | Low for in-loop use; its LLM-only phases duplicate the base prompt | Not a fit for `--skill`. It is a reasonable *complementary* standalone run on a repo you already cloned |
| [Security-Phoenix-demo/security-skills-claude-code](https://github.com/Security-Phoenix-demo/security-skills-claude-code) | MIT | Mostly: search APIs, NotebookLM, optional osv-scanner | Low: research/rule-generation workflows rather than review guidance | Not a fit |
| [MaTriXy/github-review-skill](https://github.com/MaTriXy/github-review-skill) — remediation plans from GitHub Code Scanning / Dependabot / Secret Scanning alerts | see repo | Yes: GitHub API | Different job: consumes alerts secscan does not read | Not a fit in-loop; a natural follow-up tool for the issues secscan opens |
| [Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill), [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) (third-party despite the name) | see repos | Largely tool-driven | Offensive ops, threat hunting, reverse engineering — out of secscan's scope | Not a fit |
| [anthropics/skills](https://github.com/anthropics/skills) — Anthropic's public skill catalog and the Agent Skills spec | Apache-2.0 | n/a | No security-review skill; the **spec** is what secscan's loader implements | Format reference |

## Bundled skills

`secscan skills list` prints these; `secscan skills show <name>` prints one in
full. They live in `src/secscan/skills/<name>/SKILL.md` and ship with the package.

| Name | Use when | Adapted from |
|---|---|---|
| `false-positive-filter` | Every scan whose findings become issues or secman entries. Adds the exploitability triad (attacker input → reachable sink → blast radius), confidence calibration, hard exclusions (DoS, hardening gaps, test-only code, unverified CVEs…), precedent rules and consolidation | Anthropic `claude-code-security-review` (MIT) |
| `owasp-top10` | Web services, APIs, anything with an authenticated surface. Per OWASP 2025 category: what to `Grep` for, the evidence bar, and the mapping onto `critical`/`high` and CWE ids | Own text; structure informed by agamm/claude-code-owasp |
| `cicd-and-iac` | Repos with `.github/workflows`, other CI configs, Dockerfiles, Kubernetes/Helm, Terraform/CloudFormation. Pwn-requests, `${{ github.event.* }}` expression injection, AI agents in workflows, secrets in images, public buckets, wildcard IAM, open security groups | Own text; concepts informed by Trail of Bits `agentic-actions-auditor` / `insecure-defaults` and GitHub's guidance |
| `llm-app-security` | Repos that import an LLM SDK, agent framework or MCP server library. Prompt injection reaching tools with side effects, LLM output in shells/SQL/HTML, excessive agency, MCP transport exposure, RAG tenant boundaries. Self-disables when no LLM code is found | Own text following OWASP LLM Top 10 (2025) / Agentic threats (2026) |

Every bundled skill keeps the reviewer read-only, keeps the JSON contract and the
severity rubric from the base prompt, and is short enough to be re-sent each turn
(the loader enforces a 60,000-character ceiling).

A sensible default for an organization scan:

```bash
uv run secscan run --org my-org \
    --skill false-positive-filter --skill owasp-top10 --skill cicd-and-iac
```

Add `llm-app-security` when the org ships LLM features. Skills are opt-in
precisely because they change what the reviewer reports; a run without `--skill`
behaves exactly as before.

## Using skills: `--skill`

`--skill` is accepted by `run`, `scan` and `review`, and may be repeated. Each
value is either a bundled name or a path to a skill directory (or to its
`SKILL.md`). A bare name always resolves to the bundled skill, so a directory in
the current folder that happens to share a name cannot shadow it — use `./name`
for the local one.

```bash
uv run secscan skills list
uv run secscan skills show false-positive-filter
uv run secscan scan octo/webapp --skill false-positive-filter --skill owasp-top10
uv run secscan review ./some/local/repo --skill ./my-skills/company-rules
```

Unknown names or invalid `SKILL.md` files fail **before** anything is cloned or
reviewed, with the list of bundled names in the message. Giving the same skill
twice is harmless; two *different* skills with the same `name` is an error. The
run prints `Skills: …` once the provider is resolved.

## Bringing an external skill

Any directory that follows the [Agent Skills](https://agentskills.io) layout
works: `SKILL.md` with YAML frontmatter (`name`, `description`; `license`,
`metadata`, `allowed-tools` are read but not acted on) and a Markdown body, plus
optional reference files next to it. Clone the repository once and point
`--skill` at the skill directory:

```bash
# agamm/claude-code-owasp — OWASP reference with per-language quirks
git clone https://github.com/agamm/claude-code-owasp ~/skills/claude-code-owasp
uv run secscan scan octo/webapp --skill ~/skills/claude-code-owasp/.claude/skills/owasp-security

# trailofbits/skills — pick a reasoning-only plugin (CC-BY-SA-4.0)
git clone https://github.com/trailofbits/skills ~/skills/trailofbits
uv run secscan scan octo/webapp --skill ~/skills/trailofbits/plugins/agentic-actions-auditor/skills/agentic-actions-auditor
```

Directory layouts inside those repositories change; if a path stops resolving,
`find <clone> -name SKILL.md` shows the current one. Before adopting an external
skill, read it end to end — it becomes part of the reviewer's instructions — and
check that it does not depend on tools the reviewer does not have. Instructions
such as "run semgrep" or "write the report to `.security-review/`" are simply
impossible in-loop; the reviewer will either ignore them or waste turns on them.

Skills that define sub-agents (`agents/`), commands (`commands/`) or hooks are
loaded for their `SKILL.md` body only; those other parts are not activated.

## Writing your own

The bundled files are templates. Keep to the pattern that works for a read-only
reviewer:

- **Locate** — concrete `Grep`/`Glob` targets, not "review the authentication".
- **Evidence** — what must have been read before a finding is reported.
- **Severity** — the mapping onto `critical`/`high`; say what is *not* a finding.
- **Output discipline** — anything specific about `category`, `file_path`,
  `line_range`, `description`, `recommendation`.

Frontmatter `name` must match the directory name (lowercase, digits, single
hyphens, ≤ 64 characters). Keep the body under ~500 lines; put long tables in a
reference file and mention it by filename — the skill directory is readable by
the agent. Test with `secscan review ./fixture --skill ./my-skill` against a
repository with known findings and compare `findings.csv` with and without it.

## How skills reach the agent, and the trust model

`src/secscan/skills.py` loads each `SKILL.md`, validates it, and
`reviewer._build_options` appends the bodies to the system prompt under an
"Operator-supplied security skills" heading that tells the model the text is
trusted operator input and that the tool set, rubric and output contract are
unchanged. Each skill's directory is passed to the agent as an additional
readable directory (`add_dirs`) so reference files can be opened with `Read`
without a permission prompt — which nothing could answer in an unattended run.

Two things are deliberately *not* done:

- Skills are not loaded through Claude Code's own skill discovery
  (`setting_sources`, `skills=`, `plugins=`). Enabling project settings would
  also load the scanned repository's `.claude/` directory, which an attacker
  controls; that is the exact prompt-injection vector the hermetic review exists
  to close. The `Skill` tool is also unnecessary: prompt injection is
  deterministic and works identically through OpenRouter, Kimi and Copilot.
- Skills never widen the tool allowlist. A `SKILL.md` declaring
  `allowed-tools: Bash` still runs read-only.

The flip side is that skill text is trusted like the system prompt. Only pass
`--skill` paths you have read, and never point it inside a repository you are
scanning.

## Cost

The system prompt is sent on every agent turn. Bundled skills are roughly
1,000–1,300 words each (about 2,000–3,000 tokens); with all four enabled the
prompt grows by roughly 8,000–12,000 tokens per turn, most of which is served
from the prompt cache on Anthropic and OpenRouter. Watch `cost_usd` in `summary.csv` when
introducing a skill, and prefer two well-chosen skills over six.

## Gaps a skill cannot close

Because the reviewer cannot run tools or reach the network, some checks belong
outside the review and are explicitly left to other scanners:

| Check | Why not here | Run instead |
|---|---|---|
| Known-CVE dependency scanning | needs a vulnerability database | `osv-scanner`, Dependabot, `pip-audit`, `npm audit`, Trivy |
| High-recall secret scanning with verification | needs entropy scanning across history and live validation | `gitleaks`, `trufflehog`, GitHub Secret Scanning |
| Rule-based SAST at scale | needs the Semgrep/CodeQL engines | Semgrep, CodeQL (Trail of Bits `static-analysis` for the workflow) |
| Container/IaC policy at scale | needs the policy engines | Trivy, Checkov, tfsec, kube-linter |

The bundled `false-positive-filter` tells the reviewer to leave those to their
tools rather than guess, which is what keeps its High/Critical output credible.
