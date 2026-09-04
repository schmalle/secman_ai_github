# secscan

A command-line tool that security-reviews GitHub repositories with an autonomous
coding agent. Point it at a **local checkout** (`secscan review ./dir`), a **single
remote repository** (`secscan scan owner/name` or a URL — cloned with a GitHub App
installation token or a personal access token), or **every repository a GitHub App can
reach** (`secscan run`). Each review runs over a local clone, and writes a
**CSV of High/Critical findings per repository** plus an aggregate `summary.csv` index.
Findings and state also live in a database (SQLite by default, MySQL/MariaDB
optionally), findings can become GitHub issues or secman vulnerabilities, results can
be emailed as an HTML report — and with `--fix` / `--create-fix-prs` the agent goes
back in, remediates the High/Critical findings, and opens a **pull request with the
proposed fixes** (see [Fixing findings](#fixing-findings---fix-and---create-fix-prs)).

The review step is pluggable (`--engine`): **Claude Code** (default; billed through
Anthropic directly, a Claude subscription login, OpenRouter, Moonshot/Kimi, or a
Copilot bridge), the **OpenAI Codex CLI**, the **Kimi Code CLI**, or
[CodeScanAI](https://github.com/codescan-ai/codescan) — see
[Review engines](#review-engines---engine).

## How it works

```
list installations → mint installation token → list repos (filter)
   + explicit targets (secscan repo add / --repos-file), resolved via their installation
   → shallow clone (or: a local directory you already have)
   → read-only security review by the chosen engine → validate findings JSON
   → write per-repo CSV + DB findings → update state ↘ aggregate summary.csv
                                                     ↘ --create-issues (GitHub issues)
                                                     ↘ --fix → fixes.patch
                                                        ↘ --create-fix-prs (branch + PR)
                                                     ↘ --push-to-secman, send-report
```

Every review — and every fix — is performed on a **local checkout**: either the
directory you hand to `review` (already cloned, nothing is fetched) or a fresh shallow
clone `scan`/`run` make with the App or PAT credential. The review agent runs with
**read-only tools only** (`Read`, `Grep`, `Glob`) — no Bash, no network — so untrusted
repository code is never executed. Repo contents are treated as untrusted data
(prompt-injection aware); with the Codex engine the agent has a shell, confined to
Codex's own read-only sandbox (see [Review engines](#review-engines---engine)).

Switching `--engine` replaces only the review (and fix) box; everything before and after
it — enumeration, cloning, CSV, state, issues, fix PRs, secman, email — is unchanged.

## Prerequisites

- Python 3.10+ (this repo pins 3.12 via `uv`).
- `git` on `PATH`.
- One review engine, installed and authenticated (see
  [Review engines](#review-engines---engine)):
  - **Claude Code** (default): Node + the Claude Code CLI (`npm install -g
    @anthropic-ai/claude-code`); the Claude Agent SDK shells out to it. Auth via
    `ANTHROPIC_API_KEY`, a logged-in Claude subscription (`claude login`, i.e. your
    Claude Code license), **or** an `OPENROUTER_API_KEY`, a Moonshot/Kimi key, or a
    local GitHub Copilot bridge (see [Choosing a provider](#choosing-a-provider---provider)).
  - **Codex CLI**: `npm install -g @openai/codex`, then `OPENAI_API_KEY` or `codex login`.
  - **Kimi CLI**: `uv tool install kimi-cli` (Python 3.12+), then `KIMI_API_KEY`,
    `MOONSHOT_API_KEY`, or `kimi login`.
  - **CodeScanAI**: `pip install codescanai` and an OpenAI/Gemini key or a self-hosted
    server.
- GitHub credentials. A **GitHub App** is the primary credential; a PAT is an
  optional fallback. Either works alone.
  - **GitHub App** — installed on the target org(s)/repos with permissions
    **Contents: Read**, **Metadata: Read**. You need two things from its settings page
    (*Settings → Developer settings → GitHub Apps → your app*):
    1. Its **App ID** (or, equivalently, its **Client ID** — GitHub accepts either as
       the JWT issuer).
    2. A **private key**: scroll to **Private keys → Generate a private key** and keep
       the downloaded `.pem`.

    The **Client Secret** is *not* usable here. It belongs to the OAuth user-login
    flow; an App signs its own JWT with the private key to mint installation tokens,
    and there is no substitute for it.

    Step-by-step setup, the full environment-variable reference, a verification
    ladder and a troubleshooting table:
    **[docs/GITHUB_APP_SETUP.md](docs/GITHUB_APP_SETUP.md)**.
  - **Personal access token** (`GITHUB_TOKEN`) — optional fallback with read access to
    the repos you want to scan (classic: `repo` scope; fine-grained: Contents +
    Metadata read). Useful for repos the App is not installed on.
  - For `list-users` only, the credential also needs to see organization membership:
    a PAT with the `read:org` scope (classic) or Members: Read (fine-grained), held by
    a member of the org; or a GitHub App with the **Organization permission
    Members: Read**, installed on that org.
- Works against github.com, GitHub Enterprise Cloud (including data residency) and
  GitHub Enterprise Server — see [GitHub Enterprise](#github-enterprise-cloud-and-server).
- (Optional) MySQL/MariaDB backend: install the client system libs
  (macOS `brew install mysql-client`; Debian/Ubuntu
  `apt-get install default-libmysqlclient-dev pkg-config`), then
  `uv sync --extra mysql`.

## Configuration

Set via environment (a `.env` you source yourself works fine). Secrets are read from
the environment only and never written to disk.

| Variable | Purpose |
|---|---|
| `GITHUB_APP_ID` | GitHub App ID (numeric), or… |
| `GITHUB_APP_CLIENT_ID` | …the App's Client ID — GitHub accepts either as the JWT issuer. `GITHUB_APP_ID` wins if both are set |
| `GITHUB_APP_PRIVATE_KEY` | PEM contents, or… |
| `GITHUB_APP_PRIVATE_KEY_PATH` | …path to the `.pem` file. **Required** — the App's Client Secret cannot replace it |
| `GITHUB_TOKEN` | Personal access token — optional fallback for repos the App is not installed on |
| `GITHUB_API_URL` | GitHub deployment (or `--github-api-url`); unset = github.com / Enterprise Cloud. See [GitHub Enterprise](#github-enterprise-cloud-and-server) |
| `ANTHROPIC_API_KEY` | Claude auth (or use a subscription login) |
| `OPENROUTER_API_KEY` | Route Claude Code reviews through OpenRouter (auto-selected when set unless `--provider usecc`) |
| `OPENROUTER_SMALL_MODEL` | OpenRouter slug for Claude Code's background "small fast" model (default `anthropic/claude-haiku-4.5`); `COPILOT_SMALL_MODEL` is the Copilot equivalent |
| `CLAUDE_CONFIG_DIR` | Forwarded to the Claude Code subprocess, so a login stored outside `~/.claude` keeps working |
| `MOONSHOT_API_KEY` | Route reviews through Kimi (Moonshot); `KIMI_API_KEY` works too. Auto-selected when set and no OpenRouter key is present |
| `KIMI_BASE_URL` | Override the Kimi endpoint (default `https://api.moonshot.ai/anthropic`; mainland China: `https://api.moonshot.cn/anthropic`) |
| `KIMI_MODEL` | Kimi model the default `--model` alias resolves to (default `kimi-k2.7-code`) |
| `COPILOT_BASE_URL` | Anthropic-compatible GitHub Copilot bridge for `--provider copilot` (default `http://localhost:4141`) |
| `COPILOT_API_KEY` | Token for that bridge, if it requires one (`GITHUB_COPILOT_API_KEY` works too) |
| `COPILOT_MODEL` | Copilot model the default `--model` alias resolves to (default `claude-sonnet-4.5`) |
| `SECSCAN_ENGINE` | Review engine (or `--engine`): `claude` (default), `codex`, `kimi-cli` or `codescanai`. See [Review engines](#review-engines---engine) |
| `CODEX_BIN` / `CODEX_MODEL` / `CODEX_HOME` | `--engine codex`: how to invoke the Codex CLI (default `codex`), the model the default `--model` alias resolves to (else Codex's own default), and where `codex login` stored its credentials (default `~/.codex`) |
| `KIMI_API_KEY` | `--engine kimi-cli`: Kimi Code platform key (`https://api.kimi.com/coding/v1`); `MOONSHOT_API_KEY` selects the Moonshot open platform instead. Without either, a prior `kimi login` is used |
| `KIMI_BIN` / `KIMI_CLI_BASE_URL` / `KIMI_SHARE_DIR` | `--engine kimi-cli`: how to invoke the Kimi CLI (default `kimi`), an endpoint override for the CLI (a `KIMI_BASE_URL` ending in `/anthropic` is ignored here — that one belongs to `--provider kimi`), and Kimi's config directory (default `~/.kimi`) |
| `OPENAI_API_KEY` | OpenAI key for `--engine codescanai` (`--codescanai-provider openai`, auto-selected when set); `OPENAI_BASE_URL` points it at an OpenAI-compatible gateway |
| `GEMINI_API_KEY` | Google Gemini key for `--engine codescanai` (`--codescanai-provider gemini`; `GOOGLE_API_KEY` works too) |
| `CODESCANAI_PROVIDER` | CodeScanAI provider (or `--codescanai-provider`): `auto`, `openai`, `gemini`, `custom` |
| `CODESCANAI_MODEL` | Model CodeScanAI uses when `--model` is left at its default alias (else CodeScanAI's own per-provider default) |
| `CODESCANAI_HOST` / `CODESCANAI_PORT` / `CODESCANAI_ENDPOINT` | Self-hosted OpenAI-compatible server for `--codescanai-provider custom` (or the `--codescanai-*` flags), e.g. `http://localhost` / `11434` / `/v1` for Ollama |
| `CODESCANAI_TOKEN` | Bearer token for that custom server. No `--codescanai-token` flag — env only, so the token never reaches argv/`ps` |
| `CODESCANAI_BIN` | How to invoke CodeScanAI (or `--codescanai-bin`); default `codescanai`, may be a full command line |
| `CODESCANAI_DEFAULT_SEVERITY` | Severity for a CodeScanAI finding whose free-text severity can't be mapped (or `--codescanai-default-severity`); default `medium` |
| `SECSCAN_DB_URL` | `mysql://user:pass@host:3306/secscan` for state + findings + targets; unset = local SQLite |
| `DB_USERNAME` | MySQL/MariaDB username (or `--db-user`); overrides any user embedded in `SECSCAN_DB_URL` |
| `DB_PASSWORD` | MySQL/MariaDB password; overrides any password embedded in `SECSCAN_DB_URL`. No `--db-password` flag — env only, so the password never reaches argv/`ps` |
| `DB_SSL` | Encrypt the MySQL/MariaDB connection (or `--db-ssl`); truthy values are `"true"` and `"1"` |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | SMTP credentials for `send-report` |
| `SMTP_HOST` / `SMTP_PORT` | SMTP server for `--email-provider custom` (port defaults to 587) |
| `SMTP_FROM` | From address (defaults to `SMTP_USERNAME`) |
| `SECMAN_URL` | secman base URL (or `--secman-url`), for `push-to-secman` and `scan`/`run --push-to-secman` |
| `SECMAN_USERNAME` | secman username (or `--secman-username`); needs ADMIN or VULN role |
| `SECMAN_PASSWORD` | secman password. No `--secman-password` flag — env only, so the password never reaches argv/`ps` |
| `SECSCAN_DRY_RUN` | `1`/`true`/`yes`/`on` forces `--dry-run` on `run`, `scan`, and `push-to-secman` |

## Usage

```bash
uv sync                                   # install deps into .venv

uv run secscan list-repos                    # preview what would be scanned, with each repo's latest commit
uv run secscan list-repos --no-last-commit   # skip the commit lookup (one API call per repo faster)
uv run secscan list-users --org my-org       # org members and their roles
uv run secscan list-users --repo octo/webapp # one repo's collaborators and permissions
uv run secscan list-users --org my-org --org-repos --format json   # members + every repo's collaborators
uv run secscan list-repos --github-api-url https://ghes.example.com   # GitHub Enterprise Server
uv run secscan repo add octo/webapp       # add an explicit scan target (stored in DB)
uv run secscan repo list                  # show explicit targets
uv run secscan repo remove octo/webapp    # remove a target
uv run secscan scan octo/webapp           # clone + review one remote repo on demand
uv run secscan scan octo/webapp --branch develop   # review a specific branch
uv run secscan scan https://github.com/octo/webapp # the same, given as a URL (GITHUB_TOKEN or the App)
uv run secscan review ./some/local/repo   # review one local dir you already cloned (no GitHub)
uv run secscan review ./some/local/repo --fix      # …and write the proposed fixes as fixes.patch
uv run secscan scan octo/webapp --create-fix-prs   # review, fix, push a branch, open a pull request
uv run secscan scan octo/webapp --create-fix-prs --dry-run   # same, but only say what PR it would open
uv run secscan review ./repo --store-db --create-fix-prs     # PR from a local clone (uses its 'origin')
uv run secscan review ./some/local/repo --store-db   # …and record it in the state DB
uv run secscan skills list                # bundled security skill packs for --skill
uv run secscan scan octo/webapp --skill false-positive-filter --skill owasp-top10   # sharper review
uv run secscan run --limit 1              # full pipeline, one repo (smoke test)
uv run secscan run --org my-org           # scope to one org
uv run secscan run --targets-only         # only scan 'repo add' targets (skip App enumeration)
uv run secscan run                        # all reachable repos + explicit targets
uv run secscan run --db-url mysql://user:pass@host:3306/secscan   # MySQL/MariaDB state
uv run secscan report                     # rebuild summary.csv from state
uv run secscan stats                      # scan statistics (table / --format csv|json)
uv run secscan stats reset                # delete all stored stats (history + findings)
uv run secscan send-report --email-to sec@example.com --email-provider gmail
uv run secscan run --org my-org --email-to sec@example.com --email-provider gmail  # auto-email after scan
uv run secscan push-to-secman                              # push High/Critical findings to secman
uv run secscan push-to-secman --dry-run                    # preview only
uv run secscan scan octo/webapp --push-to-secman           # review and push, in one step
uv run secscan run --targets-only --push-to-secman         # same for a whole run
uv run secscan run --dry-run                               # no issues opened, nothing pushed to secman
uv run secscan scan octo/webapp --engine codex             # review with the OpenAI Codex CLI
uv run secscan scan octo/webapp --engine kimi-cli          # review with the Kimi Code CLI
uv run secscan scan octo/webapp --provider openrouter --model anthropic/claude-sonnet-5   # Claude Code via OpenRouter
uv run secscan scan octo/webapp --provider usecc           # Claude Code via your claude.ai login
uv run secscan scan octo/webapp --engine codescanai        # review with CodeScanAI (OpenAI key in OPENAI_API_KEY)
uv run secscan review ./repo --engine codescanai --codescanai-provider custom \
    --codescanai-host http://localhost --codescanai-port 11434 --codescanai-endpoint /v1 --model llama3   # local Ollama
```

Common flags: `--include-archived --include-forks --max-size-mb --concurrency
--engine --model --provider --skill --max-turns --max-cost-usd --timeout --output-dir --db-url --db-user --db-ssl --no-db --store-db --create-issues --fix --create-fix-prs --pr-draft --pr-prefix --push-to-secman --secman-url --secman-username --dry-run --issue-prefix --keep-clones
--branch --no-resume --limit --targets-only --repos-file --github-api-url --org-repos
--format --output --no-csv --codex-bin --codex-arg --kimi-bin --kimi-arg
--codescanai-provider --codescanai-host --codescanai-port
--codescanai-endpoint --codescanai-bin --codescanai-arg --codescanai-default-severity`.
(`DB_PASSWORD`/`SECMAN_PASSWORD`/`CODESCANAI_TOKEN` are env-only — there is no
`--db-password`/`--secman-password`/`--codescanai-token` flag.)

`list-repos` prints one tab-separated line per repo: `owner/name`, size in KB, then the
latest commit on the branch GitHub reports as HEAD — short SHA and `YYYY-MM-DD` date, or
`-` `-` if the repo is empty or unreadable. Each commit found is also recorded in the
state DB (`last_commit_sha`, `last_commit_date` on the `repos` table) without disturbing
the repo's scan status; `--output-dir`, `--db-url`, `--db-user`, `--db-ssl` (and the
env-only `DB_PASSWORD`) select the database, and `--no-db` prints without storing.

The commit lookup costs one extra API call per repo. `--no-last-commit` skips it — the
line is then just `owner/name` and size, and nothing is written to the DB.

`run` and `scan` record the same two columns for every repo they clone, read from the
clone itself (`git log -1`), so they cost no extra API calls and reflect the branch
actually reviewed.

`scan` takes the repository as `owner/name` or as a URL — `https://github.com/owner/name`,
`https://github.com/owner/name.git`, `git@github.com:owner/name.git`. A URL on a GitHub
Enterprise host (`https://ghes.example.com/owner/name`) also selects that deployment,
as if `--github-api-url https://ghes.example.com` had been passed. Cloning uses the
GitHub App installation that owns the repo, or `GITHUB_TOKEN` when the App is not
installed there — so a one-off scan of any repository a token can read is
`GITHUB_TOKEN=ghp_… secscan scan https://github.com/owner/name`.

`--branch` (on `run` and `scan`) selects the branch to clone and review. Without it,
each repo's default branch is used (whatever GitHub reports as HEAD — `main` for most
repos). With `run`, the one branch name applies to every repo in scope; a repo that
doesn't have that branch is recorded as a failed scan and the run continues.

`--timeout` (default 900s) aborts a review if the agent produces no output for that
long — a stall guard (e.g. a permission prompt with no interactive terminal to answer
it), not a cap on total review duration. `--timeout 0` disables it.

`--no-db` skips all DB storage (state, findings, targets) for `run`/`scan` — only
per-repo `findings.csv` is written; `summary.csv` is skipped since it's normally
rebuilt from the state store. Useful for one-off scans where you don't want
`output/secscan.sqlite3` (or a configured MySQL backend) touched at all.

`--store-db` is the mirror image on `review`, which writes only `findings.csv` by
default. With it, the local review is recorded like any scanned repo — under owner
`local` and the directory name (`local/my-app`), with its High/Critical findings, the
reviewed `git log -1` commit (blank if the directory is not a git repo), cost and
duration — and `summary.csv` is rebuilt. `--db-url`, `--db-user` and `--db-ssl` (or
`SECSCAN_DB_URL` / `DB_USERNAME` / `DB_PASSWORD` / `DB_SSL`) select the database,
exactly as on `run`/`scan`. Reviewing the same directory again replaces its
findings, and `stats`, `report` and `push-to-secman` then see local reviews alongside
GitHub ones. `--create-issues` remains `run`/`scan`-only — a local directory has no
GitHub repo to file against.

## Security skills (`--skill`)

The reviewer's base prompt is general-purpose. `--skill` (on `run`, `scan`, and
`review`, repeatable) appends operator-chosen **skill packs** — Markdown
checklists in the [Agent Skills](https://agentskills.io) `SKILL.md` format — to
its system prompt, so a review can be sharpened for a technology or held to a
stricter false-positive bar without changing the tool. Four are bundled:

| Skill | What it adds |
|---|---|
| `false-positive-filter` | Exploitability bar, hard exclusions and precedent rules adapted from Anthropic's `claude-code-security-review` action — recommended whenever findings feed `--create-issues` or `--push-to-secman` |
| `owasp-top10` | OWASP Top 10:2025 as a read-only review checklist: what to grep for, evidence required, severity/CWE mapping |
| `cicd-and-iac` | GitHub Actions pwn-requests and expression injection, AI agents in CI, Dockerfile/Kubernetes/Terraform misconfigurations |
| `llm-app-security` | Prompt injection reaching tools, LLM output in dangerous sinks, excessive agency, MCP servers, RAG boundaries |

```bash
uv run secscan skills list                                   # names + descriptions
uv run secscan skills show false-positive-filter             # print one in full
uv run secscan run --org my-org --skill false-positive-filter --skill owasp-top10
uv run secscan review ./repo --skill ./my-skills/company-rules   # any SKILL.md directory
```

A bare name is a bundled skill; anything else is a path to a skill directory (or
its `SKILL.md`), so skills published on GitHub — e.g. agamm/claude-code-owasp or
the reasoning-only Trail of Bits plugins — can be cloned and used as-is. Unknown
names fail before anything is cloned. Skills never widen the reviewer's read-only
tool set, never change the JSON output contract or severity rubric, and are never
auto-discovered from the scanned repository (its `.claude/` directory is untrusted).
Their text is re-sent every turn, so each one adds a few thousand tokens per turn.

Which GitHub-hosted security skills fit this tool, which do not and why, how the
bundled ones were derived, and how to write your own:
**[docs/SECURITY_SKILLS.md](docs/SECURITY_SKILLS.md)**.

## Dry run

`--dry-run` (on `run`, `scan`, `review`, and `push-to-secman`) guarantees the command
makes **no external writes**:

* **No GitHub issue is ever opened.** With `--create-issues`, the run prints what
  it *would* create or skip and makes zero GitHub API calls and zero
  issue-tracking DB writes (a repeat finding's "last seen" timestamp isn't
  bumped either). Without `--create-issues` nothing would be opened anyway, but
  the flag is still accepted and still enforced — so it's safe to pass
  unconditionally in a wrapper script.
* **Nothing is written to secman.** `push-to-secman --dry-run` — and
  `scan`/`run --push-to-secman --dry-run` — list what they would push without
  logging in or calling `cli-add` even once; because they never contact secman,
  they don't need `SECMAN_URL`/`SECMAN_USERNAME`/`SECMAN_PASSWORD` to be set at all.
* **No branch is pushed and no pull request is opened.** With `--create-fix-prs`, the
  fix agent still runs and `fixes.patch` is still written locally, but the run only
  prints the branch name and base it *would* push and open a PR for — zero `git push`,
  zero GitHub API calls, nothing recorded in the PR ledger.

Set `SECSCAN_DRY_RUN=1` (or `true`/`yes`/`on`) to force it for every command in
an environment — useful in CI or a shared shell where an accidental real write
would be expensive.

```bash
uv run secscan run --create-issues --dry-run   # full run, zero issues opened
uv run secscan push-to-secman --dry-run        # preview the secman push
SECSCAN_DRY_RUN=1 uv run secscan run --create-issues   # same, via the environment
```

The promise is enforced, not just documented: dry-run arms a process-wide guard
(`secscan/dryrun.py`), and every call that would open an issue, push a fix branch, open
a pull request, or reach secman checks it first, raising `DryRunViolation` rather than
performing the write. In a
correct dry run the guard never fires — it's there so a future refactor that
forgets to honour the flag fails loudly instead of silently filing issues.

What `--dry-run` does **not** suppress: the security review itself still runs (and
still costs model tokens), so does the fix step of `--fix`/`--create-fix-prs` (its
patch is a local artifact like `findings.csv`), the scan/findings state in the DB is
still written, and `--email-to` still sends the report. It scopes exactly to the
three outward-facing integrations above.

## Authentication: GitHub App vs PAT

The App is the primary credential and is self-sufficient — it enumerates, resolves
explicit targets, and clones on its own. The PAT is an optional fallback for repos no
installation covers. Either works alone; together they complement each other.

```bash
export GITHUB_APP_ID=4254305                      # or GITHUB_APP_CLIENT_ID=Iv23li…
export GITHUB_APP_PRIVATE_KEY_PATH=~/.secrets/secscan-app.pem
uv run secscan list-repos                         # no GITHUB_TOKEN needed
```

| Configured | `run` scans | `list-repos` shows | Clone auth |
|---|---|---|---|
| App only | App-enumerated repos + explicit targets on an installed account | App-reachable repos | Installation tokens |
| PAT only | Explicit targets (`secscan repo add`) + `--repos-file` entries | Token-accessible repos | The PAT |
| Both | Union of the above | Deduped union (App entry wins) | Installation token per App repo, PAT for the rest |

An explicit target is resolved through the App first, so it clones with that
installation's token; the PAT is consulted only when no installation owns the account.

PAT-only mode deliberately does **not** scan everything the token can see — a
personal token often reaches thousands of repos, and an accidental full scan is a
cost hazard. Add repos explicitly (`secscan repo add`), or pass `--repos-file`.

**Why not the Client ID + Client Secret pair?** Those drive GitHub's OAuth
*user*-login flow, which needs a browser redirect and yields an expiring token
scoped to a person. Server-to-server access — what a scanner needs — goes through
an App JWT signed with the private key, exchanged for a 1-hour installation token.
That is the flow implemented here, and the same one
[secman](https://github.com/schmalle/secman) uses in `GithubAppClientService`.

See **[docs/GITHUB_APP_SETUP.md](docs/GITHUB_APP_SETUP.md)** for the full setup walkthrough.

## GitHub Enterprise (Cloud and Server)

`secscan` talks to whichever GitHub deployment `--github-api-url` (or `GITHUB_API_URL`)
names. It applies to **every** command that reaches GitHub — `run`, `scan`,
`list-repos`, `list-users` — not just the one you pass it to, and it covers API calls,
issue creation, and the URLs repositories are cloned from.

| Deployment | What to pass | Resulting API host |
|---|---|---|
| github.com / **Enterprise Cloud** | nothing | `https://api.github.com` |
| **Enterprise Cloud with data residency** | `https://TENANT.ghe.com` | `https://api.TENANT.ghe.com` |
| **Enterprise Server** (self-hosted) | `https://ghes.example.com` | `https://ghes.example.com/api/v3` |

Enterprise Cloud on github.com is the default and needs no configuration at all — the
flag exists for the other two. The web host and the API host are derived from each
other, so either one is accepted: `https://acme.ghe.com` and `https://api.acme.ghe.com`
mean the same thing, and the `/api/v3` suffix Enterprise Server needs is added for you
(passing it yourself is fine too). A trailing slash is ignored; a URL with no scheme, or
with some other path, is rejected with a message listing the accepted forms rather than
failing later as a 404.

```bash
uv run secscan list-users --org my-org --github-api-url https://ghes.example.com
GITHUB_API_URL=https://acme.ghe.com uv run secscan run --org my-org
```

The credential itself does not change: `GITHUB_APP_ID` (or `GITHUB_APP_CLIENT_ID`) +
private key, or `GITHUB_TOKEN`, issued by that deployment.

## Listing organization users

`secscan list-users` reads the usernames GitHub associates with an organization. It is
**read-only** — nothing is written to GitHub — and works identically on all three
deployments above.

```bash
uv run secscan list-users --org my-org                     # members, with admin/member
uv run secscan list-users --repo my-org/webapp             # that repo's collaborators
uv run secscan list-users --org my-org --org-repos         # members + every repo's collaborators
uv run secscan list-users --org my-org --format json --output users.json
```

Two listings feed it:

| Source | GitHub API | `role` column |
|---|---|---|
| `--org` | `GET /orgs/{org}/members` | `admin` or `member` |
| `--repo`, `--org-repos` | `GET /repos/{owner}/{repo}/collaborators` | `admin`, `maintain`, `write`, `triage`, `read` |

**These APIs exist only for organizations.** A personal account has no members, and
`--org` against one fails with an explanatory message and exit code 1 — that is the API
saying "not an organization", not a bug. `--org-repos` requires `--org`; at least one of
`--org` / `--repo` (repeatable) must be given.

**Prerequisite:** the credential must be allowed to see membership — a PAT with
`read:org` (classic) or Members: Read (fine-grained) held by a member of the org, or a
GitHub App with the **Organization permission Members: Read** installed on that org.
Existing App installations require re-approval after that permission is added. With both
credentials configured, the App is asked first and the PAT is the fallback, so an org the
App is not installed on is still listed if the token can see it.

Output goes three places at once:

* **stdout** — tab-separated `source`, `org` or `org/repo`, `login`, `role`, `type`,
  `name`. `--format csv` or `--format json` replaces the table (`--output FILE` writes it
  to a file instead of stdout).
* **`<output-dir>/users.csv`** — always written unless `--no-csv`, with the full column
  set (`source, org, repo, login, role, user_type, site_admin, user_id, name, email,
  html_url`).
* **the state DB** — the `github_users` table, keyed on `(org, repo, login)`, unless
  `--no-db`. Each listing replaces its own scope, so somebody who left the org disappears
  on the next run rather than lingering. `stats reset` does not touch it.

**Known limitation:** these REST endpoints return GitHub identities only. SAML/SCIM
external identities on Enterprise Cloud and LDAP DNs on Enterprise Server are *not*
exposed here, and `email` is `null` (stored as an empty string) for most users unless the
caller is an organization owner.

## Scan targets

`secscan repo add owner/name` registers a repository in the state database; every
`run` scans registered targets in addition to App-enumerated repos. Targets bypass
the size/archive/fork filters (they were added by hand) and are deduplicated against
enumeration. `repo list` and `repo remove` manage the set; targets follow the
selected backend (`--db-url` / `SECSCAN_DB_URL`), so a shared MySQL database gives a
shared target list.

To scan only the registered targets — without enumerating the whole GitHub App —
use `secscan run --targets-only` (a `--repos-file` allowlist still applies;
`--org` does not, since it only filters App enumeration). To scan one specific
remote repo on demand without registering it as a target, use
`secscan scan owner/name`; it clones, reviews, and records the result the same way
`run` does for a single repo, but doesn't add it to the target list. `scan` works with
App-only credentials: it locates the installation owning `owner` and clones with that
installation's token, falling back to the PAT when the App is not installed there.

## Creating GitHub issues

`--create-issues` (on `run`/`scan`) opens one GitHub issue per new High/Critical
finding, deduped by a content fingerprint (severity + category + title + file
path) tracked in the state DB — re-scanning the same repo never opens a second
issue for a finding already tracked, it just bumps that finding's "last seen"
timestamp. `--dry-run` previews what would be created/skipped with **zero**
GitHub API calls and zero DB writes (see [Dry run](#dry-run)). Requires the DB
(`--no-db --create-issues` is a config error).

```bash
uv run secscan scan octo/webapp --create-issues --dry-run   # preview
uv run secscan scan octo/webapp --create-issues             # actually open issues
```

Issue titles are `<prefix> <severity>: <title> (<file>)` — e.g.
`secscan: high: SQL injection in user lookup (app/db.py)`. `--issue-prefix` changes
the prefix (default `secscan:`); pass an empty string for no prefix at all:

```bash
uv run secscan scan octo/webapp --create-issues --issue-prefix '[acme]'
# -> "[acme] high: SQL injection in user lookup (app/db.py)"
```

The prefix is cosmetic: dedup keys off the finding fingerprint, not the title, so
changing it between runs never re-opens issues that already exist. Every issue also
gets the `secscan` label, which is not configurable.

**Prerequisite:** the GitHub App's permissions need **Issues: Write** added
(alongside the existing Contents: Read, Metadata: Read) — existing installations
require re-approval after this permission is added to the App manifest. PAT mode
already covers this via the `repo` scope.

## Fixing findings (`--fix` and `--create-fix-prs`)

Reviewing tells you what is wrong; `--fix` asks the same engine to put it right.
After the review, the agent is sent back into the repository with file-editing tools
and the High/Critical findings as its task; the resulting change is captured with
`git diff` and written as `<output-dir>/<owner>__<repo>/fixes.patch` (plus a
`fixes.json` with the finding fingerprints, the changed files and the agent's own
per-finding summary). `--create-fix-prs` (which implies `--fix`) additionally commits
that diff on a `secscan/fix-<key>` branch, pushes it, and opens **one pull request per
repository** against the branch that was reviewed.

```bash
uv run secscan scan octo/webapp --fix                        # patch only, nothing pushed
uv run secscan scan octo/webapp --create-fix-prs             # patch + branch + pull request
uv run secscan scan octo/webapp --create-fix-prs --dry-run   # preview the PR, push nothing
uv run secscan run --org my-org --create-fix-prs --pr-draft  # every repo in scope, PRs as drafts
uv run secscan review ./webapp --fix                         # local checkout: patch under output/local__webapp/
uv run secscan review ./webapp --store-db --create-fix-prs   # local checkout: PR on its GitHub 'origin'
git -C ./webapp apply output/local__webapp/fixes.patch       # …or apply the patch yourself
```

What the fix step can and cannot do:

* **It edits, it does not execute.** The Claude engine gains `Edit`/`Write` and keeps
  `Bash` denied; the Kimi engine's agent spec adds only its two file-writing tools;
  Codex runs in its `workspace-write` sandbox with network off. None of them can run
  the project's build or tests, so **a fix PR is a proposal for a human reviewer**, and
  its description says so. `--engine codescanai` cannot fix (it only reports).
* **It never edits your working copy.** `scan`/`run` fix the disposable clone in
  place. `review ./dir` clones the directory (or copies it, if it is not a git repo)
  into a temp workspace, fixes that, and deletes it afterwards — only the patch
  survives. The clone is of the committed HEAD, so uncommitted changes are not part
  of the fix (a warning says so).
* **One PR per set of findings.** The PR is keyed by the fingerprints of the findings
  it addresses (`fix_key` in `fixes.json`, `fix_prs` table in the state DB). A re-scan
  with the same High/Critical findings skips the fix step and the PR entirely; once a
  fix merges and the finding set changes, the next scan opens a new PR. That ledger is
  why `--create-fix-prs` needs the DB (`--no-db` is an error; on `review`, pass
  `--store-db`). `stats reset` keeps it, like the issue ledger.
* **The base branch** is the one reviewed: `--branch` if given, else the repository's
  default branch (the shallow clone's HEAD); for `review ./dir`, the branch currently
  checked out there. The PR targets it; the fix branch is pushed with the same
  token-in-environment mechanism the clone uses, never with the token on argv.
* **Titles** are `<prefix> fix <n> critical and <m> high security findings` (or
  `fix high: <title>` for a single finding); `--pr-prefix` changes the prefix (default
  `secscan:`, empty string for none), `--pr-draft` opens drafts (draft PRs are not
  available on every GitHub plan — GitHub returns an error, the outcome is reported as
  failed, and the pushed branch stays for a manual PR).

**Prerequisites:** the GitHub App needs **Contents: Write** and **Pull requests:
Write** (existing installations must re-approve after the permission change); a PAT
needs the `repo` scope. A fix that touches `.github/workflows/` additionally needs
**Workflows: Write** / the `workflow` scope, or GitHub rejects the push — the run
reports the rejection and moves on. `review ./dir --create-fix-prs` requires the
directory's `origin` remote to point at the configured GitHub host (`https://…` or
`git@…:` forms both work) and `HEAD` to be on a branch.

Cost: the fix run is a second agent session over the repository, typically comparable
to the review; `--max-turns`, `--max-cost-usd` and `--timeout` apply to it as well.
More detail — the prompts, what the agent is told not to do, and how to review a
fix PR — in [docs/FIX_PRS.md](docs/FIX_PRS.md).

## Push findings to secman

`secscan push-to-secman` pushes every High/Critical finding currently in the
state DB into [secman](https://github.com/schmalle/secman) via its
`POST /api/vulnerabilities/cli-add` endpoint (requires an ADMIN or VULN-role
secman account). One secman asset is created per scanned repo (`owner/repo` as
the hostname); re-running after a later scan updates the existing secman
vulnerability rather than duplicating it (secman upserts by asset + a stable
synthetic identifier derived from the finding's fingerprint).

```bash
export SECMAN_URL=https://secman.example.com
export SECMAN_USERNAME=vulnbot
export SECMAN_PASSWORD=…
uv run secscan push-to-secman --dry-run   # preview what would be pushed
uv run secscan push-to-secman             # actually push
```

Note that `--db-url`/`--db-user`/`DB_PASSWORD` are unrelated to these: they
configure secscan's *own* state store. secman is only ever reached over HTTPS.

### Pushing straight from a scan

`scan` and `run` accept `--push-to-secman` and the same credential options
(`--secman-url`, `--secman-username`, and the `SECMAN_PASSWORD` environment
variable — there is no `--secman-password` flag, so the password never reaches
argv/`ps`; `--secman-url`/`--secman-username` also fall back to their `SECMAN_*`
environment variables), so a review and its push are one command:

```bash
uv run secscan scan octo/webapp --push-to-secman
uv run secscan run --targets-only --push-to-secman --secman-url https://secman.example.com
```

Only the repositories that invocation reviewed are pushed — repos skipped by
`--resume` are not, and neither is anything else already in the state DB. Use
`push-to-secman` for that. Credentials are validated before the review starts, so
a misconfigured push never wastes an LLM run; `--no-db` cannot be combined with
`--push-to-secman`, since the push reads findings and first-seen dates from the
state store. A login failure exits non-zero *after* `findings.csv`, state, and any
GitHub issues are written, so nothing is lost and `push-to-secman` can retry.

`--dry-run` makes zero login/`cli-add` calls, so nothing reaches secman and no
secman credentials are needed — see [Dry run](#dry-run).

**Known limitation:** secman's `cli-add` schema has no free-text field — it only
shows a compact identifier (`SECSCAN:<category>:<fingerprint prefix>`), severity,
and asset name. Full finding detail (description, recommendation, file/line)
stays in secscan's own `findings.csv`/state DB and, if `--create-issues` was
used, the linked GitHub issue.

## MySQL / MariaDB backend

By default, state, findings, and targets live in `output/secscan.sqlite3`. Point
`--db-url` (or `SECSCAN_DB_URL`) at `mysql://user:pass@host:3306/secscan` to use
MySQL or MariaDB instead — both work with the same driver and schema, and
`mariadb://…` URLs are accepted as an alias. Install the driver first:

```bash
uv sync --extra mysql
```

CSV outputs are **always written** regardless of backend (dual-write); the database
never replaces `findings.csv` / `summary.csv`. Tables: `repos` (run state),
`findings` (High/Critical findings per repo, replaced on each review), `targets`
(explicitly-added scan targets), `issue_tracking` (one row per finding fingerprint
an issue was opened for, with first/last seen timestamps — the dedup ledger for
`--create-issues`).

To run the integration tests against a real server:

```bash
docker run --rm -e MARIADB_ROOT_PASSWORD=pw -e MARIADB_DATABASE=secscan_test -p 3306:3306 mariadb
SECSCAN_TEST_MYSQL_URL=mysql://root:pw@127.0.0.1:3306/secscan_test uv run pytest tests/test_state_mysql.py -v
```

## MySQL setup script

`scripts/setup-mysql.sh` provisions a database and application user on a MySQL/
MariaDB server you already have admin access to (for local ephemeral testing,
use the `docker run mariadb` one-liner above instead — this script is for a
real, persistent server).

Prerequisites: the `mysql` CLI client on `PATH`, network access to the target
server, and admin credentials for it.

```bash
./scripts/setup-mysql.sh --host db.internal --db-name secscan \
    --app-user secscan --admin-user root [--port 3306] [--ssl]
```

You'll be prompted (hidden input) for the admin password and a new password for
the app user — neither is ever accepted as a command-line flag. On success it
prints the config to export:

```
export SECSCAN_DB_URL=mysql://db.internal:3306/secscan
export DB_USERNAME=secscan
export DB_PASSWORD=<the password you entered>
export DB_SSL=true   # only if --ssl was passed
```

## Review engines (`--engine`)

`--engine` (on `run`, `scan`, and `review`; or `SECSCAN_ENGINE`) selects what performs
the review step. Everything around it — enumeration, cloning, `findings.csv`, the
state DB, `--create-issues`, `--push-to-secman`, `--email-to`, `stats`, `report` —
is engine-agnostic and behaves identically.

| `--engine` | Reviewer | Fix (`--fix`) | Configured by |
|---|---|---|---|
| `claude` (default) | Claude Code via the Claude Agent SDK: an autonomous, read-only agent that explores the repository with `Read`/`Grep`/`Glob` and emits secscan's JSON findings contract | yes — `Edit`/`Write`, still no `Bash` | `--provider`, `--model`, `--skill`, `--max-turns`, `--max-cost-usd` — see [Choosing a provider](#choosing-a-provider---provider) |
| `codex` | [OpenAI Codex CLI](https://github.com/openai/codex) (`codex exec`), OpenAI's terminal agent, in its read-only OS sandbox | yes — `workspace-write` sandbox, network off | `--model` (Codex model ID), `--skill`, `--codex-bin`, `--codex-arg`, `CODEX_*` env, `OPENAI_API_KEY` or `codex login` |
| `kimi-cli` | [Kimi Code CLI](https://github.com/MoonshotAI/kimi-cli) (`kimi --print`), Moonshot AI's terminal agent, with a secscan-supplied agent spec limited to `ReadFile`/`Glob`/`Grep` | yes — adds `WriteFile`/`StrReplaceFile` only | `--model` (Moonshot model ID), `--skill`, `--kimi-bin`, `--kimi-arg`, `KIMI_*` env, `KIMI_API_KEY`/`MOONSHOT_API_KEY` or `kimi login` |
| `codescanai` | [CodeScanAI](https://github.com/codescan-ai/codescan): an open-source CLI that sends each file to an LLM (OpenAI, Gemini, or an OpenAI-compatible server) one at a time and reports the vulnerabilities it finds | no | `--codescanai-provider`, `--model`, `--codescanai-host/-port/-endpoint`, `--codescanai-bin`, `--codescanai-arg`, `--codescanai-default-severity`, and the `CODESCANAI_*` environment variables |

Flags that belong to another engine are configuration errors rather than silently
ignored (a non-default `--provider` with anything but `claude`; `--skill` or `--fix`
with `codescanai`; any `--codescanai-*`, `--codex-*` or `--kimi-*` flag with a different
engine). `CODESCANAI_*`, `CODEX_*` and `KIMI_*` environment variables are never an error,
so they can be exported process-wide. Every engine is checked before anything is
cloned — executable on `PATH`, a credential present — so a misconfigured engine fails
in seconds, not after a clone.

### Using the Codex CLI

```bash
npm install -g @openai/codex
export OPENAI_API_KEY=sk-…         # or: codex login  (ChatGPT account; stored in ~/.codex/auth.json)
uv run secscan scan octo/webapp --engine codex
uv run secscan review ./repo --engine codex --model gpt-5.4 --skill owasp-top10
uv run secscan run --org my-org --engine codex --create-fix-prs
```

secscan runs `codex exec` non-interactively over the clone with its own prompt (the
same persona, rubric and JSON contract as the Claude engine, plus any `--skill`
packs, all in one prompt since `exec` has no separate system prompt) and reads the
agent's final message back through `-o`. `--model` is a Codex/OpenAI model ID; left
at the default alias, Codex's own default model applies, and `CODEX_MODEL` changes
that. Anything else Codex can be configured with — reasoning effort, a custom
`model_provider` from `~/.codex/config.toml` (Codex's route to OpenRouter and other
OpenAI-compatible endpoints), `--oss` for a local Ollama/LM Studio model — is passed
through verbatim with `--codex-arg`, e.g. `--codex-arg=-c
--codex-arg=model_reasoning_effort=high`.

What is pinned, and why: `--sandbox read-only` for reviews and `workspace-write`
(network off, `.git/` protected) for fixes; approvals never; `-c
project_doc_max_bytes=0` so the scanned repository's `AGENTS.md` is **not** loaded
into the agent's instructions; `--ephemeral` and `--skip-git-repo-check`. Unlike the
Claude and Kimi engines, Codex keeps its shell tool: the model can run commands, but
only inside Codex's OS-level sandbox (Landlock/bubblewrap on Linux, Seatbelt on
macOS — install `bubblewrap` on Linux for the native sandbox). That is weaker
isolation than a tool-restricted agent; prefer the Claude engine for repositories you
do not trust, or run Codex reviews in a throwaway container. The subprocess sees a
minimal environment: `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `CODEX_HOME`, proxy and CA
settings, nothing else. Tested with Codex CLI 0.153.

### Using the Kimi Code CLI

```bash
uv tool install kimi-cli            # Python 3.12+
export KIMI_API_KEY=sk-…            # Kimi Code platform; or MOONSHOT_API_KEY for the Moonshot open platform; or: kimi login
uv run secscan scan octo/webapp --engine kimi-cli
uv run secscan review ./repo --engine kimi-cli --model kimi-k2.7-code --fix
```

Not to be confused with `--provider kimi`, which bills *Claude Code* through
Moonshot's Anthropic-compatible endpoint; `--engine kimi-cli` runs Moonshot's own
agent. secscan hands it an agent specification (`--agent-file`) with secscan's
system prompt and an explicit tool list — `ReadFile`/`Glob`/`Grep` for reviews, plus
`WriteFile`/`StrReplaceFile` for fixes; no `Shell`, no web tools, no sub-agents — and
the task (with any `--skill` packs) on stdin, reading the result from its
`stream-json` output. The repository's `AGENTS.md`, its `.kimi/`/`.claude/`/`.agents/`
skills and your global MCP servers are all kept out of the run.

Credentials: with `KIMI_API_KEY` set, the Kimi Code platform
(`https://api.kimi.com/coding/v1`, default model `kimi-for-coding`) is used; with
`MOONSHOT_API_KEY`, the Moonshot open platform (`https://api.moonshot.ai/v1`, default
model `kimi-k2.7-code`; set `KIMI_CLI_BASE_URL=https://api.moonshot.cn/v1` for the
mainland-China host). The key reaches Kimi through its own `KIMI_API_KEY` environment
override of an inline provider config whose `api_key` is empty, so it is never on the
command line. `KIMI_MODEL` changes what the default `--model` alias resolves to (shared
with `--provider kimi`). With neither key, the model you selected with `kimi login`
is used, and `--model` then names a model alias from Kimi's own config. Extra Kimi
flags pass through with `--kimi-arg` (e.g. `--kimi-arg=--thinking`). Tested with
kimi-cli 1.50.

### Using CodeScanAI

```bash
pip install codescanai            # or: uv tool install codescanai — needs Python 3.10+
export OPENAI_API_KEY=sk-…        # or GEMINI_API_KEY=…
uv run secscan scan octo/webapp --engine codescanai
uv run secscan run --org my-org --engine codescanai --model gpt-4o --create-issues
uv run secscan review ./repo --engine codescanai --codescanai-provider gemini
```

secscan runs the `codescanai` command as a subprocess over the clone (with
`.git/` left out, since CodeScanAI walks every file and each text file is one model
call), reads its per-file report, and maps each reported vulnerability onto a
secscan finding:

| CodeScanAI | secscan finding |
|---|---|
| file header (`--- Vulnerabilities found in path ---`) | `file_path` |
| `Line N` | `line_range` |
| `[severity]` (free text chosen by the model) | `severity` — exact rubric values and common synonyms (`moderate`, `severe`, `informational`, …) are mapped; anything else becomes `--codescanai-default-severity` (default `medium`) |
| vulnerability type | `title` and `category` |
| `Issue` / `Fix` | `description` / `recommendation` |

`confidence` is always `medium`, `cost_usd` is always `0` (CodeScanAI does not report
spend — watch your provider's dashboard), and the "turns" of a review are the number
of files scanned. The raw report is kept verbatim as
`<output-dir>/<owner>__<repo>/codescanai-report.md` next to `findings.csv`. If a
custom server or a future CodeScanAI build prints secscan's own
`{"findings": [...]}` JSON contract instead of the Markdown blocks, that is accepted
too.

**Provider and model.** `--codescanai-provider` (or `CODESCANAI_PROVIDER`) is `auto`
by default: `openai` if `OPENAI_API_KEY` is set, else `gemini` if `GEMINI_API_KEY`
(or `GOOGLE_API_KEY`) is set; `custom` is never auto-selected. `--model` is passed to
CodeScanAI as-is (`gpt-4o`, `gemini-1.5-flash`, `llama3`, …); left at secscan's
default alias, CodeScanAI's own per-provider default applies (`gpt-4o-mini` for
OpenAI), and `CODESCANAI_MODEL` changes that without passing `--model` everywhere.
`OPENAI_BASE_URL` is forwarded, so the `openai` provider also works against any
OpenAI-compatible gateway. The reviewer's `--provider` (Claude routing) does not apply
here, and neither do `--skill`, `--max-turns` or `--max-cost-usd`.

**Self-hosted servers (`custom`).** Point CodeScanAI at any OpenAI-compatible server —
Ollama, vLLM, LM Studio, a corporate gateway:

```bash
export CODESCANAI_TOKEN=…         # only if the server authenticates; optional for Ollama
uv run secscan scan octo/webapp --engine codescanai --codescanai-provider custom \
    --codescanai-host http://localhost --codescanai-port 11434 --codescanai-endpoint /v1 \
    --model llama3
```

The URL is assembled the way CodeScanAI's own `--host`/`--port`/`--endpoint` assemble
it (`host[:port][endpoint]`, so `http://localhost:11434/v1` above) — but it is handed
to CodeScanAI through the `OPENAI_BASE_URL` / `OPENAI_API_KEY` environment variables
its OpenAI-compatible client reads, never on its command line. CodeScanAI's own
`--token` flag would put the bearer token into the subprocess's argv, visible to every
local process via `ps`, which is why there is deliberately no `--codescanai-token`
flag: `CODESCANAI_TOKEN` is env-only, exactly like `DB_PASSWORD` and
`SECMAN_PASSWORD`. Without a token, the same placeholder CodeScanAI itself uses is
sent, so a real `OPENAI_API_KEY` from your shell never reaches a custom server. The
same `custom` route is the workaround for Gemini when CodeScanAI's `gemini` provider
is out of step with its `pydantic-ai` dependency (CodeScanAI 0.1.4 fails with
"Unknown model: gemini:…" on current pydantic-ai): use Gemini's OpenAI-compatible
endpoint, `--codescanai-host https://generativelanguage.googleapis.com
--codescanai-endpoint /v1beta/openai --model gemini-2.5-flash` with
`CODESCANAI_TOKEN` set to the Gemini key.

**How it is invoked.** `--codescanai-bin` (or `CODESCANAI_BIN`, default `codescanai`)
may be a path or a whole command line — `'python3 -m core.runner_v2'` for a source
checkout, `'uvx codescanai'` for an on-demand install. `--codescanai-arg` (repeatable)
appends anything else verbatim, e.g. `--codescanai-arg=--changes_only`, so options
added by future CodeScanAI releases are usable without waiting for secscan. The
executable, the API key for the chosen provider, and the host for `custom` are all
checked before anything is cloned, so a misconfigured engine fails fast.

**Isolation.** The subprocess gets a minimal environment: `PATH`/`HOME`, locale, proxy
and CA-bundle variables, plus only the credential of the provider in use. Your GitHub
App key, PAT, and DB/secman/SMTP passwords never reach a process that ships file
contents to a third-party API. Note what that means: unlike the Claude engine, which
reads files locally through a tool-restricted agent, CodeScanAI **uploads every text
file in the repository** (minus `.git/`) to OpenAI, Google, or your custom server —
check your data-handling policy before pointing it at private code, and prefer the
`custom` route with a self-hosted model where that matters.

**Timeouts and failures.** `--timeout` keeps its meaning: the review is aborted if
CodeScanAI prints nothing for that long (it logs one line per file, so this is a stall
guard, not a cap on total duration). CodeScanAI exits 0 even when every file failed
(no key, unreachable server); secscan reads its log and records the repository as
failed when not a single file could be analysed, and prints a warning when only some
could.

**Limitations.** One model call per file means cost and rate-limit exposure grow with
file count, not repository complexity; CodeScanAI's own README suggests splitting very
large directories. There is no cross-file reasoning — each file is judged on its own
(with full-file context, but nothing from the rest of the repository) — so
architectural findings, secret sprawl across files, and CI/IaC review are better
served by the Claude engine, and `--skill` packs cannot be applied. Severities are
whatever the model wrote; keep the default `medium` fallback unless you have reviewed
what unmapped labels your provider produces.

## Choosing a provider (`--provider`)

With the default `--engine claude`, the reviewer is always Claude Code (via the
Claude Agent SDK); `--provider` only picks which API endpoint bills the tokens.
Available on `run`, `scan`, and `review`. (With `--engine codescanai` use
`--codescanai-provider` instead — see [Review engines](#review-engines---engine).)

| `--provider` | Behavior |
|---|---|
| `auto` (default) | OpenRouter if `OPENROUTER_API_KEY` is set, else Kimi if `MOONSHOT_API_KEY`/`KIMI_API_KEY` is set, else Anthropic. Never picks `copilot` — that one needs a local bridge process running. |
| `anthropic` | Force direct Anthropic auth (`ANTHROPIC_API_KEY` or a logged-in Claude subscription), ignoring every other provider key even if set. Does **not** strip an already-exported `ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN` — use `usecc` if those need clearing too. |
| `openrouter` | Force OpenRouter; fails with a config error if `OPENROUTER_API_KEY` isn't set. |
| `kimi` | Force Kimi (Moonshot) via its Anthropic-compatible endpoint; fails with a config error if `MOONSHOT_API_KEY`/`KIMI_API_KEY` isn't set. |
| `copilot` | Force GitHub Copilot via a local Anthropic-compatible bridge at `COPILOT_BASE_URL`. |
| `usecc` | Force the **locally authenticated Claude Code session**. Ignores every provider key and explicitly clears any inherited `ANTHROPIC_API_KEY`/`ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN`, so a shell that still exports OpenRouter vars (or any other Anthropic auth override) can't hijack the review — Claude Code falls back to your `claude.ai` login. |

Every non-Anthropic provider works the same way: it speaks the Anthropic
`/v1/messages` API, so secscan only overrides `ANTHROPIC_BASE_URL` /
`ANTHROPIC_AUTH_TOKEN` for the review subprocess (and blanks any inherited
`ANTHROPIC_API_KEY` so it can't conflict). The Claude Code CLI still has to be
installed either way.

### Using OpenRouter

Set `OPENROUTER_API_KEY` and it is used automatically (`--provider auto` is the
default); force it explicitly with `--provider openrouter`.

```bash
export OPENROUTER_API_KEY=sk-or-…
uv run secscan run --model anthropic/claude-sonnet-4.5
```

Note: with OpenRouter, `--model` takes an **OpenRouter slug** such as
`anthropic/claude-sonnet-4.5` — aliases like `sonnet` only work against Anthropic
directly (the default `sonnet` alias maps to `anthropic/claude-sonnet-5`). The Claude
Code CLI still needs to be installed; only its environment is overridden for the
review subprocess, following OpenRouter's own Claude Code integration recipe:
`ANTHROPIC_BASE_URL=https://openrouter.ai/api`, `ANTHROPIC_AUTH_TOKEN=<your key>`,
`ANTHROPIC_API_KEY` blanked. Claude Code also calls a "small fast" model (Haiku) in
the background, and every one of those calls is pinned as well —
`ANTHROPIC_MODEL`/`ANTHROPIC_DEFAULT_SONNET_MODEL`/`ANTHROPIC_DEFAULT_OPUS_MODEL` to
your `--model`, `ANTHROPIC_SMALL_FAST_MODEL`/`ANTHROPIC_DEFAULT_HAIKU_MODEL` to
`anthropic/claude-haiku-4.5` (override with `OPENROUTER_SMALL_MODEL`) — so no request
ever leaves with an alias OpenRouter does not know. `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`
is set for the subprocess too, since a gateway does not serve the CLI's update and
telemetry endpoints. The same pinning applies to the `kimi` and `copilot` providers
(there the small model defaults to your main model).

### Using Kimi (Moonshot)

Set `MOONSHOT_API_KEY` (or `KIMI_API_KEY`) and Kimi is used automatically when no
OpenRouter key is present; force it explicitly with `--provider kimi`.

```bash
export MOONSHOT_API_KEY=sk-…
uv run secscan run --provider kimi --model kimi-k2.7-code
```

`--model` takes **Moonshot model IDs** (`kimi-k2.7-code`, `kimi-k3`, …). Left at the
default, the `sonnet` alias maps to `kimi-k2.7-code` and `opus` maps to `kimi-k3`;
set `KIMI_MODEL` to change what the alias resolves to without passing `--model`
everywhere. For the mainland-China platform, set
`KIMI_BASE_URL=https://api.moonshot.cn/anthropic`.

### Using GitHub Copilot

Copilot's API speaks OpenAI, not Anthropic, so this provider expects a local
Anthropic-compatible bridge in front of your Copilot subscription — e.g.
[`copilot-api`](https://github.com/ericc-ch/copilot-api), which listens on
`http://localhost:4141`:

```bash
npx copilot-api@latest start          # in another terminal; authenticates with GitHub
uv run secscan scan --provider copilot --model claude-sonnet-4.5 octo/webapp
```

`--model` takes **Copilot model IDs** (`claude-sonnet-4.5`, `gpt-4.1`, … — whatever
your Copilot plan exposes); the default `sonnet` alias maps to `claude-sonnet-4.5`,
and `COPILOT_MODEL` overrides that. Point `COPILOT_BASE_URL` at the bridge if it
isn't on the default port. secscan sends a placeholder bearer token unless
`COPILOT_API_KEY` is set, so a real Anthropic credential is never forwarded to the
local bridge. Check your Copilot plan's terms before pointing an automated scanner
at it.

### Forcing your local Claude Code login (`--provider usecc`)

Use this when `OPENROUTER_API_KEY`, `MOONSHOT_API_KEY`, `ANTHROPIC_API_KEY`, or `ANTHROPIC_BASE_URL` is
set somewhere in your environment (e.g. exported in a shell profile for other tools)
and you want to guarantee the review runs against your own `claude.ai` subscription
login instead — no key lookup, no OpenRouter, no risk of an inherited env var being
treated as "another auth source" and disabling Claude Code's connectors.

```bash
uv run secscan scan --provider usecc --model sonnet octo/webapp
```

With `usecc`, `--model` takes bare Anthropic aliases (`sonnet`, `opus`, …), the same
as plain `anthropic`. Both keep working when your login lives outside `~/.claude`:
`CLAUDE_CONFIG_DIR` is forwarded to the review subprocess, as are proxy and CA
variables (`HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`), while
everything else in secscan's environment is withheld from it.

## Email reports

`secscan send-report` emails the latest results from the state database as a
multipart **HTML + plain-text** report (repository summary table plus the top
findings, critical first):

```bash
export SMTP_USERNAME=reports@example.com
export SMTP_PASSWORD=…                      # app password for Gmail
uv run secscan send-report --email-to sec@example.com --email-provider gmail
uv run secscan send-report --email-to a@x.com --email-to b@y.com --email-provider o365
uv run secscan send-report --email-to sec@example.com --smtp-host mail.internal --smtp-port 2525
```

- **Gmail** (`--email-provider gmail` → `smtp.gmail.com:587`): use an
  [app password](https://myaccount.google.com/apppasswords) — regular passwords are
  rejected on accounts with 2FA.
- **Office 365** (`--email-provider o365` → `smtp.office365.com:587`): the mailbox
  needs **SMTP AUTH (authenticated client submission)** enabled; some tenants
  disable it by default.
- **Custom** (default): any SMTP server via `SMTP_HOST`/`SMTP_PORT` or
  `--smtp-host`/`--smtp-port`.

Delivery always uses STARTTLS on the submission port (587-style); implicit-TLS
port 465 is not supported. Useful flags: `--subject`, `--max-findings` (default 50),
`--db-url` to read from a shared MySQL/MariaDB backend.

### Automatic notification after a scan

`run` and `scan` accept the same email flags to send the report automatically at
the end of a scan — no separate `send-report` invocation needed:

```bash
uv run secscan run --org my-org --email-to sec@example.com --email-provider gmail
uv run secscan scan octo/webapp --email-to a@x.com --email-to b@y.com
```

Behavior:

- The email is sent **only when the run found High/Critical findings**; a clean run
  just logs that the report was skipped.
- SMTP configuration is validated **before** the scan starts (missing
  `SMTP_USERNAME`/`SMTP_PASSWORD` fails fast instead of after an expensive review).
- A delivery failure at the end is a warning, never a scan failure — results are
  already stored, and `send-report` can resend at any time.
- Incompatible with `--no-db` (the report is built from the state DB).

## Statistics

`secscan stats` summarizes everything in the state database:

```bash
uv run secscan stats                          # human-readable table
uv run secscan stats --format json            # full payload as JSON
uv run secscan stats --format csv --output stats.csv   # per-repo rows as CSV
uv run secscan stats --top 25                 # include more repos in the ranking
```

Reported metrics: repos by scan status (done / failed / pending), stored findings
broken down by severity (critical / high / medium / low / info), total critical and
high counts, failed-repo count, total review cost, number of GitHub issues created
(tracked for dedup), the most recent review timestamp, and the top repos ranked by
finding count.

`--format csv` writes one row per top repo (`repo,status,critical,high,
total_findings,cost_usd,reviewed_at`); the scalar totals go to stderr so stdout
stays clean CSV. `--format json` includes everything in one document. Reads the
same backend as every other command (`--db-url` / `SECSCAN_DB_URL` or the local
SQLite file in `--output-dir`).

### Deleting stored statistics

`secscan stats reset` wipes the stats: all scan history (repo records) and all stored
findings. It prompts for confirmation, stating what is about to be deleted; `--yes`
skips the prompt for scripts.

```bash
uv run secscan stats reset                 # prompts, then clears history + findings
uv run secscan stats reset --yes           # no prompt
uv run secscan stats reset --yes --include-csv   # also delete the generated CSVs
```

Deliberately **kept**:

- **Registered scan targets** (`secscan repo add`) — the reset clears results, not
  your scan scope. Use `secscan repo remove` for those.
- **GitHub issue tracking** — clearing it would make the next `--create-issues` run
  re-open issues that already exist on GitHub.

`--include-csv` additionally deletes `summary.csv` and every
`<owner>__<repo>/findings.csv` under `--output-dir`, removing a per-repo directory
only once it is empty; other files there are left alone. Without it, `output/` is
untouched.

Like every other command, `reset` acts on the configured backend — including a shared
MySQL/MariaDB database if `--db-url` / `SECSCAN_DB_URL` is set, in which case it
clears the stats for everyone using it.

## Output

```
output/
  <owner>__<repo>/findings.csv   # High + Critical findings for that repo
  <owner>__<repo>/fixes.patch    # unified diff of the proposed fixes (--fix / --create-fix-prs)
  <owner>__<repo>/fixes.json     # finding fingerprints, changed files, the fix agent's summary
  <owner>__<repo>/codescanai-report.md   # CodeScanAI's raw report (--engine codescanai only)
  summary.csv                    # one row per repo: counts, status, cost, duration
  users.csv                      # org members + repo collaborators (secscan list-users)
  secscan.sqlite3                # state + findings + targets + issue/PR tracking + users (unless --db-url)
  _clones/                       # working clones, deleted after each review unless --keep-clones
```

## Development & tests

```bash
uv run pytest            # full offline suite (no network, no credentials needed)
uv run pytest -v tests/test_emailer.py        # e.g. one module
```

Tests never hit the network: the Claude Agent SDK, PyGithub, SMTP, git pushes, and
the `codescanai`, `codex` and `kimi` CLIs (stub scripts that reproduce each one's
output format) are replaced with fakes. MySQL/MariaDB integration tests are skipped unless
`SECSCAN_TEST_MYSQL_URL` is set (see above).

The [dry-run](#dry-run) guard is process-wide state, so `tests/conftest.py` disarms
it (and clears `SECSCAN_DRY_RUN`) around every test — a test that arms the guard
must not leak into the next one, and a stray `SECSCAN_DRY_RUN` in your shell must
not change what the suite exercises.

## Notes & limits

- **Cost** scales with repo count/size. Use `--limit`, `--org`, `--max-cost-usd`, and the
  `sonnet` default to control spend; per-repo cost is recorded in `summary.csv`.
  With `--engine codescanai` cost scales with *file count* (one call per file), is not
  reported (`cost_usd` stays 0), and `--max-cost-usd` has no effect.
- Very large monorepos may exceed one autonomous pass — a known limitation.
- The reviewer cannot run scanners: known-CVE dependency checks, high-recall secret
  scanning and rule-based SAST belong to `osv-scanner`, `gitleaks`, Semgrep and
  friends — see [docs/SECURITY_SKILLS.md](docs/SECURITY_SKILLS.md#gaps-a-skill-cannot-close).
- The fix step cannot run the project's tests — every fix PR needs a human review
  (see [Fixing findings](#fixing-findings---fix-and---create-fix-prs)).
- For stronger isolation, run reviews inside a throwaway network-less container —
  especially with `--engine codex`, whose agent keeps a (sandboxed) shell.
