# secscan

A command-line tool that enumerates **all reachable repositories** of a GitHub App
(and/or explicitly-added repos with a personal access token), clones each one, runs an
**autonomous Claude Code security review** over the full codebase, and writes a
**CSV of High/Critical findings per repository** plus an aggregate `summary.csv` index.
Findings and state also live in a database (SQLite by default, MySQL/MariaDB
optionally), and results can be emailed as an HTML report.

## How it works

```
list installations → mint installation token → list repos (filter)
   + explicit targets (secscan repo add / --repos-file, cloned with a PAT)
   → shallow clone → Claude read-only security review → validate findings JSON
   → write per-repo CSV + DB findings → update state ↘ aggregate summary.csv
                                                     ↘ secscan send-report (HTML email)
```

The review agent runs with **read-only tools only** (`Read`, `Grep`, `Glob`) — no
Bash, no network — so untrusted repository code is never executed. Repo contents are
treated as untrusted data (prompt-injection aware).

## Prerequisites

- Python 3.10+ (this repo pins 3.12 via `uv`).
- `git` on `PATH`.
- Node + the Claude Code CLI installed and authenticated. The Claude Agent SDK shells
  out to it. Auth via `ANTHROPIC_API_KEY`, a logged-in Claude subscription, **or** an
  `OPENROUTER_API_KEY`, a Moonshot/Kimi key, or a local GitHub Copilot bridge (see
  [Choosing a provider](#choosing-a-provider---provider)).
- GitHub credentials — one (or both) of:
  - A **GitHub App** installed on the target org(s)/repos with permissions
    **Contents: Read**, **Metadata: Read**. You need its App ID and a private key (`.pem`).
  - A **personal access token** (`GITHUB_TOKEN`) with read access to the repos you
    want to scan (classic: `repo` scope; fine-grained: Contents + Metadata read).
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
| `GITHUB_APP_ID` | GitHub App ID |
| `GITHUB_APP_PRIVATE_KEY` | PEM contents, or… |
| `GITHUB_APP_PRIVATE_KEY_PATH` | …path to the `.pem` file |
| `GITHUB_TOKEN` | Personal access token — alternative or complement to the App |
| `GITHUB_API_URL` | GitHub deployment (or `--github-api-url`); unset = github.com / Enterprise Cloud. See [GitHub Enterprise](#github-enterprise-cloud-and-server) |
| `ANTHROPIC_API_KEY` | Claude auth (or use a subscription login) |
| `OPENROUTER_API_KEY` | Route reviews through OpenRouter (auto-selected when set unless `--provider usecc`) |
| `MOONSHOT_API_KEY` | Route reviews through Kimi (Moonshot); `KIMI_API_KEY` works too. Auto-selected when set and no OpenRouter key is present |
| `KIMI_BASE_URL` | Override the Kimi endpoint (default `https://api.moonshot.ai/anthropic`; mainland China: `https://api.moonshot.cn/anthropic`) |
| `KIMI_MODEL` | Kimi model the default `--model` alias resolves to (default `kimi-k2.7-code`) |
| `COPILOT_BASE_URL` | Anthropic-compatible GitHub Copilot bridge for `--provider copilot` (default `http://localhost:4141`) |
| `COPILOT_API_KEY` | Token for that bridge, if it requires one (`GITHUB_COPILOT_API_KEY` works too) |
| `COPILOT_MODEL` | Copilot model the default `--model` alias resolves to (default `claude-sonnet-4.5`) |
| `SECSCAN_DB_URL` | `mysql://user:pass@host:3306/secscan` for state + findings + targets; unset = local SQLite |
| `DB_USERNAME` | MySQL/MariaDB username (or `--db-user`); overrides any user embedded in `SECSCAN_DB_URL` |
| `DB_PASSWORD` | MySQL/MariaDB password (or `--db-password`); overrides any password embedded in `SECSCAN_DB_URL` |
| `DB_SSL` | Encrypt the MySQL/MariaDB connection (or `--db-ssl`); truthy values are `"true"` and `"1"` |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | SMTP credentials for `send-report` |
| `SMTP_HOST` / `SMTP_PORT` | SMTP server for `--email-provider custom` (port defaults to 587) |
| `SMTP_FROM` | From address (defaults to `SMTP_USERNAME`) |
| `SECMAN_URL` | secman base URL (or `--secman-url`), for `push-to-secman` and `scan`/`run --push-to-secman` |
| `SECMAN_USERNAME` | secman username (or `--secman-username`); needs ADMIN or VULN role |
| `SECMAN_PASSWORD` | secman password (or `--secman-password`) |
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
uv run secscan review ./some/local/repo   # review one local dir (no GitHub)
uv run secscan review ./some/local/repo --store-db   # …and record it in the state DB
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
```

Common flags: `--include-archived --include-forks --max-size-mb --concurrency
--model --provider --max-turns --max-cost-usd --timeout --output-dir --db-url --db-user --db-password --db-ssl --no-db --store-db --create-issues --push-to-secman --secman-url --secman-username --secman-password --dry-run --issue-prefix --keep-clones
--branch --no-resume --limit --targets-only --repos-file --github-api-url --org-repos
--format --output --no-csv`.

`list-repos` prints one tab-separated line per repo: `owner/name`, size in KB, then the
latest commit on the branch GitHub reports as HEAD — short SHA and `YYYY-MM-DD` date, or
`-` `-` if the repo is empty or unreadable. Each commit found is also recorded in the
state DB (`last_commit_sha`, `last_commit_date` on the `repos` table) without disturbing
the repo's scan status; `--output-dir`, `--db-url`, `--db-user`, `--db-password` and
`--db-ssl` select the database, and `--no-db` prints without storing.

The commit lookup costs one extra API call per repo. `--no-last-commit` skips it — the
line is then just `owner/name` and size, and nothing is written to the DB.

`run` and `scan` record the same two columns for every repo they clone, read from the
clone itself (`git log -1`), so they cost no extra API calls and reflect the branch
actually reviewed.

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
duration — and `summary.csv` is rebuilt. `--db-url`, `--db-user`, `--db-password` and
`--db-ssl` (or `SECSCAN_DB_URL` / `DB_USERNAME` / `DB_PASSWORD` / `DB_SSL`) select the
database, exactly as on `run`/`scan`. Reviewing the same directory again replaces its
findings, and `stats`, `report` and `push-to-secman` then see local reviews alongside
GitHub ones. `--create-issues` remains `run`/`scan`-only — a local directory has no
GitHub repo to file against.

## Dry run

`--dry-run` (on `run`, `scan`, and `push-to-secman`) guarantees the command makes
**no external writes**:

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

Set `SECSCAN_DRY_RUN=1` (or `true`/`yes`/`on`) to force it for every command in
an environment — useful in CI or a shared shell where an accidental real write
would be expensive.

```bash
uv run secscan run --create-issues --dry-run   # full run, zero issues opened
uv run secscan push-to-secman --dry-run        # preview the secman push
SECSCAN_DRY_RUN=1 uv run secscan run --create-issues   # same, via the environment
```

The promise is enforced, not just documented: dry-run arms a process-wide guard
(`secscan/dryrun.py`), and every call that would open an issue or reach secman
checks it first, raising `DryRunViolation` rather than performing the write. In a
correct dry run the guard never fires — it's there so a future refactor that
forgets to honour the flag fails loudly instead of silently filing issues.

What `--dry-run` does **not** suppress: the security review itself still runs (and
still costs model tokens), `findings.csv` and the scan/findings state in the DB are
still written, and `--email-to` still sends the report. It scopes exactly to the
two outward-facing integrations above.

## Authentication: GitHub App vs PAT

Either credential works alone; together they complement each other.

| Configured | `run` scans | `list-repos` shows | Clone auth |
|---|---|---|---|
| App only | App-enumerated repos (+ targets the App can reach) | App-reachable repos | Installation tokens |
| PAT only | Explicit targets (`secscan repo add`) + `--repos-file` entries | Token-accessible repos | The PAT |
| Both | Union of the above | Deduped union (App entry wins) | Installation token per App repo, PAT for the rest |

PAT-only mode deliberately does **not** scan everything the token can see — a
personal token often reaches thousands of repos, and an accidental full scan is a
cost hazard. Add repos explicitly (`secscan repo add`), or pass `--repos-file`.

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

The credential itself does not change: `GITHUB_APP_ID` + private key, or `GITHUB_TOKEN`,
issued by that deployment.

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
`run` does for a single repo, but doesn't add it to the target list. `scan` requires
a PAT: a single-repo scan doesn't enumerate App installations, so an App-only
credential has no installation token to clone with.

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

Note that `--db-url`/`--db-user`/`--db-password` are unrelated to these: they
configure secscan's *own* state store. secman is only ever reached over HTTPS.

### Pushing straight from a scan

`scan` and `run` accept `--push-to-secman` and the same three credential options
(`--secman-url`, `--secman-username`, `--secman-password`, each falling back to
its `SECMAN_*` environment variable), so a review and its push are one command:

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

## Choosing a provider (`--provider`)

The reviewer is always Claude Code (via the Claude Agent SDK); `--provider` only
picks which API endpoint bills the tokens. Available on `run`, `scan`, and `review`.

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
directly. The Claude Code CLI still needs to be installed; only its
`ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN` are overridden for the review subprocess.

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
as plain `anthropic`.

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
  summary.csv                    # one row per repo: counts, status, cost, duration
  users.csv                      # org members + repo collaborators (secscan list-users)
  secscan.sqlite3                # state + findings + targets + issue tracking + users (unless --db-url)
  _clones/                       # working clones, deleted after each review unless --keep-clones
```

## Development & tests

```bash
uv run pytest            # full offline suite (no network, no credentials needed)
uv run pytest -v tests/test_emailer.py        # e.g. one module
```

Tests never hit the network: the Claude Agent SDK, PyGithub, and SMTP are replaced
with fakes. MySQL/MariaDB integration tests are skipped unless
`SECSCAN_TEST_MYSQL_URL` is set (see above).

The [dry-run](#dry-run) guard is process-wide state, so `tests/conftest.py` disarms
it (and clears `SECSCAN_DRY_RUN`) around every test — a test that arms the guard
must not leak into the next one, and a stray `SECSCAN_DRY_RUN` in your shell must
not change what the suite exercises.

## Notes & limits

- **Cost** scales with repo count/size. Use `--limit`, `--org`, `--max-cost-usd`, and the
  `sonnet` default to control spend; per-repo cost is recorded in `summary.csv`.
- Very large monorepos may exceed one autonomous pass — a known limitation.
- For stronger isolation, run reviews inside a throwaway network-less container.
