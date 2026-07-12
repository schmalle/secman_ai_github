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
  `OPENROUTER_API_KEY` (see [Choosing a provider](#choosing-a-provider---provider)).
- GitHub credentials — one (or both) of:
  - A **GitHub App** installed on the target org(s)/repos with permissions
    **Contents: Read**, **Metadata: Read**. You need its App ID and a private key (`.pem`).
  - A **personal access token** (`GITHUB_TOKEN`) with read access to the repos you
    want to scan (classic: `repo` scope; fine-grained: Contents + Metadata read).
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
| `ANTHROPIC_API_KEY` | Claude auth (or use a subscription login) |
| `OPENROUTER_API_KEY` | Route reviews through OpenRouter (auto-selected when set unless `--provider usecc`) |
| `SECSCAN_DB_URL` | `mysql://user:pass@host:3306/secscan` for state + findings + targets; unset = local SQLite |
| `DB_USERNAME` | MySQL/MariaDB username (or `--db-user`); overrides any user embedded in `SECSCAN_DB_URL` |
| `DB_PASSWORD` | MySQL/MariaDB password (or `--db-password`); overrides any password embedded in `SECSCAN_DB_URL` |
| `DB_SSL` | Encrypt the MySQL/MariaDB connection (or `--db-ssl`); truthy values are `"true"` and `"1"` |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | SMTP credentials for `send-report` |
| `SMTP_HOST` / `SMTP_PORT` | SMTP server for `--email-provider custom` (port defaults to 587) |
| `SMTP_FROM` | From address (defaults to `SMTP_USERNAME`) |

## Usage

```bash
uv sync                                   # install deps into .venv

uv run secscan list-repos                 # preview what would be scanned
uv run secscan repo add octo/webapp       # add an explicit scan target (stored in DB)
uv run secscan repo list                  # show explicit targets
uv run secscan repo remove octo/webapp    # remove a target
uv run secscan scan octo/webapp           # clone + review one remote repo on demand
uv run secscan review ./some/local/repo   # review one local dir (no GitHub)
uv run secscan run --limit 1              # full pipeline, one repo (smoke test)
uv run secscan run --org my-org           # scope to one org
uv run secscan run --targets-only         # only scan 'repo add' targets (skip App enumeration)
uv run secscan run                        # all reachable repos + explicit targets
uv run secscan run --db-url mysql://user:pass@host:3306/secscan   # MySQL/MariaDB state
uv run secscan report                     # rebuild summary.csv from state
uv run secscan send-report --email-to sec@example.com --email-provider gmail
```

Common flags: `--include-archived --include-forks --max-size-mb --concurrency
--model --provider --max-turns --max-cost-usd --timeout --output-dir --db-url --db-user --db-password --db-ssl --no-db --create-issues --dry-run --keep-clones
--no-resume --limit --targets-only`.

`--timeout` (default 900s) aborts a review if the agent produces no output for that
long — a stall guard (e.g. a permission prompt with no interactive terminal to answer
it), not a cap on total review duration. `--timeout 0` disables it.

`--no-db` skips all DB storage (state, findings, targets) for `run`/`scan` — only
per-repo `findings.csv` is written; `summary.csv` is skipped since it's normally
rebuilt from the state store. Useful for one-off scans where you don't want
`output/secscan.sqlite3` (or a configured MySQL backend) touched at all.

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
GitHub API calls and zero DB writes. Requires the DB (`--no-db --create-issues`
is a config error).

```bash
uv run secscan scan octo/webapp --create-issues --dry-run   # preview
uv run secscan scan octo/webapp --create-issues             # actually open issues
```

**Prerequisite:** the GitHub App's permissions need **Issues: Write** added
(alongside the existing Contents: Read, Metadata: Read) — existing installations
require re-approval after this permission is added to the App manifest. PAT mode
already covers this via the `repo` scope.

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
(explicitly-added scan targets).

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
| `auto` (default) | OpenRouter if `OPENROUTER_API_KEY` is set, else Anthropic. |
| `anthropic` | Force direct Anthropic auth (`ANTHROPIC_API_KEY` or a logged-in Claude subscription), ignoring `OPENROUTER_API_KEY` even if set. Does **not** strip an already-exported `ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN` — use `usecc` if those need clearing too. |
| `openrouter` | Force OpenRouter; fails with a config error if `OPENROUTER_API_KEY` isn't set. |
| `usecc` | Force the **locally authenticated Claude Code session**. Ignores `OPENROUTER_API_KEY` and explicitly clears any inherited `ANTHROPIC_API_KEY`/`ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN`, so a shell that still exports OpenRouter vars (or any other Anthropic auth override) can't hijack the review — Claude Code falls back to your `claude.ai` login. |

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

### Forcing your local Claude Code login (`--provider usecc`)

Use this when `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, or `ANTHROPIC_BASE_URL` is
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

## Output

```
output/
  <owner>__<repo>/findings.csv   # High + Critical findings for that repo
  summary.csv                    # one row per repo: counts, status, cost, duration
  secscan.sqlite3                # state + findings + targets (unless --db-url)
```

## Development & tests

```bash
uv run pytest            # full offline suite (no network, no credentials needed)
uv run pytest -v tests/test_emailer.py        # e.g. one module
```

Tests never hit the network: the Claude Agent SDK, PyGithub, and SMTP are replaced
with fakes. MySQL/MariaDB integration tests are skipped unless
`SECSCAN_TEST_MYSQL_URL` is set (see above).

## Notes & limits

- **Cost** scales with repo count/size. Use `--limit`, `--org`, `--max-cost-usd`, and the
  `sonnet` default to control spend; per-repo cost is recorded in `summary.csv`.
- Very large monorepos may exceed one autonomous pass — a known limitation.
- For stronger isolation, run reviews inside a throwaway network-less container.
