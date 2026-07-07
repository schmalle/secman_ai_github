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
  `OPENROUTER_API_KEY` (see [Using OpenRouter](#using-openrouter)).
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
| `OPENROUTER_API_KEY` | Route reviews through OpenRouter (auto-selected when set) |
| `SECSCAN_DB_URL` | `mysql://user:pass@host:3306/secscan` for state + findings + targets; unset = local SQLite |
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
--model --provider --max-turns --max-cost-usd --timeout --output-dir --db-url --keep-clones
--no-resume --limit --targets-only`.

`--timeout` (default 900s) aborts a review if the agent produces no output for that
long — a stall guard (e.g. a permission prompt with no interactive terminal to answer
it), not a cap on total review duration. `--timeout 0` disables it.

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

## Using OpenRouter

The reviewer is always Claude Code; OpenRouter just becomes the API endpoint that
bills the tokens (it exposes an Anthropic-compatible API). Set `OPENROUTER_API_KEY`
and it is used automatically (`--provider auto` is the default); force a choice with
`--provider anthropic` or `--provider openrouter`.

```bash
export OPENROUTER_API_KEY=sk-or-…
uv run secscan run --model anthropic/claude-sonnet-4.5
```

Note: with OpenRouter, `--model` takes an **OpenRouter slug** such as
`anthropic/claude-sonnet-4.5` — aliases like `sonnet` only work against Anthropic
directly. The Claude Code CLI still needs to be installed; only its
`ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN` are overridden for the review subprocess.

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
