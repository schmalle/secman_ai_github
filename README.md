# secscan

A command-line tool that enumerates **all reachable repositories** of a GitHub App,
clones each one, runs an **autonomous Claude Code security review** over the full
codebase, and writes a **CSV of High/Critical findings per repository** plus an
aggregate `summary.csv` index.

## How it works

```
list installations → mint installation token → list repos (filter)
   → shallow clone → Claude read-only security review → validate findings JSON
   → write per-repo CSV → update state → cleanup clone   ↘ aggregate summary.csv
```

The review agent runs with **read-only tools only** (`Read`, `Grep`, `Glob`) — no
Bash, no network — so untrusted repository code is never executed. Repo contents are
treated as untrusted data (prompt-injection aware).

## Prerequisites

- Python 3.10+ (this repo pins 3.12 via `uv`).
- `git` on `PATH`.
- Node + the Claude Code CLI installed and authenticated. The Claude Agent SDK shells
  out to it. Auth via `ANTHROPIC_API_KEY` **or** a logged-in Claude subscription.
- A **GitHub App** installed on the target org(s)/repos with permissions:
  **Contents: Read**, **Metadata: Read**. You need its App ID and a private key (`.pem`).
- (Optional) MySQL: to store state and findings in MySQL instead of the local SQLite
  file, install the `mysqlclient` system libs (macOS `brew install mysql-client`;
  Debian/Ubuntu `apt-get install default-libmysqlclient-dev pkg-config`).

## Configuration

Set via environment (a `.env` you source yourself works fine):

| Variable | Purpose |
|---|---|
| `GITHUB_APP_ID` | GitHub App ID |
| `GITHUB_APP_PRIVATE_KEY` | PEM contents, or… |
| `GITHUB_APP_PRIVATE_KEY_PATH` | …path to the `.pem` file |
| `ANTHROPIC_API_KEY` | Claude auth (or use a subscription login) |
| `SECSCAN_DB_URL` | MySQL URL (`mysql://user:pass@host:3306/secscan`) for state + findings. Unset = local SQLite file. |

> **Note:** In `SECSCAN_DB_URL`, percent-encode any special characters (`@`, `:`, `/`) in the username or password (e.g. `p@ss` → `p%40ss`).

## Usage

```bash
uv sync                                   # install deps into .venv

uv run secscan list-repos                 # preview what would be scanned
uv run secscan review ./some/local/repo   # review one local dir (no GitHub)
uv run secscan run --limit 1              # full pipeline, one repo (smoke test)
uv run secscan run --org my-org           # scope to one org
uv run secscan run                        # all reachable repos
uv run secscan report                     # rebuild summary.csv from state
uv run secscan run --db-url mysql://user:pass@host:3306/secscan   # state + findings in MySQL
```

Common flags: `--include-archived --include-forks --max-size-mb --concurrency
--model --max-turns --max-cost-usd --output-dir --keep-clones --no-resume --limit`.

## Output

```
output/
  <owner>__<repo>/findings.csv   # High + Critical findings for that repo
  summary.csv                    # one row per repo: counts, status, cost, duration
  secscan.sqlite3                # resumable state manifest
```

## Notes & limits

- **Cost** scales with repo count/size. Use `--limit`, `--org`, `--max-cost-usd`, and the
  `sonnet` default to control spend; per-repo cost is recorded in `summary.csv`.
- Very large monorepos may exceed one autonomous pass — a known limitation.
- For stronger isolation, run reviews inside a throwaway network-less container.
