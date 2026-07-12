# DB backend hardening + GitHub issue creation for secscan

**Date:** 2026-07-12
**Status:** Approved (design)

## Goal

Two independent additions to secscan:

1. **DB backend hardening** — make DB storage of scan results optional, support
   MySQL/MariaDB credentials via CLI flag/env var (not just embedded in the URL), add
   an SSL toggle for the MySQL connection, and add a setup script + docs for
   provisioning a MySQL/MariaDB database.
2. **GitHub issue creation** — optionally open a GitHub issue per High/Critical
   finding, with a dry-run preview mode and duplicate-free re-runs via a
   first-seen/last-seen tracking table.

Both are additive: existing default behavior (SQLite state, CSV-only output, no issue
creation) is unchanged unless the new flags are used.

## Non-goals

- Closing/reopening GitHub issues when a finding disappears or reappears — a
  finding's issue, once created, is left for a human to close. Re-detection only
  bumps `last_seen_at`.
- Custom CA / client-cert MySQL SSL configuration — `--db-ssl` is a plain
  encrypt-or-not toggle, no certificate options.
- Issue creation for `review` (local-directory reviews have no `owner/repo` and no
  GitHub credentials in scope).
- Migrating existing MySQL databases that predate the new `issue_tracking` table —
  it's `CREATE TABLE IF NOT EXISTS`, so it self-provisions on first use.
- Rate-limit-aware batching of issue creation — a run with many new findings makes
  one GitHub API call per finding, relying on PyGithub's existing behavior.
- Reconstructing `summary.csv` from in-memory results when `--no-db` is set — it's
  rebuilt from `store.all_records()` today, so `--no-db` simply skips it rather than
  duplicating that bookkeeping outside the store.

## Part A — DB backend hardening

### A1. Optional DB storage (`--no-db`)

`run`, `scan`, and `review` gain `--no-db` (default: off — DB storage stays on by
default, unchanged from today). When set:

- `StateStore` is never opened; `_process_repo`/`scan_repo` skip `store.mark(...)`,
  `record_result(...)`, `replace_findings(...)`.
- Per-repo `findings.csv` is still written (it comes from `res.high_critical` in
  memory, not the store). `summary.csv`, however, is normally rebuilt from
  `store.all_records()` at the end of `run`/`scan` (`orchestrator.py:190,240`) — with
  no store to read, **`summary.csv` is skipped under `--no-db`** and a one-line notice
  is printed (`--no-db: summary.csv skipped (no state store)`). Accumulating results
  in memory instead of the DB to still produce it is deliberately out of scope (see
  Non-goals) — it would duplicate `RepoRecord` bookkeeping that already exists in the
  store, for a rarely-needed combination.
- `report`/`send-report` remain DB-only commands and don't accept `--no-db`.
- `--create-issues` (Part B) requires the DB (for the `issue_tracking` table), so
  `--no-db --create-issues` together is a `ConfigError` at startup, before any repo is
  processed.

### A2. MySQL credentials via flag/env

New `--db-user` / `--db-password` options on `run`/`scan`/`report`/`send-report`
(wherever `--db-url` already exists) and matching `DB_USERNAME` / `DB_PASSWORD` env
vars. Resolution order for each of user/password independently:

```
--db-user / --db-password  (CLI flag)
  → DB_USERNAME / DB_PASSWORD (env var)
  → credentials embedded in --db-url, if any
  → driver default ("" )
```

This keeps existing `mysql://user:pass@host:3306/db` URLs (e.g. in the integration
test docs) working unchanged, while letting new callers keep the URL credential-free
and supply secrets via env var instead (avoids secrets in shell history /
`--db-url` argv).

Implementation: `_connect_mysql` in `state.py` gains `user: str | None = None,
password: str | None = None` params; `StateStore.__init__` resolves them (CLI → env →
URL-embedded) before calling `_connect_mysql`. `cli.py` threads `db_user`/`db_password`
through `_run_config`/`RunConfig` the same way `db_url` already is.

### A3. SSL toggle (`--db-ssl`)

New `--db-ssl` boolean flag / `DB_SSL=true` env var. When set, `_connect_mysql` passes
`ssl={"ssl_mode": "REQUIRED"}`-equivalent to `MySQLdb.connect` (mysqlclient's SSL
kwarg — encrypts the connection, verifies against the system default CA trust store,
no custom CA/cert/key). Off by default (plain connection, today's behavior).

### A4. `scripts/setup-mysql.sh`

New script (no `scripts/` dir exists yet in this repo). Provisions a MySQL/MariaDB
database + user for secscan against a server the caller already has admin access to
(not a Docker bring-up — the README's existing `docker run mariadb` one-liner already
covers local ephemeral testing).

```
scripts/setup-mysql.sh --host <host> [--port 3306] --db-name secscan \
                        --app-user secscan --admin-user root [--ssl]
```

- Prompts (hidden input) for the admin password and the new app-user password;
  never accepts passwords as flags (avoids shell-history/`ps` leakage).
- Runs, via the `mysql` CLI client:
  ```sql
  CREATE DATABASE IF NOT EXISTS <db-name> CHARACTER SET utf8mb4;
  CREATE USER IF NOT EXISTS '<app-user>'@'%' IDENTIFIED BY '<generated/prompted password>';
  GRANT ALL PRIVILEGES ON <db-name>.* TO '<app-user>'@'%';
  FLUSH PRIVILEGES;
  ```
- On success, prints the env vars to export: `SECSCAN_DB_URL=mysql://<host>:<port>/<db-name>`,
  `DB_USERNAME=<app-user>`, `DB_PASSWORD=<app-user password>` (and `DB_SSL=true` if
  `--ssl` was passed) — note the URL is deliberately credential-free, matching A2.
- `set -euo pipefail`; fails fast with a clear message if the `mysql` client isn't on
  `PATH`.

New README section "MySQL setup script" (alongside the existing "MySQL / MariaDB
backend" section): prerequisites (`mysql` client installed, network access to the
target server, admin credentials), full flag reference, and a worked example showing
the script's output piped into `export`.

## Part B — GitHub issue creation

### B1. Trigger (`--create-issues`, `--dry-run`)

New flags on `run` and `scan` (not `review` — no GitHub repo context):

- `--create-issues` (default off): after a repo's review completes, process its
  `res.high_critical` findings for issue creation (below), immediately after
  `write_findings_csv`/`store.replace_findings` in `_process_repo`/`scan_repo`.
- `--dry-run` (default off, only meaningful with `--create-issues`): for each finding
  that would generate an issue, print what *would* happen (`would create` /
  `already tracked, skipping`) — **zero GitHub API calls, zero writes to
  `issue_tracking`.**

### B2. Fingerprint + dedup table

New `issue_tracking` table (both SQLite and MySQL dialects, mirroring the
`findings`/`repos` pattern in `state.py`):

```sql
CREATE TABLE IF NOT EXISTS issue_tracking (
    owner         VARCHAR(255) NOT NULL,   -- TEXT on SQLite
    repo          VARCHAR(255) NOT NULL,   -- TEXT on SQLite
    fingerprint   VARCHAR(64)  NOT NULL,   -- TEXT on SQLite; sha256 hex digest
    issue_number  INTEGER,
    issue_url     TEXT,
    first_seen_at VARCHAR(64)  NOT NULL,   -- TEXT on SQLite; ISO-8601
    last_seen_at  VARCHAR(64)  NOT NULL,   -- TEXT on SQLite; ISO-8601
    PRIMARY KEY (owner, repo, fingerprint)
);
```

`fingerprint = sha256(f"{severity}|{category}|{title}|{file_path}").hexdigest()` —
stable across reruns even if `line_range` drifts slightly (e.g. the agent reports a
line off-by-one on a re-review); deliberately excludes `line_range`/`description` so
paraphrasing by the LLM between runs doesn't spawn a duplicate issue for the same
underlying finding.

`StateStore` gains:
- `find_issue(owner, repo, fingerprint) -> IssueRecord | None`
- `record_issue_created(owner, repo, fingerprint, issue_number, issue_url, seen_at)` —
  inserts with `first_seen_at = last_seen_at = seen_at`.
- `touch_issue_seen(owner, repo, fingerprint, seen_at)` — updates `last_seen_at` only.

### B3. Per-finding flow

New `src/secscan/issues.py`, mirroring `emailer.py`'s standalone-module style:

```python
def process_finding(gh_client, store, owner, repo, finding, *, dry_run: bool) -> IssueOutcome:
    fp = fingerprint(finding)
    existing = store.find_issue(owner, repo, fp)
    if existing:
        if not dry_run:
            store.touch_issue_seen(owner, repo, fp, now)
        return IssueOutcome(action="skipped", ...)
    if dry_run:
        return IssueOutcome(action="would_create", ...)
    issue = gh_client.get_repo(f"{owner}/{repo}").create_issue(title=..., body=..., labels=["secscan"])
    store.record_issue_created(owner, repo, fp, issue.number, issue.html_url, now)
    return IssueOutcome(action="created", issue_url=issue.html_url)
```

- Issue title: `[secscan] {severity}: {title} ({file_path})`.
- Issue body: description, recommendation, category, confidence, file/line, and a
  footer noting it was opened by secscan (with the fingerprint, for debuggability).
- Label: `secscan` (created if missing — PyGithub's `create_issue(labels=[...])`
  auto-creates labels that don't exist on the repo).
- `gh_client` is a `Github(auth=Auth.Token(auth.token_for(repo_info)))` instance,
  reusing `AuthContext.token_for` — same token used for cloning, so no new credential
  plumbing.
- Orchestrator prints a per-repo summary line: `created N, skipped M (already
  tracked)` or, in dry-run, `would create N, would skip M`.

### B4. New prerequisite: Issues: Write

The GitHub App's permission set must add **Issues: Write** (currently Contents: Read,
Metadata: Read only) — existing installations need re-approval after this permission
is added to the App manifest. PAT mode already requires the `repo` scope, which
includes issue creation. Documented in README Prerequisites and as a callout in the
new "Creating GitHub issues" section.

## Data flow

```
run/scan --create-issues [--dry-run]
  → review completes → res.high_critical
  → for each finding:
       fingerprint → issue_tracking lookup
         found      → (not dry-run) touch last_seen_at            → skip
         not found  → dry-run: report "would create"              → no writes
                    → live:    gh.create_issue(...)                → record_issue_created
  → per-repo summary line (created/skipped counts)
```

`--no-db` and `--create-issues` are mutually exclusive (validated in `_run_config`/CLI
before any repo is processed).

## Testing

- **A1 (`--no-db`):** unit test that `run`/`scan` with `--no-db` never constructs a
  `StateStore` (mock/patch) and still writes `findings.csv`; `--no-db --create-issues`
  raises `ConfigError` at config-build time.
- **A2 (credentials):** unit tests on the resolution order (flag > env > URL-embedded)
  against `_connect_mysql`'s argument construction, without opening a real connection
  (same style as existing `test_providers.py` monkeypatch tests).
- **A3 (SSL):** unit test that `--db-ssl` adds the `ssl` kwarg to the `MySQLdb.connect`
  call (mock `MySQLdb.connect`); absent by default.
- **A4 (script):** shell-level smoke test (or skip if no `mysql` client / server
  available in CI, same pattern as the existing MySQL integration test gate).
- **B2/B3 (issue creation):** unit tests with a fake GitHub client (mirroring how
  `test_emailer.py` fakes SMTP) covering: new finding → issue created + row inserted;
  repeated finding → `last_seen_at` updated, no second issue; `--dry-run` → no fake-client
  calls, no DB writes; fingerprint stability when only `line_range` changes.
- **Full suite:** `uv run pytest` stays green, offline (no real GitHub/MySQL calls).

## Success criteria

1. Default `run`/`scan` behavior (no new flags) is unchanged.
2. `--no-db` skips all DB writes and `summary.csv` (with a printed notice), but still
   produces per-repo `findings.csv`; combined with `--create-issues` it fails fast
   with a clear error.
3. `--db-user`/`--db-password`/`DB_USERNAME`/`DB_PASSWORD` all work, with CLI flag
   winning over env winning over URL-embedded credentials.
4. `--db-ssl` connects over TLS; omitting it behaves exactly as today.
5. `scripts/setup-mysql.sh` provisions a working database + user and prints a
   ready-to-export config block.
6. `--create-issues` opens exactly one issue per new High/Critical finding, never a
   second issue for a finding already tracked (across repeated `run`/`scan`
   invocations), and `--dry-run` makes no GitHub API calls or DB writes.
