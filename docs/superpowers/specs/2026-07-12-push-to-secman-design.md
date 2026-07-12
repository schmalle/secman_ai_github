# Push findings to secman (`secscan push-to-secman`)

**Date:** 2026-07-12
**Status:** Approved (design)

## Goal

Let secscan push its High/Critical findings into [secman](https://github.com/schmalle/secman),
a separate security requirement/vulnerability management platform, via its existing
`POST /api/vulnerabilities/cli-add` endpoint (ADMIN/VULN role, auto-creates the
target asset). One new standalone command, `secscan push-to-secman`, reads findings
already persisted in secscan's own state DB (same pattern as `report`/`send-report`)
and pushes each High/Critical one.

## Non-goals

- Pushing MEDIUM/LOW/INFO findings, or all findings unconditionally — High/Critical
  only, matching the CSV/email/issue-creation filter used elsewhere in secscan.
- Rich finding detail on the secman side. `cli-add`'s `AddVulnerabilityRequestDto`
  is `hostname, cve, criticality, daysOpen, owner` — the underlying `Vulnerability`
  domain entity has no free-text field at all (confirmed by reading
  `VulnerabilityService.addVulnerabilityFromCli` and the entity definition in the
  `secman` repo). secman will only ever show a compact synthetic identifier +
  severity + asset name for a pushed finding — full detail stays in secscan's own
  `findings.csv`/state DB (and the linked GitHub issue, if `--create-issues` was
  used). **Accepted as-is for now** (confirmed with the user).
- A new secman-side API or schema change to carry richer finding data — out of
  scope for this repo; if this limitation becomes a problem later, per the new
  `CLAUDE.md` rule, the `secman` repository itself needs to be checked/changed.
- TLS-verification bypass (`--insecure`, mirrored from secman's own CLI) —
  omitted; can be added later if a self-signed-cert deployment needs it.
- De-duplication bookkeeping on the secscan side — `cli-add` already upserts by
  `(asset, cve)` on the secman side (confirmed in `VulnerabilityService`: existing
  vulnerability with the same `vulnerabilityId` on the same asset is *updated*, not
  duplicated), so re-running `push-to-secman` after a later scan is naturally
  idempotent without a new tracking table.
- Retrying across secman being down for an extended period, queuing, or any offline
  buffering — a failed push is reported and the run continues to the next finding;
  the operator re-runs `push-to-secman` later (it's a DB read, not a one-shot
  consumption — nothing is marked "pushed" and skipped next time, matching the
  no-dedup-table decision above).

## Approach

New `src/secscan/secman_client.py`, mirroring `emailer.py`'s standalone-module
style (a thin client, no framework):

```python
def login(base_url, username, password) -> str:
    """POST /api/auth/login, extract the JWT from Set-Cookie: secman_auth=...
    Mirrors secman's own CLI (CliHttpClient.authenticate in the secman repo) —
    LoginResponse carries no token in the JSON body; the JWT only appears in the
    Set-Cookie header."""

def push_vulnerability(base_url, token, *, hostname, cve, criticality, days_open) -> dict:
    """POST /api/vulnerabilities/cli-add with Authorization: Bearer {token}."""
```

Uses `requests` (new dependency — secscan currently has no raw HTTP client;
PyGithub/smtplib/MySQLdb cover everything else). Both calls wrapped in the same
`tenacity` retry pattern already used for clone operations in `orchestrator.py`
(`stop_after_attempt`/`wait_exponential`), retrying on connection errors only (not
on 4xx auth/validation failures, which are terminal).

The fingerprint function used to identify a finding (`sha256(severity|category|
title|file_path)`, introduced for GitHub issue dedup in the companion
[DB hardening + issue creation spec](2026-07-12-db-hardening-and-issue-creation-design.md))
moves to a shared location — a new `fingerprint(finding: Finding) -> str` in
`findings.py` — so both `issues.py` (Part B of that spec) and `secman_client.py`
import the same implementation instead of duplicating the hash logic.

## Components

### 1. `cli.py` — `push-to-secman` command

```
secscan push-to-secman
  --secman-url TEXT       [or SECMAN_URL]       (required)
  --secman-username TEXT  [or SECMAN_USERNAME]  (required)
  --secman-password TEXT  [or SECMAN_PASSWORD]  (required)
  --dry-run                                     (default: off)
  --output-dir PATH                             (state DB location; same default as other commands)
  --db-url / --db-user / --db-password / --db-ssl   (same resolution as elsewhere; see DB hardening spec)
```

Resolution order for each secman credential: CLI flag → env var → `ConfigError` if
neither is set (no third fallback — unlike `--db-url`, there's no embeddable-URL
form here since secman auth is username/password, not a connection string).

### 2. Flow

```python
def push_to_secman(cfg: RunConfig, secman_cfg: SecmanConfig) -> None:
    store = _open_store(cfg.output_dir, cfg.db_url)  # same helper as report/send-report
    records = store.all_records()

    if not secman_cfg.dry_run:
        token = secman_client.login(secman_cfg.url, secman_cfg.username, secman_cfg.password)

    pushed = failed = 0
    for rec in records:
        for row in store.get_findings(rec.owner, rec.repo):
            if row["severity"] not in ("critical", "high"):
                continue
            fp = fingerprint_from_row(row)
            issue = store.find_issue(rec.owner, rec.repo, fp)  # optional enrichment, may be None
            days_open = (now - issue.first_seen_at).days if issue else 0
            cve = f"SECSCAN:{row['category'] or 'FINDING'}:{fp[:12]}"
            hostname = rec.full_name  # "owner/repo"

            if secman_cfg.dry_run:
                typer.echo(f"would push {hostname} {cve} {row['severity'].upper()}")
                pushed += 1  # counts "would push" in dry-run; see summary line below
                continue

            try:
                secman_client.push_vulnerability(
                    secman_cfg.url, token,
                    hostname=hostname, cve=cve,
                    criticality=row["severity"].upper(), days_open=days_open,
                )
                pushed += 1
            except SecmanPushError as exc:
                typer.echo(f"failed: {hostname} {cve}: {exc}", err=True)
                failed += 1

    verb = "would push" if secman_cfg.dry_run else "pushed"
    typer.echo(f"{verb} {pushed}" + ("" if secman_cfg.dry_run else f", failed {failed}"))
```

`--dry-run` makes **zero** network calls — no login, no `cli-add` — consistent with
the dry-run semantics already established for `--create-issues`.

### 3. Error handling

- Login failure (bad credentials, unreachable host, wrong role) aborts the whole
  command immediately with a clear message (mirrors `CliHttpClient.authenticate`'s
  error messages in the secman repo — distinguish connection-refused / DNS failure /
  401 invalid credentials / 403 wrong role).
- A single finding's `cli-add` failure (e.g. 400 validation error) is logged and
  counted, not fatal — the run continues to the next finding so one bad row doesn't
  block the whole push.

## Data flow

```
push-to-secman [--dry-run]
  → open state store (same as report/send-report)
  → (unless --dry-run) login → JWT
  → for each repo record → for each High/Critical finding:
       fingerprint → cve = "SECSCAN:{category}:{fp[:12]}"
       hostname = owner/repo
       days_open = from issue_tracking if present, else 0
       --dry-run: print "would push"
       live: POST /api/vulnerabilities/cli-add (Bearer JWT) → upsert on secman side
  → summary line: pushed N, failed M (or "would push N" in dry-run)
```

## Testing

- Unit tests for `secman_client.login`/`push_vulnerability` against a fake HTTP
  server or mocked `requests` responses (mirroring how `test_emailer.py` fakes
  SMTP) — cover: successful login extracts token from `Set-Cookie`; 401 raises a
  clear error; `cli-add` 200 response parsed; `cli-add` 400 raises without killing
  the whole run.
- Unit test for the shared `fingerprint()` function (moved from the issue-creation
  spec) — stability across `line_range` changes, uniqueness across different
  severity/category/title/file_path.
- CLI-level test: `push-to-secman --dry-run` makes no HTTP calls at all (mock
  `requests`/`secman_client` and assert zero invocations).
- Full suite stays offline — no real secman server contacted in tests.

## Success criteria

1. `push-to-secman` logs in once, pushes every High/Critical finding currently in
   the state DB across all repos, and reports a pushed/failed summary.
2. `--dry-run` makes no login call and no `cli-add` call.
3. Re-running `push-to-secman` after a later scan updates (not duplicates) the
   secman-side vulnerability, relying on secman's own upsert-by-`(asset, cve)`
   behavior.
4. Credentials resolve correctly via CLI flag or env var, flag winning when both
   are set.
5. A single failed push doesn't abort the run; the command still processes and
   reports the remaining findings.
