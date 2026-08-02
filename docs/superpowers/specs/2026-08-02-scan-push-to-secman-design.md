# Push to secman directly from `scan` and `run`

**Date:** 2026-08-02
**Status:** Approved

## Problem

`secscan scan --help` and `secscan run --help` expose only `--db-url` / `--db-user` /
`--db-password`, which configure secscan's *own* state store (SQLite or MySQL/MariaDB).
They read as secman database credentials, and the secman backend credentials a user
would expect there — the HTTPS URL, username, and password — appear on a different
command entirely (`push-to-secman`).

Pushing findings into secman therefore always takes two invocations:

```bash
secscan scan owner/repo
secscan push-to-secman
```

This design makes the push available from `scan` and `run` directly, so one command
reviews a repository and files its High/Critical findings in secman.

## Non-goals

- No change to the secman API contract. Same HTTPS `POST /api/auth/login` (JWT read from
  the `Set-Cookie: secman_auth=…` response header) and `POST /api/vulnerabilities/cli-add`
  with `Authorization: Bearer …`, unchanged request and response shapes.
- No change to which findings are eligible (High/Critical only) or to the `cve` identity
  format.
- `push-to-secman` keeps working exactly as it does today. It remains the
  "push everything currently in the state DB" backfill command.
- The `--db-*` options keep their current meaning and help text.

## Design

### 1. Shared push module

The push loop lives inline in the `push_to_secman` command body (`src/secscan/cli.py`),
so no other code path can reach it. Extract it to a new `src/secscan/secman_push.py`:

```python
def resolve_credentials(url, username, password) -> tuple[str | None, str | None, str | None]
def push_records(store, records, *, url, username, password, dry_run) -> tuple[int, int]
```

- `resolve_credentials` moves the existing `_resolve_secman_url` / `_resolve_secman_username`
  / `_resolve_secman_password` helpers out of `cli.py` unchanged: explicit value first,
  then `SECMAN_URL` / `SECMAN_USERNAME` / `SECMAN_PASSWORD`.
- `push_records` is the current loop moved verbatim: for each record, each High/Critical
  finding becomes `cve = f"SECSCAN:{truncated_category or 'FINDING'}:{fingerprint[:12]}"`,
  `hostname = owner/repo`, `criticality = severity.upper()`, and `days_open` derived from
  the tracked issue's `first_seen_at` (0 when no issue row exists). Category truncation via
  `issues._truncate` / `issues._FIELD_MAX` is preserved — it caps LLM output about untrusted
  repository content before it becomes part of a secman identifier.
- It logs in once, then pushes. Login failure raises `SecmanPushError` to the caller rather
  than exiting, so `scan`/`run` and `push-to-secman` each choose their own exit behavior.
- Returns `(pushed, failed)`. Individual `cli-add` failures are printed to stderr and
  counted; they do not abort the remaining pushes.

`push_to_secman` becomes a thin wrapper: resolve credentials, validate, open the store,
call `push_records(store, store.all_records(), …)`, print the same
`pushed N, failed M` / `would push N` summary line.

The existing `tests/test_cli_push_to_secman.py` suite is the regression guard for this
extraction and must pass unmodified.

### 2. New options on `scan` and `run`

Both commands gain:

| Option | Env fallback | Meaning |
|---|---|---|
| `--push-to-secman` | — | Opt-in. Push this invocation's High/Critical findings to secman. |
| `--secman-url` | `SECMAN_URL` | secman base URL (HTTPS). |
| `--secman-username` | `SECMAN_USERNAME` | secman account; needs the ADMIN or VULN role. |
| `--secman-password` | `SECMAN_PASSWORD` | secman password. |

`RunConfig` (`src/secscan/config.py`) gains `push_to_secman: bool = False` and
`secman_url` / `secman_username` / `secman_password` (`str | None = None`). Holding a
credential in `RunConfig` follows the existing `db_password` precedent.

Validation runs in `_run_config` / `_validate_*`, **before any cloning or review starts**,
so a misconfigured push never wastes a paid LLM review:

- `--push-to-secman` together with `--no-db` → `ConfigError`. The push reads findings and
  first-seen dates from the state store, the same reason `--create-issues` requires the DB.
- `--push-to-secman`, not a dry run, and any of URL / username / password missing →
  `ConfigError` naming all three flags and their env vars.
- An explicitly passed `--secman-url` / `--secman-username` / `--secman-password` without
  `--push-to-secman` → `ConfigError`. This prevents credentials that silently do nothing.
  Environment variables alone never error — they are frequently set process-wide.

### 3. Where the push runs

In `orchestrator.scan_repo` and `orchestrator.run`, after `write_summary_csv` and before
`_maybe_email_report`.

It pushes **only the repositories that invocation processed** — `scan` its single repo,
`run` the repos it actually reviewed this time. With `--resume`, repos skipped as already
done are not pushed. The processed set is filtered out of `store.all_records()` by
`full_name`. Pushing the entire state DB stays the job of `push-to-secman`.

Findings are pushed regardless of whether they are new: secman upserts by asset plus the
stable `cve` identifier, so a re-scan updates the existing vulnerability instead of
duplicating it.

### 4. Failure handling

- **Login failure** — message on stderr, non-zero exit. This happens after `findings.csv`,
  the state DB, and any GitHub issues are already persisted, so no review work is lost and
  `push-to-secman` can retry the push later.
- **Individual `cli-add` failure** — printed to stderr and counted; the remaining findings
  still push. The command still exits 0 and prints `pushed N, failed M`. This matches
  today's `push-to-secman` behavior.

### 5. Dry run

`--dry-run` already promises no external writes. With `--push-to-secman` it prints
`would push <owner/repo> <cve> <SEVERITY>` lines and makes zero login and zero `cli-add`
calls. `dryrun.guard(...)` already sits inside `secman_client.login` and
`secman_client.push_vulnerability`, so the invariant covers the new call site without a new
guard — but per `CLAUDE.md` the new path gets explicit coverage in `tests/test_dryrun.py`.
A dry run needs no secman credentials, consistent with `push-to-secman --dry-run`.

## Testing

Existing, unmodified:

- `tests/test_cli_push_to_secman.py` — proves the extraction preserved behavior.

New `tests/test_cli_scan_push.py`, in the established monkeypatched-`secman_client` style:

- `scan --push-to-secman` pushes only the scanned repo's High/Critical findings.
- `run --push-to-secman` pushes each repo it processed, and not resume-skipped ones.
- `--push-to-secman --no-db` is rejected.
- Missing credentials are rejected **before** the review runs (assert no clone/review call).
- Explicit `--secman-*` without `--push-to-secman` is rejected.
- `--push-to-secman --dry-run` makes zero login/`cli-add` calls and arms the dry-run guard.

Added to `tests/test_dryrun.py`: the `scan`/`run` push path raises `DryRunViolation` if it
ever reaches `secman_client` while the guard is armed.

## Documentation

`README.md`:

- Document `--push-to-secman` and the three `--secman-*` options under `scan` and `run`.
- Update the env-var table: `SECMAN_URL` / `SECMAN_USERNAME` / `SECMAN_PASSWORD` are no
  longer `push-to-secman`-only.
- Extend the "Push findings to secman" section with the one-step flow.
- Extend the "Dry run" section to name the new call site.
