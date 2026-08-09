# GitHub Enterprise support and username extraction from orgs and repos

Date: 2026-08-09

## Problem

`secscan` can only talk to one GitHub. Every PyGithub client is constructed without a
`base_url` (`github_auth.py`, `github_app.py`, `orchestrator.py`), and `resolve_target`
hardcodes `https://github.com/{owner}/{name}.git`. An organization on GitHub Enterprise
Server, or on Enterprise Cloud with data residency, is simply unreachable.

It also has no concept of a GitHub *user*. The only user-facing API call in the codebase
is `gh.get_user().get_repos()`, used to enumerate repositories. Knowing **who** can reach
a repository is a first-class security question — an org with a long tail of admins, or a
repo with write-level collaborators nobody remembers adding, is an exposure the code
review will never surface.

## Goals

1. Every command works against all three commercial deployments: Enterprise Cloud on
   github.com, Enterprise Cloud with data residency (`*.ghe.com`), and Enterprise Server.
2. `secscan list-users` lists an organization's members with their role, and its
   repositories' collaborators with their permission level.
3. Those usernames land in stdout, a CSV, and the state DB, so they can be diffed and
   queried like findings.
4. The org-only nature of these APIs is an explanatory error, not a traceback.

## Non-goals

- Outside collaborators, teams and team membership, and the 2FA-disabled member filter.
  All are org-only APIs too and would slot into the same command later.
- SAML/SCIM external identities (Enterprise Cloud) and LDAP DNs (Enterprise Server).
  Neither is exposed by the REST endpoints used here; surfacing them means GraphQL or
  SCIM and a different credential.
- Changing what `--dry-run` covers. Listing users is read-only, so no `dryrun.guard(...)`
  call is added — the guard is for outward-facing *writes*, per `CLAUDE.md`.
- Enterprise-account-level APIs (`/enterprises/{enterprise}/...`).

## Design

### 1. Host resolution

`config.normalize_github_urls(value) -> (api_url, web_url)` is a pure function, so the
riskiest logic in the change is unit-testable with no network. The three deployments
address their API differently:

| Input | api_url | web_url |
| --- | --- | --- |
| *(unset)*, `https://github.com`, `https://api.github.com` | `https://api.github.com` | `https://github.com` |
| `https://acme.ghe.com`, `https://api.acme.ghe.com` | `https://api.acme.ghe.com` | `https://acme.ghe.com` |
| `https://ghes.example.com`, `…/api/v3` | `https://ghes.example.com/api/v3` | `https://ghes.example.com` |

Enterprise Cloud (both tenancies) puts the API on an `api.` **subdomain**; Enterprise
Server puts it on an `/api/v3` **path**. The rule keys off the host: a URL already ending
in `/api/v3` is taken as-is; a host that is `github.com` or ends in `.ghe.com` gets the
subdomain form; anything else gets `/api/v3` appended. A missing scheme, a non-http(s)
scheme, or any other path raises `ConfigError` listing the accepted forms — a wrong host
must fail at the CLI edge, not as a 404 halfway through a run.

Both URLs are needed: the API host for PyGithub, the web host for the clone-URL fallback
in `resolve_target`, since Enterprise Server serves git from its own hostname.

`GithubHost(api_url, web_url)` is a frozen dataclass defaulting to public GitHub, with
`GithubHost.resolve(api_url=None)` applying the precedence *argument → `GITHUB_API_URL`
→ default*. It hangs off `GithubAppConfig`, `GithubPatConfig` and `AuthContext`.

### 2. Threading it through

`build_auth()` becomes `build_auth(api_url=None)` and stamps the resolved host onto both
clients and the context. Three existing call sites (`run_scan`, `scan_repo`,
`list-repos`) pass it; `RunConfig` carries `github_api_url` for the orchestrator.

`_create_issues_sync` gains an `api_url` parameter — issue creation mints its own
`Github()` and would otherwise silently keep talking to github.com. `authed_clone_url`
needs no change: it rewrites whatever `clone_url` the API returned, which on Enterprise
is already the right host.

`--github-api-url` is added to `run`, `scan`, `list-repos` and `list-users`, sharing one
`_GITHUB_API_URL_HELP` constant.

### 3. Username extraction

`github_users.py` follows the `issues.py` convention: functions take an
already-authenticated PyGithub client, never credentials, so they carry no auth knowledge
and are trivial to fake.

- `iter_org_members(gh, org)` — reads `get_members(role="admin")` into a set, then walks
  `get_members()`, tagging each `admin` or `member`. Two paginated listings, not one
  request per user.
- `iter_repo_collaborators(gh, full_name)` — `get_collaborators(affiliation="all")`, role
  from `role_name`, falling back to the most privileged true flag in `permissions`
  (`admin > maintain > push > triage > pull`) because older Enterprise Server releases
  omit `role_name`.
- `GithubUser` is the record. `None` name/email/type collapse to `""` so the string
  `"None"` never reaches a CSV cell.
- `OrgAccessError` wraps `GithubException` with a message that names the scope, states
  the endpoints exist only for organizations, and lists the permission needed.

Both clients gain `iter_org_members` / `iter_repo_collaborators`, keeping their
interfaces symmetric as `list-repos` already assumes. The App client cannot use its JWT
for these calls, so `github_for_account(login)` finds the installation whose
`account.login` matches and returns an installation-scoped client, raising
`OrgAccessError` when the App is not installed there.

### 4. `secscan list-users`

`--org` (members), `--repo` (repeatable, collaborators), `--org-repos` (with `--org`,
walk every repo in the org). At least one of `--org`/`--repo` is required; `--org-repos`
without `--org` is a `BadParameter`.

Scopes are collected in order and deduped on `(org, repo, login)`. Per scope the App is
tried first and the PAT is the fallback, so an org the App is not installed on is still
listed when the token can see it; only if every credential fails is the first
`OrgAccessError` raised, printed to stderr, exit 1.

`--format table|csv|json` and `--output` mirror `stats`. `<output-dir>/users.csv` is
written unless `--no-csv`, independent of `--format`.

### 5. Schema: a fifth table

```sql
CREATE TABLE IF NOT EXISTS github_users (
    org, repo, login,          -- PRIMARY KEY; repo = '' for an org-members row
    source, role, user_id, name, email, user_type, site_admin, html_url, seen_at
);
```

Registered in both dialects' `schema` tuples. No `_MIGRATIONS_*` entry is needed —
that mechanism exists for columns added to a table that already shipped, and
`CREATE TABLE IF NOT EXISTS` covers a brand-new table on an existing database.

On MySQL the three key columns are `VARCHAR(255)`: 3060 bytes under utf8mb4, inside
InnoDB's 3072-byte index limit, which is why they are not wider.

`replace_users(org, repo, users, seen_at)` deletes the scope then inserts, matching
`replace_findings` — an upsert would leave a departed member in the table forever.
`get_users(org=None, repo=None)` reads it back.

`stats reset` is deliberately untouched: it is scoped to scan history and findings, and
already keeps targets and issue tracking. Usernames are neither.

### 6. CSV

`USER_FIELDS`, `write_users_csv` and `render_users_csv` live in `findings.py` — the
project's only CSV module, and the owner of `_csv_cell`, the formula-injection guard. A
GitHub display name is free text its owner chooses, so it is exactly as
attacker-controlled as a finding title and must route through the same guard; both the
file and the stdout rendering share one writer so neither can drift. The rendered string
uses `\n` rather than the csv module's `\r\n`, since it is echoed to a terminal.

## Testing

- `normalize_github_urls` across all three deployments, both URL shapes each, trailing
  slashes, and four rejected inputs.
- `GithubPatClient(...).gh.requester.base_url` and `GithubAppClient(...).integration.base_url`
  for Enterprise Cloud, data residency and Enterprise Server. PyGithub's constructors make
  no request, so these are real assertions with no network.
- `build_auth` precedence (argument beats `GITHUB_API_URL` beats default) and the host
  landing on both clients and the context; `resolve_target`'s fallback using the web host.
- `iter_org_members` admin/member tagging (case-insensitive), `collaborator_role`
  preferring `role_name` then the permission flags, null collapsing, and a real
  `github.GithubException` becoming an `OrgAccessError` whose message says "only for
  organizations".
- `github_for_account` picking the matching installation and raising when there is none.
- `write_users_csv` column order, dict input, and formula-injection neutralization;
  `render_users_csv` agreeing with the file.
- `replace_users` round-trip, dropping departed members, leaving other scopes alone;
  `get_users` filtering; the table appearing on a pre-existing database.
- `list-users` end to end: validation errors, table/csv/json output, `users.csv` written
  and suppressed, `--no-db`, `OrgAccessError` exiting 1, PAT fallback after App failure,
  App entries winning over PAT duplicates, `--org-repos` walking the org without
  re-listing an explicit `--repo`.
- `--github-api-url` reaching `build_auth` from `list-repos`/`list-users` and `RunConfig`
  from `run`/`scan`, and a malformed URL exiting 1 with a message.

No `tests/test_dryrun.py` change: the feature adds no external write.

## Documentation

`README.md` gains a `GITHUB_API_URL` row in the Configuration table, the extra credential
scope in Prerequisites, `list-users` usage lines, the new flags in "Common flags",
`users.csv` in the Output tree, and two sections: **GitHub Enterprise (Cloud and Server)**
with the normalization table, and **Listing organization users** with the org-only
limitation, the permission prerequisites, the output destinations, and the SAML/SCIM/LDAP
known limitation. `cli.py`'s module docstring lists the new command and flag.
