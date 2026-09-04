# GitHub App setup

How to run `secscan` against GitHub using **GitHub App credentials** — no personal
access token required. Follow the steps in order; each one has a check you can run
before moving on.

Everything below assumes you are in the repository root
(`extensions/secman_ai_github`).

---

## 0. TL;DR

```bash
# One-time: generate a private key on the App's settings page (step 2 below).
export GITHUB_APP_ID=4254305                                       # or GITHUB_APP_CLIENT_ID
export GITHUB_APP_PRIVATE_KEY_PATH=~/.secrets/secmangithubscanner.pem
unset GITHUB_TOKEN                                                 # prove the App works alone

uv sync                                                            # install dependencies
uv run secscan list-repos --no-last-commit                         # should print your repos
```

If `list-repos` prints repositories, the App credentials work. If it prints nothing,
the App is not installed anywhere yet — see [step 3](#3-install-the-app).

---

## 1. What the App needs (and what it does not)

A GitHub App authenticates **server-to-server** in three hops:

```
private key  --signs-->  App JWT (RS256, 9 min)
App JWT      --GET-->    /app/installations          (which accounts installed the App)
App JWT      --POST-->   /app/installations/{id}/access_tokens
                         ↳ installation token (1 hour) — lists and clones repos
```

So you need exactly **two** values:

| Value | Where it comes from |
|---|---|
| **App ID** *or* **Client ID** | Shown on the App's settings page under *About*. Either works — GitHub accepts both as the JWT issuer. |
| **Private key** (`.pem`) | You generate it (step 2). It is the signing key for the JWT above. |

> **The Client Secret is not usable here.** It belongs to GitHub's OAuth
> *user*-login flow: browser redirect, user consent, an expiring token scoped to a
> person. A scanner needs server-to-server access, which is only reachable by
> signing a JWT with the private key. There is no substitute, and no configuration
> that makes a client secret work.
>
> This is the same flow [secman](https://github.com/schmalle/secman) uses in
> `GithubAppClientService` (App ID + `privateKeyPem`; it stores no client secret either).

---

## 2. Generate the private key

1. Go to **Settings → Developer settings → GitHub Apps → *your app*** —
   e.g. <https://github.com/settings/apps/secmangithubscanner>.
2. Note the **App ID** and **Client ID** from the *About* block at the top.
3. Scroll down to **Private keys** → **Generate a private key**. A `.pem` file
   downloads immediately.
4. Store it somewhere private and lock it down — GitHub will never show it again:

```bash
mkdir -p ~/.secrets
mv ~/Downloads/secmangithubscanner.*.private-key.pem ~/.secrets/secmangithubscanner.pem
chmod 600 ~/.secrets/secmangithubscanner.pem
```

**Check** — the file must start with a PEM header:

```bash
head -1 ~/.secrets/secmangithubscanner.pem
# -----BEGIN RSA PRIVATE KEY-----   (or -----BEGIN PRIVATE KEY-----)
```

If you see anything else (a hex string, a `ghs_`/`github_pat_` prefix), you saved the
wrong thing.

---

## 3. Install the App

Credentials alone reach nothing: an App only sees accounts it is **installed** on.

1. On the same settings page, click **Install App** in the left sidebar.
2. Install it on your user account and/or each organization you want to scan.
3. Choose **All repositories** or select specific ones.

### Permissions

Set these under **Permissions & events**. Adding a permission to an App that is
already installed requires the installation owner to **re-approve** it — GitHub emails
them a request; until it is accepted the new permission is not active.

| Permission | Level | Needed for |
|---|---|---|
| Repository → **Contents** | Read | Cloning the repo (required) |
| Repository → **Metadata** | Read | Listing repos (required; GitHub auto-selects it) |
| Repository → **Issues** | Write | `--create-issues` only |
| Repository → **Contents** | Write | `--create-fix-prs` only (pushing the `secscan/fix-…` branch) |
| Repository → **Pull requests** | Write | `--create-fix-prs` only (opening the PR) |
| Repository → **Workflows** | Write | `--create-fix-prs` only, and only when a fix touches `.github/workflows/` |
| Organization → **Members** | Read | `secscan list-users --org` only |

---

## 4. Install secscan

| Prerequisite | Notes |
|---|---|
| Python 3.10+ | The repo pins 3.12 via `.python-version`. |
| [`uv`](https://docs.astral.sh/uv/) | `brew install uv`, or `curl -LsSf https://astral.sh/uv/install.sh \| sh`. |
| `git` on `PATH` | Used to clone each repo. |
| Node + Claude Code CLI | The Claude Agent SDK shells out to it. Only needed for `run`/`scan`/`review`, **not** for `list-repos`/`list-users`. |

```bash
cd extensions/secman_ai_github
uv sync                          # creates .venv and installs dependencies
uv run secscan --help            # verify the CLI is wired up
```

`./secscan <command>` is a thin wrapper for `uv run secscan <command>` from any
directory.

Optional — MySQL/MariaDB state backend instead of the default SQLite:

```bash
# macOS
brew install mysql-client
# Debian/Ubuntu
sudo apt-get install default-libmysqlclient-dev pkg-config

uv sync --extra mysql
```

---

## 5. Environment variables

Set these in your shell, or in a `.env` file **you source yourself** — secscan does
not read `.env` automatically, and never writes secrets to disk.

### GitHub credentials

| Variable | Required | Purpose |
|---|---|---|
| `GITHUB_APP_ID` | one of these two | Numeric App ID, e.g. `4254305`. |
| `GITHUB_APP_CLIENT_ID` | one of these two | The App's Client ID, e.g. `Iv23liV27z2aVR0QLrBp`. GitHub accepts it as the JWT issuer wherever the App ID is accepted. If **both** are set, `GITHUB_APP_ID` wins. |
| `GITHUB_APP_PRIVATE_KEY_PATH` | one of these two | Path to the `.pem`. `~` is expanded. |
| `GITHUB_APP_PRIVATE_KEY` | one of these two | The PEM **contents** inline (newlines and all). Use this for CI secrets; `..._PATH` is easier locally. |
| `GITHUB_TOKEN` | no | Optional PAT fallback, only consulted for repos no App installation covers. Leave it unset to prove the App path works on its own. |
| `GITHUB_API_URL` | no | GitHub Enterprise deployment. Unset = github.com. See [step 8](#8-github-enterprise). |

There is deliberately **no** `GITHUB_APP_CLIENT_SECRET` — see step 1.

### Review engine (needed for `run` / `scan` / `review`, not for listing)

Pick one. With the default `--provider auto` the precedence is **OpenRouter → Kimi →
Anthropic** — an `OPENROUTER_API_KEY` left over in your shell silently wins over
`ANTHROPIC_API_KEY`. Pass `--provider anthropic` (or `usecc`) to pin it.

| Variable | Purpose |
|---|---|
| `OPENROUTER_API_KEY` | Route reviews through OpenRouter. Auto-selected whenever set. |
| `MOONSHOT_API_KEY` / `KIMI_API_KEY` | Route through Kimi (Moonshot). Auto-selected when set and no OpenRouter key is present. |
| `ANTHROPIC_API_KEY` | Anthropic API key. Used when neither of the above is set. |
| *(none)* | Falls back to a logged-in Claude Code subscription — run `claude login` once. `--provider usecc` forces this and ignores every key above. |
| `COPILOT_BASE_URL` / `COPILOT_API_KEY` | Local Copilot bridge. Never auto-selected; requires `--provider copilot`. |

The table above is for the default `--engine claude`. With `--engine codescanai`
(or `SECSCAN_ENGINE=codescanai`) none of it applies — the review is done by the
[CodeScanAI](https://github.com/codescan-ai/codescan) CLI, which needs
`pip install codescanai` plus one of these instead (see the README's
[Review engines](../README.md#review-engines---engine)):

| Variable | Purpose |
|---|---|
| `OPENAI_API_KEY` | OpenAI. Auto-selected whenever set. `OPENAI_BASE_URL` redirects it to an OpenAI-compatible gateway. |
| `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) | Google Gemini. Auto-selected when set and no OpenAI key is present. |
| `CODESCANAI_HOST` / `CODESCANAI_PORT` / `CODESCANAI_ENDPOINT` / `CODESCANAI_TOKEN` | A self-hosted OpenAI-compatible server (Ollama, vLLM, …); requires `--codescanai-provider custom`. The token is env-only. |
| `CODESCANAI_PROVIDER` / `CODESCANAI_MODEL` / `CODESCANAI_BIN` / `CODESCANAI_DEFAULT_SEVERITY` | Defaults for the matching `--codescanai-*` flags. |

### Optional integrations

| Variable | Purpose |
|---|---|
| `SECSCAN_DB_URL` | `mysql://user:pass@host:3306/secscan`. Unset = SQLite at `output/secscan.sqlite3`. |
| `DB_USERNAME` / `DB_PASSWORD` / `DB_SSL` | MySQL credentials, overriding anything embedded in the URL. |
| `SECMAN_URL` / `SECMAN_USERNAME` / `SECMAN_PASSWORD` | Push findings to secman (`--push-to-secman`). |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM` | Emailed HTML report (`send-report`). |
| `SECSCAN_DRY_RUN=1` | Same as `--dry-run`: no GitHub issue is opened and nothing is pushed to secman. |

### Copy-paste block

```bash
export GITHUB_APP_ID=4254305
# export GITHUB_APP_CLIENT_ID=Iv23liV27z2aVR0QLrBp      # equivalent alternative
export GITHUB_APP_PRIVATE_KEY_PATH=~/.secrets/secmangithubscanner.pem
unset GITHUB_TOKEN
```

---

## 6. Verify, in order

Each check isolates one layer. Stop at the first that fails and use
[step 7](#7-troubleshooting).

**6.1 — Credentials parse and a JWT can be signed.** No network, no installation
needed; proves the PEM is a real key and the issuer is accepted.

```bash
uv run python -c "
from secscan.github_auth import build_auth
a = build_auth(); print('app:', a.app is not None, '| pat:', a.pat is not None)
print('jwt ok, base url:', a.app.integration.base_url)"
```

Expected: `app: True | pat: False`, then `jwt ok, base url: https://api.github.com`.

**6.2 — GitHub accepts the JWT and the App has installations.**

```bash
uv run python -c "
from secscan.github_auth import build_auth
for i in build_auth().app.integration.get_installations():
    print(i.id, i.account.login)"
```

Expected: one line per account the App is installed on. **No output means the App is
installed nowhere** — go back to step 3. A `401` means GitHub rejected the JWT (wrong
key or wrong issuer).

**6.3 — Repository enumeration.** The first real command.

```bash
uv run secscan list-repos --no-last-commit
```

Expected: a table of repositories. Empty output with installations present in 6.2
means those installations were scoped to *Only select repositories* and none were
selected, or every repo was filtered out (archived and forks are excluded by default —
try `--include-archived --include-forks --max-size-mb 0`).

**6.4 — Cloning with an installation token.** `--dry-run` blocks GitHub issues and
secman pushes; the review itself still runs and still costs model tokens.

```bash
uv run secscan scan <owner>/<repo> --dry-run --no-db --max-turns 5
```

Expected: it clones, starts a review, and writes
`output/<owner>__<repo>/findings.csv`. This is the step that proves installation
tokens work for git, not just for the API.

**6.5 — Organization member listing** (only if you granted *Members: Read*).

```bash
uv run secscan list-users --org <your-org>
```

**6.6 — A real bounded scan.**

```bash
uv run secscan run --org <your-org> --limit 2 --dry-run
uv run secscan stats
```

---

## 7. Troubleshooting

Errors are quoted as secscan prints them.

| Message | Cause | Fix |
|---|---|---|
| `GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH is required…` | An App ID is set but no key. | Generate the `.pem` (step 2). A client secret will not work. |
| `GITHUB_APP_ID or GITHUB_APP_CLIENT_ID is required…` | Neither issuer variable is set. | Export one of them. |
| `cannot read GITHUB_APP_PRIVATE_KEY_PATH: …` | Wrong path, or unreadable. | Check the path; `~` is expanded, shell variables inside the value are not. |
| `GitHub credentials required: set GITHUB_APP_ID…` | No GitHub credentials at all. | Export the App variables. |
| `Could not deserialize key data` / `Incorrect padding` | The value in `GITHUB_APP_PRIVATE_KEY` is not a PEM, or lost its newlines. | Use `GITHUB_APP_PRIVATE_KEY_PATH` instead, or ensure real newlines survive (`$(cat key.pem)` in double quotes). |
| `401 {"message": "A JSON web token could not be decoded"}` | Key does not match the App, or the issuer belongs to a different App. | Confirm the App ID/Client ID and the `.pem` come from the *same* app; regenerate the key if unsure. |
| `401 {"message": "'Expiration time' claim ('exp') is too far in the future"}` | Local clock is ahead of GitHub's. | Sync system time (NTP). |
| `list-repos` prints nothing, 6.2 shows no installations | The App is not installed. | **Install App** in the sidebar (step 3). |
| `list-repos` prints nothing, 6.2 shows installations | Installation scoped to *Only select repositories* with none selected, or everything was filtered. | Adjust the installation's repository access, or relax the filters. |
| `the GitHub App has no installation on 'X', so it cannot list its users` | `list-users --org X` where the App is not installed on `X`. | Install it on that org with **Members: Read**. |
| `no credentials can clone owner/repo — install the GitHub App on 'owner', or set GITHUB_TOKEN` | An explicit target lives on an account no installation covers. | Install the App there, or set `GITHUB_TOKEN`. |
| `403 Resource not accessible by integration` on `--create-issues` | Missing **Issues: Write**. | Add it, then have the installation owner re-approve. |
| `fix PR failed: git push failed … 403` or `… could not be opened: 403` on `--create-fix-prs` | Missing **Contents: Write** (push) or **Pull requests: Write** (PR); a push touching `.github/workflows/` also needs **Workflows: Write**. | Add the permission, re-approve the installation; the pushed branch (if any) can be turned into a PR by hand. |

---

## 8. GitHub Enterprise

Set `GITHUB_API_URL` (or pass `--github-api-url`, which wins). Both the web host and
the API host are accepted — secscan normalizes them.

| Deployment | Value |
|---|---|
| github.com / Enterprise Cloud | unset |
| Enterprise Cloud with data residency | `https://acme.ghe.com` (or `https://api.acme.ghe.com`) |
| Enterprise Server | `https://ghes.example.com` (or `https://ghes.example.com/api/v3`) |

The credential itself is unchanged — an App registered *on that deployment*, with its
own App ID/Client ID and private key.

---

## 9. Security notes

- The private key is read once and held **in memory only**. secscan never writes it,
  or any token, to disk or to a log.
- Installation tokens last ~1 hour and are minted per repository as needed.
- A clone token never reaches git's argv. It is sent as an `http.extraHeader` Basic
  auth header injected through `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_0`/`GIT_CONFIG_VALUE_0`
  in that subprocess's environment only — nothing lands in a URL, `.git/config`, a temp
  file, or the process list (`ps`, `/proc/<pid>/cmdline`). Errors are redacted before
  they propagate, as a second line of defense (`cloner.py`, `redact_url`).
- Keep the `.pem` at `chmod 600`, outside the repository. It is a credential
  equivalent to every permission you granted the App, on every account that installed
  it. If it leaks, **Generate a private key** again and delete the old one — GitHub
  supports several keys at once, so rotation needs no downtime.

---

## Related

- [`README.md`](../README.md) — full command reference, `Authentication: GitHub App vs PAT`.
- [`CLAUDE.md`](../CLAUDE.md) — the `--dry-run` invariant and secman integration.
