"""Turn a fix workspace into a branch and a GitHub pull request (`--create-fix-prs`).

Mirrors `issues.py`: the caller resolves GitHub auth and hands over a token and an
already-authenticated PyGithub Repository; this module owns the git mechanics and
the PR text. Everything that reaches the outside world — the `git push` and the
`create_pull` call — goes through `dryrun.guard()` first, so `--dry-run` can only
ever *describe* the pull request it would open.

Dedup: a PR is keyed by `fixer.fix_key` (the set of finding fingerprints it
addresses) in the state DB's `fix_prs` table. Re-scanning a repo whose High/Critical
findings have not changed skips the PR (and the fix run's cost is already sunk by
then, which is why the orchestrator checks the ledger *before* running the fixer).

The push authenticates the same way the clone does — an `Authorization` header via
the env-only `GIT_CONFIG_*` mechanism — so the token is never on argv. It needs
**Contents: Write** (App) or the `repo` scope (PAT); opening the PR needs **Pull
requests: Write**. A change under `.github/workflows/` additionally needs the
`workflow` scope / **Workflows: Write**, or GitHub rejects the push — that surfaces
as the outcome's `reason`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import dryrun
from .cloner import _auth_env
from .config import GithubHost
from .findings import Finding, fingerprint
from .fixer import FixError, FixResult, _git_env, git
from .github_app import RepoInfo, redact_url
from .state import StateStore

DEFAULT_PR_PREFIX = "secscan:"
BRANCH_PREFIX = "secscan/fix-"

# Same caps as issues.py: finding text is LLM output about untrusted content.
_TITLE_MAX = 120
_FIELD_MAX = 120
_BODY_FIELD_MAX = 400
_MAX_LISTED = 20


def _truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class FixPrOutcome:
    action: str  # "created" | "would_create" | "skipped" | "no_changes" | "failed"
    pr_url: str = ""
    branch: str = ""
    reason: str = ""


def branch_name(fix_key: str) -> str:
    return f"{BRANCH_PREFIX}{fix_key[:12]}"


def pr_title(findings: list[Finding], prefix: str) -> str:
    n_crit = sum(1 for f in findings if f.severity.value == "critical")
    n_high = len(findings) - n_crit
    parts = []
    if n_crit:
        parts.append(f"{n_crit} critical")
    if n_high:
        parts.append(f"{n_high} high")
    what = " and ".join(parts) or "security"
    if len(findings) == 1:
        base = f"fix {findings[0].severity.value}: {_truncate(findings[0].title, _TITLE_MAX)}"
    else:
        base = f"fix {what} security findings"
    return f"{prefix} {base}" if prefix else base


def pr_body(findings: list[Finding], result: FixResult, fix_key: str) -> str:
    lines = [
        "Automated remediation proposed by [secscan](https://github.com/schmalle/secman_ai_github) "
        "for the High/Critical findings of its last review.",
        "",
        "**The fix agent could not run this project's build or tests** — it edits with "
        "read/write file tools only and no shell — so treat this as a starting point: "
        "review every hunk, run the test-suite, and check the behaviour of the changed "
        "code paths before merging.",
        "",
        "## Findings addressed",
        "",
    ]
    by_title = {
        str(f.get("title", "")): f for f in result.summary.get("fixes", []) if isinstance(f, dict)
    }
    for f in findings[:_MAX_LISTED]:
        note = by_title.get(f.title, {})
        status = str(note.get("status", "")) or "see diff"
        summary = _truncate(str(note.get("summary", "")), _BODY_FIELD_MAX)
        lines.append(
            f"- **{f.severity.value}** — {_truncate(f.title, _TITLE_MAX)} "
            f"(`{_truncate(f.file_path, _FIELD_MAX)}`"
            + (f", {_truncate(f.line_range, _FIELD_MAX)}" if f.line_range else "")
            + f") — _{status}_" + (f": {summary}" if summary else "")
        )
    if len(findings) > _MAX_LISTED:
        lines.append(f"- … and {len(findings) - _MAX_LISTED} more (see `fixes.json` in the scan output)")
    if result.changed_files:
        lines += ["", "## Files changed", ""]
        lines += [f"- `{_truncate(p, _FIELD_MAX)}`" for p in result.changed_files[:_MAX_LISTED]]
    lines += [
        "",
        "---",
        f"_Opened automatically by secscan. Fix key: `{fix_key}`. Finding fingerprints: "
        + ", ".join(f"`{fingerprint(f)[:12]}`" for f in findings[:_MAX_LISTED])
        + "._",
    ]
    return "\n".join(lines)


# --- remote detection for `review <local-dir>` ---------------------------------------

_SSH_RE = re.compile(r"^(?:ssh://)?(?:[\w.-]+@)?(?P<host>[\w.-]+)[:/](?P<path>.+?)(?:\.git)?/?$")


def parse_github_remote(url: str, host: GithubHost) -> tuple[str, str] | None:
    """(owner, name) if `url` points at a repo on `host`, else None.

    Accepts https://host/owner/name(.git), git@host:owner/name.git and
    ssh://git@host/owner/name.
    """
    url = url.strip()
    if not url:
        return None
    web_host = urlsplit(host.web_url).netloc.lower()
    if "://" in url:
        parts = urlsplit(url)
        remote_host, path = parts.netloc.lower(), parts.path
        if "@" in remote_host:
            remote_host = remote_host.rsplit("@", 1)[1]
    else:
        m = _SSH_RE.match(url)
        if not m:
            return None
        remote_host, path = m.group("host").lower(), m.group("path")
    if remote_host != web_host:
        return None
    segments = [s for s in path.strip("/").split("/") if s]
    if len(segments) != 2:
        return None
    owner, name = segments
    if name.endswith(".git"):
        name = name[: -len(".git")]
    return (owner, name) if owner and name else None


async def origin_url(path: Path) -> str:
    return (await git("remote", "get-url", "origin", cwd=path, check=False)).strip()


# --- the outward-facing part ------------------------------------------------------


async def push_fix_branch(workspace: Path, remote_url: str, branch: str, token: str, message: str) -> None:
    """Commit the staged fix on a new branch and push it, token in env only."""
    dryrun.guard(f"push branch {branch} to {redact_url(remote_url)}")
    await git("checkout", "--quiet", "-b", branch, cwd=workspace)
    await git("commit", "--quiet", "-m", message, cwd=workspace)
    env = {**_git_env(), **_auth_env(token)}
    try:
        await git("push", "--quiet", remote_url, f"HEAD:refs/heads/{branch}", cwd=workspace, env=env)
    except FixError as exc:
        raise FixError(redact_url(str(exc))) from None


def open_pull_request(gh_repo, *, title: str, body: str, head: str, base: str, draft: bool):
    """Blocking PyGithub call; the caller runs it on a worker thread."""
    dryrun.guard(f"open a pull request from {head} into {base}")
    return gh_repo.create_pull(title=title, body=body, head=head, base=base, draft=draft)


def commit_message(findings: list[Finding], prefix: str) -> str:
    title = pr_title(findings, prefix)
    body = "\n".join(
        f"- {f.severity.value}: {_truncate(f.title, _TITLE_MAX)} ({_truncate(f.file_path, _FIELD_MAX)})"
        for f in findings[:_MAX_LISTED]
    )
    return f"{title}\n\n{body}\n"


async def create_fix_pr(
    *,
    workspace: Path,
    repo: RepoInfo,
    base_branch: str,
    token: str,
    store: StateStore,
    result: FixResult,
    dry_run: bool,
    prefix: str = DEFAULT_PR_PREFIX,
    draft: bool = False,
    gh_repo_factory=None,
) -> FixPrOutcome:
    """Push the fix on a new branch and open a PR against `base_branch`.

    `gh_repo_factory()` returns the PyGithub Repository to open the PR on; it is only
    called outside dry-run, so a dry run makes zero GitHub API calls. The ledger is
    consulted first, so a repeated fix set is skipped before anything is pushed.
    """
    findings = result.findings
    key = result.fix_key
    owner, name = repo.owner, repo.name

    existing = store.find_fix_pr(owner, name, key)
    if existing:
        return FixPrOutcome("skipped", pr_url=existing.pr_url, branch=existing.branch,
                            reason="a pull request for these findings already exists")
    if not result.patch.strip():
        return FixPrOutcome("no_changes", reason="the fix agent changed no files")
    if not base_branch:
        return FixPrOutcome("failed", reason="could not determine the base branch")

    branch = branch_name(key)
    if dry_run:
        return FixPrOutcome("would_create", branch=branch)

    title = pr_title(findings, prefix)
    try:
        await push_fix_branch(
            workspace, repo.clone_url, branch, token, commit_message(findings, prefix)
        )
    except FixError as exc:
        return FixPrOutcome("failed", branch=branch, reason=str(exc))

    try:
        gh_repo = gh_repo_factory()
        pr = open_pull_request(
            gh_repo, title=title, body=pr_body(findings, result, key),
            head=branch, base=base_branch, draft=draft,
        )
    except dryrun.DryRunViolation:
        raise
    except Exception as exc:  # GithubException and friends
        return FixPrOutcome(
            "failed", branch=branch,
            reason=f"branch pushed but the pull request could not be opened: {redact_url(str(exc))}",
        )

    store.record_fix_pr(
        owner, name, key, pr.number, pr.html_url, branch,
        datetime.now(timezone.utc).isoformat(),
    )
    return FixPrOutcome("created", pr_url=pr.html_url, branch=branch)
