"""Shallow-clone a repository using a short-lived installation token, then clean up.

The token is passed to git as an `Authorization` header via `http.extraHeader`,
set through the env-only `GIT_CONFIG_*` mechanism (git >= 2.31) rather than
embedded in the clone URL. A URL-embedded token becomes an argv element of the
`git clone` child process and is readable by anyone who can see the process
list (`ps`, `/proc/<pid>/cmdline`) for as long as the clone runs — for a PAT
that is the same credential that can live for months, not just the App
installation token's one hour. The header lives only in this subprocess's env,
never in argv, a config file, or a log line. Errors are still redacted before
they propagate, as a second line of defense.
"""

from __future__ import annotations

import asyncio
import base64
import os
import shutil
from pathlib import Path

from .github_app import RepoInfo, redact_url


class CloneError(Exception):
    """Raised when `git clone` fails (message is token-redacted)."""


def build_clone_command(url: str, dest: Path, branch: str | None = None) -> list[str]:
    """Build a shallow, non-interactive clone command. `url` may contain a token.

    Without `branch`, git clones the remote HEAD (the repo's default branch).
    """
    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--no-tags",
        "--single-branch",
    ]
    if branch:
        cmd += ["--branch", branch]
    cmd += [url, str(dest)]
    return cmd


def _dest_dir(root: Path, repo: RepoInfo) -> Path:
    return Path(root) / f"{repo.owner}__{repo.name}"


def _auth_env(token: str) -> dict[str, str]:
    """Env vars that make git send `token` as a Basic auth header, argv-free.

    `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_0`/`GIT_CONFIG_VALUE_0` set a config
    value for this process only (git >= 2.31) — nothing is written to argv, to
    any `.git/config` on disk, or to a temp file. Git only attaches
    `http.extraHeader` to http(s) requests, so it is silently ignored for the
    `file://` URLs the local-clone tests use.
    """
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.extraheader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
    }


async def clone_repo(
    repo: RepoInfo, token: str, dest_root: Path, branch: str | None = None
) -> Path:
    """Shallow-clone `repo` into `dest_root`, returning the clone directory."""
    dest = _dest_dir(dest_root, repo)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)

    cmd = build_clone_command(repo.clone_url, dest, branch)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", **_auth_env(token)}

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        msg = redact_url(stderr.decode("utf-8", "replace").strip())
        raise CloneError(f"git clone failed for {repo.full_name}: {msg}")
    return dest


async def head_commit(path: Path) -> tuple[str, str] | None:
    """(full sha, committer date as YYYY-MM-DD) of the clone's HEAD, or None.

    Read from the working tree rather than the GitHub API: it costs nothing and it
    describes the commit actually reviewed, including when --branch selected a
    non-default branch. None when `path` is not a readable git repository.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "log", "-1", "--format=%H%x09%cs",
            cwd=str(path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return None  # path missing, or git not installed
    stdout, _ = await proc.communicate()
    if proc.returncode != 0:
        return None
    sha, _, date = stdout.decode("utf-8", "replace").strip().partition("\t")
    return (sha, date) if sha and date else None


def cleanup(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


