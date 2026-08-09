"""Shallow-clone a repository using a short-lived installation token, then clean up.

The token is passed to git via an `http.extraheader` Authorization header injected
through `GIT_CONFIG_*` environment variables (git >= 2.31) rather than embedded in the
clone URL. A URL-embedded token is a plain positional argv element, so for the
lifetime of the `git clone` subprocess it would be readable by any local user/process
via `ps` or `/proc/<pid>/cmdline`; the environment-variable form is restricted to the
process owner. The token is never logged, and clone-failure errors are redacted before
they propagate.
"""

from __future__ import annotations

import asyncio
import base64
import os
import shutil
from contextlib import asynccontextmanager
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


def _auth_header_env(token: str) -> dict[str, str]:
    """GIT_CONFIG_* env vars that set `http.extraheader` to a Basic-auth token.

    Equivalent to embedding `x-access-token:{token}@` in the clone URL, but the
    token only ever lives in the subprocess's environment, never its argv.
    """
    creds = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.extraheader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {creds}",
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
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", **_auth_header_env(token)}

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


@asynccontextmanager
async def cloned_repo(
    repo: RepoInfo, token: str, dest_root: Path, keep: bool = False,
    branch: str | None = None,
):
    """Clone for the duration of the context; remove afterwards unless `keep`."""
    dest = await clone_repo(repo, token, dest_root, branch)
    try:
        yield dest
    finally:
        if not keep:
            cleanup(dest)
