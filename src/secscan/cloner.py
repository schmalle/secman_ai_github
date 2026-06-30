"""Shallow-clone a repository using a short-lived installation token, then clean up.

Tokens are injected into the clone URL only for the git invocation and are never logged;
errors are redacted before they propagate.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from contextlib import asynccontextmanager
from pathlib import Path

from .github_app import RepoInfo, authed_clone_url, redact_url


class CloneError(Exception):
    """Raised when `git clone` fails (message is token-redacted)."""


def build_clone_command(url: str, dest: Path) -> list[str]:
    """Build a shallow, non-interactive clone command. `url` may contain a token."""
    return [
        "git",
        "clone",
        "--depth",
        "1",
        "--no-tags",
        "--single-branch",
        url,
        str(dest),
    ]


def _dest_dir(root: Path, repo: RepoInfo) -> Path:
    return Path(root) / f"{repo.owner}__{repo.name}"


async def clone_repo(repo: RepoInfo, token: str, dest_root: Path) -> Path:
    """Shallow-clone `repo` into `dest_root`, returning the clone directory."""
    dest = _dest_dir(dest_root, repo)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)

    url = authed_clone_url(repo.clone_url, token)
    cmd = build_clone_command(url, dest)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}

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


def cleanup(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


@asynccontextmanager
async def cloned_repo(repo: RepoInfo, token: str, dest_root: Path, keep: bool = False):
    """Clone for the duration of the context; remove afterwards unless `keep`."""
    dest = await clone_repo(repo, token, dest_root)
    try:
        yield dest
    finally:
        if not keep:
            cleanup(dest)
