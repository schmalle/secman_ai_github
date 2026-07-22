import shutil
import subprocess
from pathlib import Path

import pytest

from secscan.cloner import CloneError, build_clone_command, cleanup, clone_repo
from secscan.github_app import RepoInfo


def test_build_clone_command_is_shallow_and_noninteractive():
    cmd = build_clone_command("https://x-access-token:tok@github.com/o/r.git", Path("/tmp/o__r"))
    assert cmd[:2] == ["git", "clone"]
    assert "--depth" in cmd and "1" in cmd
    assert "--single-branch" in cmd
    assert cmd[-1] == "/tmp/o__r"


def test_build_clone_command_without_branch_has_no_branch_flag():
    cmd = build_clone_command("https://github.com/o/r.git", Path("/tmp/o__r"))
    assert "--branch" not in cmd


def test_build_clone_command_with_branch():
    cmd = build_clone_command("https://github.com/o/r.git", Path("/tmp/o__r"), branch="dev")
    assert "--depth" in cmd and "--single-branch" in cmd
    i = cmd.index("--branch")
    assert cmd[i + 1] == "dev"
    assert cmd[-2:] == ["https://github.com/o/r.git", "/tmp/o__r"]


def _local_repo(tmp_path: Path) -> RepoInfo:
    """git init a throwaway repo with one commit on branch 'main' and one on 'dev'."""
    src = tmp_path / "src"
    src.mkdir()
    run = lambda *args: subprocess.run(
        ["git", *args], cwd=src, check=True, capture_output=True,
        env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
             "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    run("init", "-b", "main")
    (src / "f.txt").write_text("x")
    run("add", "f.txt")
    run("commit", "-m", "init")
    run("checkout", "-b", "dev")
    (src / "g.txt").write_text("y")
    run("add", "g.txt")
    run("commit", "-m", "dev commit")
    run("checkout", "main")
    return RepoInfo(
        owner="octo", name="demo", full_name="octo/demo",
        archived=False, fork=False, size_kb=1, default_branch="main",
        clone_url=f"file://{src}", installation_id=None,
    )


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@needs_git
async def test_clone_repo_checks_out_requested_branch(tmp_path):
    repo = _local_repo(tmp_path)
    dest = await clone_repo(repo, "tok", tmp_path / "clones", branch="dev")
    assert (dest / "g.txt").exists()  # file only on dev


@needs_git
async def test_clone_repo_default_branch_when_none(tmp_path):
    repo = _local_repo(tmp_path)
    dest = await clone_repo(repo, "tok", tmp_path / "clones")
    assert (dest / "f.txt").exists()
    assert not (dest / "g.txt").exists()  # remote HEAD is main, not dev


@needs_git
async def test_clone_repo_missing_branch_raises_clone_error(tmp_path):
    repo = _local_repo(tmp_path)
    with pytest.raises(CloneError):
        await clone_repo(repo, "tok", tmp_path / "clones", branch="does-not-exist")


def test_cleanup_removes_tree(tmp_path):
    d = tmp_path / "clone"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "f.txt").write_text("x")
    cleanup(d)
    assert not d.exists()


def test_cleanup_is_safe_on_missing(tmp_path):
    cleanup(tmp_path / "does-not-exist")  # must not raise
