from types import SimpleNamespace

import pytest

from secscan.config import Filters
from secscan.github_app import (
    RepoInfo,
    authed_clone_url,
    redact_url,
    should_include,
)


def _repo(owner="octo", name="repo", archived=False, fork=False, size_kb=1000):
    return RepoInfo(
        owner=owner,
        name=name,
        full_name=f"{owner}/{name}",
        archived=archived,
        fork=fork,
        size_kb=size_kb,
        default_branch="main",
        clone_url=f"https://github.com/{owner}/{name}.git",
        installation_id=1,
    )


def test_repo_info_from_github_object():
    gh_repo = SimpleNamespace(
        owner=SimpleNamespace(login="octo"),
        name="repo",
        full_name="octo/repo",
        archived=False,
        fork=True,
        size=2048,
        default_branch="develop",
        clone_url="https://github.com/octo/repo.git",
    )
    info = RepoInfo.from_github_repo(gh_repo, installation_id=42)
    assert info.full_name == "octo/repo"
    assert info.fork is True
    assert info.size_kb == 2048
    assert info.installation_id == 42


def test_filters_skip_archived_and_forks_by_default():
    f = Filters()
    assert should_include(_repo(archived=True), f, org=None) is False
    assert should_include(_repo(fork=True), f, org=None) is False
    assert should_include(_repo(), f, org=None) is True


def test_filters_can_include_archived_and_forks():
    f = Filters(include_archived=True, include_forks=True)
    assert should_include(_repo(archived=True), f, org=None) is True
    assert should_include(_repo(fork=True), f, org=None) is True


def test_size_cap_excludes_large_repos():
    f = Filters(max_size_mb=1)  # 1 MB == 1024 KB
    assert should_include(_repo(size_kb=2048), f, org=None) is False
    assert should_include(_repo(size_kb=512), f, org=None) is True


def test_size_cap_disabled_when_zero():
    f = Filters(max_size_mb=0)
    assert should_include(_repo(size_kb=10_000_000), f, org=None) is True


def test_org_filter():
    f = Filters()
    assert should_include(_repo(owner="octo"), f, org="other") is False
    assert should_include(_repo(owner="octo"), f, org="octo") is True


def test_authed_clone_url_injects_token():
    url = authed_clone_url("https://github.com/octo/repo.git", "ghs_secret")
    assert url == "https://x-access-token:ghs_secret@github.com/octo/repo.git"


def test_redact_url_hides_token():
    url = "https://x-access-token:ghs_secret@github.com/octo/repo.git"
    assert "ghs_secret" not in redact_url(url)
    assert "octo/repo" in redact_url(url)
