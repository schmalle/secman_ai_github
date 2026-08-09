from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from secscan.config import Filters, GithubAppConfig
from secscan.github_app import (
    GithubAppClient,
    RepoInfo,
    fetch_last_commit,
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


def test_redact_url_hides_token():
    url = "https://x-access-token:ghs_secret@github.com/octo/repo.git"
    assert "ghs_secret" not in redact_url(url)
    assert "octo/repo" in redact_url(url)


def _gh_with_commit(sha="a1b2c3d4e5f6"):
    commit = SimpleNamespace(
        sha=sha,
        commit=SimpleNamespace(
            committer=SimpleNamespace(date=datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc))
        ),
    )
    return SimpleNamespace(get_repo=lambda full_name: SimpleNamespace(get_commits=lambda: [commit]))


def test_fetch_last_commit_returns_sha_and_iso_date():
    assert fetch_last_commit(_gh_with_commit(), "octo/repo") == ("a1b2c3d4e5f6", "2026-07-15")


def test_fetch_last_commit_none_on_empty_repo():
    from github import GithubException

    def _boom():
        raise GithubException(409, {"message": "Git Repository is empty."}, {})

    gh = SimpleNamespace(get_repo=lambda full_name: SimpleNamespace(get_commits=_boom))
    assert fetch_last_commit(gh, "octo/empty") is None


def test_app_client_last_commit_uses_installation_client():
    seen: list[int] = []

    def _get_github_for_installation(installation_id):
        seen.append(installation_id)
        return _gh_with_commit()

    client = GithubAppClient(GithubAppConfig(app_id="123", private_key="fake-pem"))
    client._integration = SimpleNamespace(get_github_for_installation=_get_github_for_installation)
    assert client.last_commit(_repo()) == ("a1b2c3d4e5f6", "2026-07-15")
    assert seen == [1]  # _repo() carries installation_id=1
