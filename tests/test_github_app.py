from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from secscan.config import Filters, GithubAppConfig
from secscan.github_app import (
    GithubAppClient,
    RepoInfo,
    authed_clone_url,
    fetch_last_commit,
    redact_url,
    should_include,
)
from secscan.github_users import OrgAccessError


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


# -- GitHub deployment (Enterprise Cloud / Enterprise Server) ----------------------


@pytest.mark.parametrize(
    "api_url,expected_base",
    [
        (None, "https://api.github.com"),                              # Enterprise Cloud
        ("https://acme.ghe.com", "https://api.acme.ghe.com"),          # GHEC data residency
        ("https://ghes.example.com", "https://ghes.example.com/api/v3"),  # Enterprise Server
    ],
)
def test_app_client_points_pygithub_at_the_configured_deployment(api_url, expected_base):
    from secscan.config import GithubHost

    # A real RSA key is needed because GithubIntegration signs a JWT on construction.
    private_key = _rsa_private_key()
    client = GithubAppClient(
        GithubAppConfig(app_id="123", private_key=private_key, host=GithubHost.resolve(api_url))
    )
    assert client.integration.base_url == expected_base


def _rsa_private_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


# -- user listings ----------------------------------------------------------------


def _app_client_with_installations(installations, github_by_id=None):
    client = GithubAppClient(GithubAppConfig(app_id="123", private_key="fake-pem"))
    client._integration = SimpleNamespace(
        get_installations=lambda: installations,
        get_github_for_installation=lambda i: (github_by_id or {}).get(i),
    )
    return client


def _installation(login, installation_id=7):
    return SimpleNamespace(id=installation_id, account=SimpleNamespace(login=login))


def test_github_for_account_picks_the_matching_installation():
    marker = SimpleNamespace(name="installation-scoped client")
    client = _app_client_with_installations(
        [_installation("other", 1), _installation("Acme", 7)], {7: marker}
    )
    assert client.github_for_account("acme") is marker


def test_github_for_account_raises_when_the_app_is_not_installed():
    client = _app_client_with_installations([_installation("other", 1)])
    with pytest.raises(OrgAccessError, match="no installation on 'acme'"):
        client.github_for_account("acme")


def test_app_client_iter_org_members_uses_the_installation_client():
    members = [
        SimpleNamespace(login="alice", id=1, name=None, email=None, type="User",
                        site_admin=False, html_url="")
    ]
    installation_gh = SimpleNamespace(
        get_organization=lambda org: SimpleNamespace(
            get_members=lambda role=None: (members if role != "admin" else members)
        )
    )
    client = _app_client_with_installations([_installation("acme")], {7: installation_gh})
    assert [(u.login, u.role) for u in client.iter_org_members("acme")] == [("alice", "admin")]


def test_app_client_iter_repo_collaborators_resolves_the_owner_installation():
    collaborators = [
        SimpleNamespace(login="bob", id=2, name=None, email=None, type="User",
                        site_admin=False, html_url="", role_name="admin")
    ]
    installation_gh = SimpleNamespace(
        get_repo=lambda full_name: SimpleNamespace(
            get_collaborators=lambda affiliation=None: collaborators
        )
    )
    client = _app_client_with_installations([_installation("acme")], {7: installation_gh})
    users = list(client.iter_repo_collaborators("acme/webapp"))
    assert [(u.login, u.role, u.repo) for u in users] == [("bob", "admin", "webapp")]
