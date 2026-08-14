from types import SimpleNamespace

import pytest

from secscan.config import ConfigError, Filters, GithubPatConfig
from secscan.github_app import RepoInfo
from secscan.github_auth import (
    AuthContext,
    GithubPatClient,
    build_auth,
    resolve_target,
)


def _repo(owner="octo", name="repo", installation_id=0, **kw):
    defaults = dict(
        full_name=f"{owner}/{name}",
        archived=False,
        fork=False,
        size_kb=100,
        default_branch="main",
        clone_url=f"https://github.com/{owner}/{name}.git",
    )
    defaults.update(kw)
    return RepoInfo(owner=owner, name=name, installation_id=installation_id, **defaults)


def _gh_repo(owner="octo", name="repo", archived=False, fork=False, size=100):
    return SimpleNamespace(
        owner=SimpleNamespace(login=owner),
        name=name,
        full_name=f"{owner}/{name}",
        archived=archived,
        fork=fork,
        size=size,
        default_branch="main",
        clone_url=f"https://github.com/{owner}/{name}.git",
    )


# -- GithubPatConfig --------------------------------------------------------------


def test_pat_config_from_env(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_abc")
    assert GithubPatConfig.from_env().token == "ghp_abc"


def test_pat_config_missing_raises(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(ConfigError):
        GithubPatConfig.from_env()


# -- build_auth -------------------------------------------------------------------


def _clear_github_env(monkeypatch):
    for var in (
        "GITHUB_APP_ID",
        "GITHUB_APP_CLIENT_ID",
        "GITHUB_APP_PRIVATE_KEY",
        "GITHUB_APP_PRIVATE_KEY_PATH",
        "GITHUB_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)


def test_build_auth_app_only(monkeypatch):
    _clear_github_env(monkeypatch)
    monkeypatch.setenv("GITHUB_APP_ID", "123")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "fake-pem")  # client is lazy; never parsed here
    auth = build_auth()
    assert auth.app is not None
    assert auth.pat is None


def test_build_auth_pat_only(monkeypatch):
    _clear_github_env(monkeypatch)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_abc")
    auth = build_auth()
    assert auth.app is None
    assert auth.pat is not None


def test_build_auth_both(monkeypatch):
    _clear_github_env(monkeypatch)
    monkeypatch.setenv("GITHUB_APP_ID", "123")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "fake-pem")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_abc")
    auth = build_auth()
    assert auth.app is not None
    assert auth.pat is not None


def test_build_auth_app_from_client_id_only(monkeypatch):
    _clear_github_env(monkeypatch)
    monkeypatch.setenv("GITHUB_APP_CLIENT_ID", "Iv23liV27z2aVR0QLrBp")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "fake-pem")
    auth = build_auth()
    assert auth.app is not None
    assert auth.app._config.app_id == "Iv23liV27z2aVR0QLrBp"
    assert auth.pat is None


def test_build_auth_neither_raises(monkeypatch):
    _clear_github_env(monkeypatch)
    with pytest.raises(ConfigError, match="GITHUB_APP_ID"):
        build_auth()


# -- AuthContext.token_for --------------------------------------------------------


class _FakeApp:
    def __init__(self, installed=None):
        self.calls = []
        self.installed = installed or {}  # owner -> installation_id

    def token_for(self, repo):
        self.calls.append(repo.full_name)
        return "ghs_installation"

    def lookup_repo(self, owner, name):
        installation_id = self.installed.get(owner)
        if installation_id is None:
            return None
        return _repo(owner=owner, name=name, installation_id=installation_id)


class _FakePat:
    def __init__(self, token="ghp_abc"):
        self.token = token
        self.calls = []

    def token_for(self, repo):
        self.calls.append(repo.full_name)
        return self.token

    def lookup_repo(self, owner, name):
        return None


def test_token_for_prefers_app_for_installation_repos():
    app, pat = _FakeApp(), _FakePat()
    auth = AuthContext(app=app, pat=pat)
    assert auth.token_for(_repo(installation_id=42)) == "ghs_installation"
    assert pat.calls == []


def test_token_for_falls_back_to_pat_for_installation_id_zero():
    app, pat = _FakeApp(), _FakePat()
    auth = AuthContext(app=app, pat=pat)
    assert auth.token_for(_repo(installation_id=0)) == "ghp_abc"
    assert app.calls == []


def test_token_for_uses_pat_when_no_app():
    auth = AuthContext(app=None, pat=_FakePat())
    assert auth.token_for(_repo(installation_id=42)) == "ghp_abc"


def test_token_for_raises_without_usable_credentials():
    auth = AuthContext(app=None, pat=None)
    with pytest.raises(ConfigError):
        auth.token_for(_repo())


# -- GithubPatClient --------------------------------------------------------------


def _pat_client_with_fake_gh(fake_gh):
    client = GithubPatClient(GithubPatConfig(token="ghp_abc"))
    client._gh = fake_gh
    return client


def test_pat_client_token_for_returns_pat():
    client = GithubPatClient(GithubPatConfig(token="ghp_abc"))
    assert client.token_for(_repo()) == "ghp_abc"


def test_pat_client_iter_repositories_maps_and_filters():
    fake_gh = SimpleNamespace(
        get_user=lambda: SimpleNamespace(
            get_repos=lambda: [
                _gh_repo(name="keep"),
                _gh_repo(name="forked", fork=True),
            ]
        )
    )
    client = _pat_client_with_fake_gh(fake_gh)
    repos = list(client.iter_repositories(filters=Filters()))
    assert [r.full_name for r in repos] == ["octo/keep"]
    assert repos[0].installation_id == 0


def test_pat_client_lookup_repo_returns_info():
    fake_gh = SimpleNamespace(get_repo=lambda full_name: _gh_repo(name="repo"))
    client = _pat_client_with_fake_gh(fake_gh)
    info = client.lookup_repo("octo", "repo")
    assert info.full_name == "octo/repo"
    assert info.installation_id == 0


def test_pat_client_last_commit_returns_sha_and_iso_date():
    from datetime import datetime, timezone

    commit = SimpleNamespace(
        sha="a1b2c3d4e5f6",
        commit=SimpleNamespace(
            committer=SimpleNamespace(date=datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc))
        ),
    )
    fake_gh = SimpleNamespace(
        get_repo=lambda full_name: SimpleNamespace(get_commits=lambda: [commit])
    )
    client = _pat_client_with_fake_gh(fake_gh)
    assert client.last_commit(_repo()) == ("a1b2c3d4e5f6", "2026-07-15")


def test_pat_client_lookup_repo_none_on_api_error():
    from github import GithubException

    def _boom(full_name):
        raise GithubException(404, {"message": "Not Found"}, {})

    client = _pat_client_with_fake_gh(SimpleNamespace(get_repo=_boom))
    assert client.lookup_repo("octo", "missing") is None


# -- resolve_target ---------------------------------------------------------------


def test_resolve_target_constructs_url_without_pat():
    info = resolve_target("octo", "repo", AuthContext(app=None, pat=None))
    assert info.clone_url == "https://github.com/octo/repo.git"
    assert info.installation_id == 0
    assert info.full_name == "octo/repo"


def test_resolve_target_uses_pat_lookup():
    class _Pat(_FakePat):
        def lookup_repo(self, owner, name):
            return _repo(owner=owner, name=name, size_kb=777)

    info = resolve_target("octo", "repo", AuthContext(app=None, pat=_Pat()))
    assert info.size_kb == 777


def test_resolve_target_falls_back_when_lookup_fails():
    info = resolve_target("octo", "repo", AuthContext(app=None, pat=_FakePat()))
    assert info.clone_url == "https://github.com/octo/repo.git"


def test_resolve_target_app_only_yields_a_cloneable_repo():
    """Regression: App-only credentials could not clone an explicitly added target.

    `resolve_target` used to consult the PAT alone, so with App-only credentials it
    returned installation_id=0 and `token_for` then refused to mint any token.
    """
    app = _FakeApp(installed={"acme": 7})
    auth = AuthContext(app=app, pat=None)

    info = resolve_target("acme", "webapp", auth)

    assert info.installation_id == 7
    assert auth.token_for(info) == "ghs_installation"


def test_resolve_target_prefers_the_app_over_the_pat():
    class _Pat(_FakePat):
        def lookup_repo(self, owner, name):
            return _repo(owner=owner, name=name, size_kb=777)

    info = resolve_target("acme", "webapp", AuthContext(app=_FakeApp({"acme": 7}), pat=_Pat()))
    assert info.installation_id == 7


def test_resolve_target_uses_the_pat_where_the_app_is_not_installed():
    class _Pat(_FakePat):
        def lookup_repo(self, owner, name):
            return _repo(owner=owner, name=name, size_kb=777)

    info = resolve_target("octo", "repo", AuthContext(app=_FakeApp({"acme": 7}), pat=_Pat()))
    assert (info.installation_id, info.size_kb) == (0, 777)


def test_token_for_error_names_both_ways_to_fix_it():
    auth = AuthContext(app=None, pat=None)
    with pytest.raises(ConfigError, match="GITHUB_TOKEN") as exc:
        auth.token_for(_repo(owner="acme", name="webapp"))
    assert "acme" in str(exc.value)


# -- GitHub deployment (Enterprise Cloud / Enterprise Server) ----------------------


@pytest.mark.parametrize(
    "api_url,expected_base",
    [
        (None, "https://api.github.com"),                              # Enterprise Cloud
        ("https://github.com", "https://api.github.com"),              # Enterprise Cloud
        ("https://acme.ghe.com", "https://api.acme.ghe.com"),          # GHEC data residency
        ("https://ghes.example.com", "https://ghes.example.com/api/v3"),  # Enterprise Server
    ],
)
def test_pat_client_points_pygithub_at_the_configured_deployment(api_url, expected_base):
    """PyGithub's constructor makes no request, so the base URL can be asserted directly."""
    from secscan.config import GithubHost

    client = GithubPatClient(GithubPatConfig(token="ghp_abc", host=GithubHost.resolve(api_url)))
    assert client.gh.requester.base_url == expected_base


def test_build_auth_applies_the_api_url_to_every_client_and_the_context(monkeypatch):
    _clear_github_env(monkeypatch)
    monkeypatch.setenv("GITHUB_APP_ID", "123")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "fake-pem")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_abc")

    auth = build_auth("https://ghes.example.com")

    assert auth.host.api_url == "https://ghes.example.com/api/v3"
    assert auth.host.web_url == "https://ghes.example.com"
    assert auth.app._config.host == auth.host
    assert auth.pat._config.host == auth.host


def test_build_auth_reads_github_api_url_from_the_environment(monkeypatch):
    _clear_github_env(monkeypatch)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_abc")
    monkeypatch.setenv("GITHUB_API_URL", "https://acme.ghe.com")

    auth = build_auth()

    assert auth.host.api_url == "https://api.acme.ghe.com"


def test_build_auth_argument_beats_the_environment(monkeypatch):
    _clear_github_env(monkeypatch)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_abc")
    monkeypatch.setenv("GITHUB_API_URL", "https://acme.ghe.com")

    auth = build_auth("https://ghes.example.com")

    assert auth.host.api_url == "https://ghes.example.com/api/v3"


def test_resolve_target_fallback_uses_the_enterprise_web_host():
    """Enterprise Server serves git from its own host, not github.com."""
    from secscan.config import GithubHost

    auth = AuthContext(app=None, pat=None, host=GithubHost.resolve("https://ghes.example.com"))
    info = resolve_target("acme", "webapp", auth)
    assert info.clone_url == "https://ghes.example.com/acme/webapp.git"


def test_resolve_target_fallback_defaults_to_github_com():
    assert resolve_target("octo", "repo", AuthContext()).clone_url == (
        "https://github.com/octo/repo.git"
    )


# -- user listings ----------------------------------------------------------------


def test_pat_client_iter_org_members_delegates_to_the_token_client():
    from types import SimpleNamespace as NS

    members = [NS(login="alice", id=1, name=None, email=None, type="User", site_admin=False, html_url="")]
    fake_gh = NS(
        get_organization=lambda org: NS(
            get_members=lambda role=None: (members if role != "admin" else [])
        )
    )
    client = _pat_client_with_fake_gh(fake_gh)
    assert [(u.login, u.role, u.org) for u in client.iter_org_members("acme")] == [
        ("alice", "member", "acme")
    ]


def test_pat_client_iter_repo_collaborators_delegates_to_the_token_client():
    from types import SimpleNamespace as NS

    collaborators = [
        NS(login="bob", id=2, name=None, email=None, type="User", site_admin=False,
           html_url="", role_name="write")
    ]
    fake_gh = NS(
        get_repo=lambda full_name: NS(get_collaborators=lambda affiliation=None: collaborators)
    )
    client = _pat_client_with_fake_gh(fake_gh)
    users = list(client.iter_repo_collaborators("acme/webapp"))
    assert [(u.login, u.role, u.org, u.repo) for u in users] == [("bob", "write", "acme", "webapp")]
