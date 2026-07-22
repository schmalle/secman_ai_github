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
    for var in ("GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_TOKEN"):
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


def test_build_auth_neither_raises(monkeypatch):
    _clear_github_env(monkeypatch)
    with pytest.raises(ConfigError):
        build_auth()


# -- AuthContext.token_for --------------------------------------------------------


class _FakeApp:
    def __init__(self):
        self.calls = []

    def token_for(self, repo):
        self.calls.append(repo.full_name)
        return "ghs_installation"


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
