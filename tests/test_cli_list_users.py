import csv
import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from secscan.cli import app
from secscan.github_app import RepoInfo
from secscan.github_users import GithubUser, OrgAccessError

runner = CliRunner()


def _user(login, org="acme", repo="", role="member", **kw):
    defaults = dict(
        user_id=1, name="", email="", user_type="User", site_admin=False,
        source="repo" if repo else "org", html_url="",
    )
    defaults.update(kw)
    return GithubUser(login=login, org=org, repo=repo, role=role, **defaults)


def _repo_info(owner="acme", name="webapp"):
    return RepoInfo(
        owner=owner, name=name, full_name=f"{owner}/{name}", archived=False, fork=False,
        size_kb=1, default_branch="main",
        clone_url=f"https://github.com/{owner}/{name}.git", installation_id=0,
    )


class _FakeClient:
    """Duck-types GithubPatClient / GithubAppClient for the listings list-users uses."""

    def __init__(self, members=None, collaborators=None, repos=(), error=None):
        self.members = members or {}          # org -> [GithubUser]
        self.collaborators = collaborators or {}  # "owner/name" -> [GithubUser]
        self.repos = list(repos)
        self.error = error
        self.calls = []

    def iter_org_members(self, org):
        self.calls.append(("org", org))
        if self.error:
            raise self.error
        return iter(self.members.get(org, []))

    def iter_repo_collaborators(self, full_name):
        self.calls.append(("repo", full_name))
        if self.error:
            raise self.error
        return iter(self.collaborators.get(full_name, []))

    def iter_repositories(self, org=None, filters=None):
        yield from self.repos


def _patch_auth(monkeypatch, pat=None, appc=None):
    import secscan.github_auth as github_auth

    monkeypatch.setattr(
        github_auth, "build_auth",
        lambda api_url=None: SimpleNamespace(app=appc, pat=pat),
    )


def _capture_auth(monkeypatch, client):
    """Patch build_auth and record the api_url the CLI forwarded to it."""
    import secscan.github_auth as github_auth

    seen = {}

    def _build_auth(api_url=None):
        seen["api_url"] = api_url
        return SimpleNamespace(app=None, pat=client)

    monkeypatch.setattr(github_auth, "build_auth", _build_auth)
    return seen


# -- CLI plumbing and validation --------------------------------------------------


def test_list_users_requires_org_or_repo(monkeypatch):
    _patch_auth(monkeypatch, pat=_FakeClient())
    result = runner.invoke(app, ["list-users", "--no-db", "--no-csv"])
    assert result.exit_code != 0
    assert "--org" in result.output


def test_org_repos_without_org_is_rejected(monkeypatch):
    _patch_auth(monkeypatch, pat=_FakeClient())
    result = runner.invoke(
        app, ["list-users", "--repo", "acme/webapp", "--org-repos", "--no-db", "--no-csv"]
    )
    assert result.exit_code != 0
    assert "--org-repos" in result.output


def test_bad_format_is_rejected(monkeypatch):
    _patch_auth(monkeypatch, pat=_FakeClient())
    result = runner.invoke(app, ["list-users", "--org", "acme", "--format", "yaml", "--no-db"])
    assert result.exit_code != 0


def test_bad_repo_name_is_rejected(monkeypatch):
    _patch_auth(monkeypatch, pat=_FakeClient())
    result = runner.invoke(app, ["list-users", "--repo", "webapp", "--no-db", "--no-csv"])
    assert result.exit_code != 0


def test_github_api_url_is_forwarded_to_build_auth(monkeypatch, tmp_path):
    client = _FakeClient(members={"acme": [_user("alice")]})
    seen = _capture_auth(monkeypatch, client)

    result = runner.invoke(
        app,
        ["list-users", "--org", "acme", "--no-db", "--no-csv",
         "--github-api-url", "https://ghes.example.com"],
    )

    assert result.exit_code == 0
    assert seen["api_url"] == "https://ghes.example.com"


# -- output ------------------------------------------------------------------------


def test_table_output_lists_members_with_their_role(monkeypatch):
    client = _FakeClient(members={"acme": [_user("alice", role="admin"), _user("bob")]})
    _patch_auth(monkeypatch, pat=client)

    result = runner.invoke(app, ["list-users", "--org", "acme", "--no-db", "--no-csv"])

    assert result.exit_code == 0
    assert "org\tacme\talice\tadmin\tUser\t-\n" in result.output
    assert "org\tacme\tbob\tmember\tUser\t-\n" in result.output


def test_table_output_says_so_when_empty(monkeypatch):
    _patch_auth(monkeypatch, pat=_FakeClient(members={"acme": []}))
    result = runner.invoke(app, ["list-users", "--org", "acme", "--no-db", "--no-csv"])
    assert result.exit_code == 0
    assert "(no users found)" in result.output


def test_repo_collaborators_are_listed_with_their_permission(monkeypatch):
    client = _FakeClient(
        collaborators={"acme/webapp": [_user("bob", repo="webapp", role="write")]}
    )
    _patch_auth(monkeypatch, pat=client)

    result = runner.invoke(
        app, ["list-users", "--repo", "acme/webapp", "--no-db", "--no-csv"]
    )

    assert result.exit_code == 0
    assert "repo\tacme/webapp\tbob\twrite\tUser\t-\n" in result.output


def test_json_output_carries_every_field(monkeypatch):
    client = _FakeClient(members={"acme": [_user("alice", role="admin", name="Alice A")]})
    _patch_auth(monkeypatch, pat=client)

    result = runner.invoke(
        app, ["list-users", "--org", "acme", "--format", "json", "--no-db", "--no-csv"]
    )

    payload = json.loads(result.output)
    assert payload == [
        {
            "login": "alice", "user_id": 1, "name": "Alice A", "email": "",
            "user_type": "User", "site_admin": False, "source": "org", "org": "acme",
            "repo": "", "role": "admin", "html_url": "",
        }
    ]


def test_csv_output_goes_to_stdout(monkeypatch):
    client = _FakeClient(members={"acme": [_user("alice", role="admin")]})
    _patch_auth(monkeypatch, pat=client)

    result = runner.invoke(
        app, ["list-users", "--org", "acme", "--format", "csv", "--no-db", "--no-csv"]
    )

    rows = list(csv.DictReader(result.output.strip().splitlines()))
    assert rows[0]["login"] == "alice"
    assert rows[0]["role"] == "admin"


def test_output_file_receives_the_rendered_format(monkeypatch, tmp_path):
    client = _FakeClient(members={"acme": [_user("alice")]})
    _patch_auth(monkeypatch, pat=client)
    target = tmp_path / "nested" / "users.json"

    result = runner.invoke(
        app,
        ["list-users", "--org", "acme", "--format", "json", "--output", str(target),
         "--no-db", "--no-csv"],
    )

    assert result.exit_code == 0
    assert json.loads(target.read_text())[0]["login"] == "alice"


def test_users_csv_is_written_to_the_output_dir(monkeypatch, tmp_path):
    client = _FakeClient(members={"acme": [_user("alice", role="admin")]})
    _patch_auth(monkeypatch, pat=client)

    result = runner.invoke(
        app, ["list-users", "--org", "acme", "--output-dir", str(tmp_path), "--no-db"]
    )

    assert result.exit_code == 0
    rows = list(csv.DictReader((tmp_path / "users.csv").read_text().splitlines()))
    assert [(r["login"], r["role"]) for r in rows] == [("alice", "admin")]


def test_no_csv_suppresses_the_file(monkeypatch, tmp_path):
    _patch_auth(monkeypatch, pat=_FakeClient(members={"acme": [_user("alice")]}))

    runner.invoke(
        app,
        ["list-users", "--org", "acme", "--output-dir", str(tmp_path), "--no-db", "--no-csv"],
    )

    assert not (tmp_path / "users.csv").exists()


# -- state DB ----------------------------------------------------------------------


def test_users_are_recorded_in_the_state_db(monkeypatch, tmp_path):
    from secscan.state import StateStore

    client = _FakeClient(
        members={"acme": [_user("alice", role="admin")]},
        collaborators={"acme/webapp": [_user("bob", repo="webapp", role="write")]},
    )
    _patch_auth(monkeypatch, pat=client)

    result = runner.invoke(
        app,
        ["list-users", "--org", "acme", "--repo", "acme/webapp",
         "--output-dir", str(tmp_path), "--no-csv"],
    )

    assert result.exit_code == 0
    store = StateStore(tmp_path / "secscan.sqlite3")
    assert [(r["repo"], r["login"], r["role"]) for r in store.get_users()] == [
        ("", "alice", "admin"),
        ("webapp", "bob", "write"),
    ]
    store.close()


def test_no_db_writes_no_state(monkeypatch, tmp_path):
    _patch_auth(monkeypatch, pat=_FakeClient(members={"acme": [_user("alice")]}))

    runner.invoke(
        app,
        ["list-users", "--org", "acme", "--output-dir", str(tmp_path), "--no-db", "--no-csv"],
    )

    assert not (tmp_path / "secscan.sqlite3").exists()


# -- credentials and scope ---------------------------------------------------------


def test_org_access_error_exits_one_with_the_explanation(monkeypatch):
    error = OrgAccessError("cannot list users for 'someone': only for organizations")
    _patch_auth(monkeypatch, pat=_FakeClient(error=error))

    result = runner.invoke(app, ["list-users", "--org", "someone", "--no-db", "--no-csv"])

    assert result.exit_code == 1
    assert "only for organizations" in result.output


def test_pat_is_tried_when_the_app_cannot_see_the_org(monkeypatch):
    """App-only failure must not mask a PAT that can read the org."""
    appc = _FakeClient(error=OrgAccessError("app has no installation on 'acme'"))
    pat = _FakeClient(members={"acme": [_user("alice")]})
    _patch_auth(monkeypatch, pat=pat, appc=appc)

    result = runner.invoke(app, ["list-users", "--org", "acme", "--no-db", "--no-csv"])

    assert result.exit_code == 0
    assert "alice" in result.output


def test_app_entry_wins_and_pat_duplicates_are_dropped(monkeypatch):
    appc = _FakeClient(members={"acme": [_user("alice", role="admin")]})
    pat = _FakeClient(members={"acme": [_user("alice", role="member")]})
    _patch_auth(monkeypatch, pat=pat, appc=appc)

    result = runner.invoke(app, ["list-users", "--org", "acme", "--no-db", "--no-csv"])

    assert result.output.count("alice") == 1
    assert "alice\tadmin" in result.output
    assert pat.calls == []  # the App answered; the PAT was never asked


def test_org_repos_walks_every_repository_in_the_org(monkeypatch):
    client = _FakeClient(
        members={"acme": [_user("alice", role="admin")]},
        collaborators={
            "acme/webapp": [_user("bob", repo="webapp", role="write")],
            "acme/api": [_user("carol", repo="api", role="read")],
        },
        repos=[_repo_info(name="webapp"), _repo_info(name="api")],
    )
    _patch_auth(monkeypatch, pat=client)

    result = runner.invoke(
        app, ["list-users", "--org", "acme", "--org-repos", "--no-db", "--no-csv"]
    )

    assert result.exit_code == 0
    assert [c for c in client.calls if c[0] == "repo"] == [
        ("repo", "acme/webapp"),
        ("repo", "acme/api"),
    ]
    for login in ("alice", "bob", "carol"):
        assert login in result.output


def test_org_repos_does_not_re_list_an_explicit_repo(monkeypatch):
    client = _FakeClient(
        members={"acme": []},
        collaborators={"acme/webapp": [_user("bob", repo="webapp")]},
        repos=[_repo_info(name="webapp")],
    )
    _patch_auth(monkeypatch, pat=client)

    runner.invoke(
        app,
        ["list-users", "--org", "acme", "--repo", "acme/webapp", "--org-repos",
         "--no-db", "--no-csv"],
    )

    assert [c for c in client.calls if c[0] == "repo"] == [("repo", "acme/webapp")]


@pytest.mark.parametrize("flag", ["--include-archived", "--include-forks"])
def test_org_repos_filter_flags_are_accepted(monkeypatch, flag):
    client = _FakeClient(members={"acme": []}, repos=[])
    _patch_auth(monkeypatch, pat=client)

    result = runner.invoke(
        app, ["list-users", "--org", "acme", "--org-repos", flag, "--no-db", "--no-csv"]
    )

    assert result.exit_code == 0
