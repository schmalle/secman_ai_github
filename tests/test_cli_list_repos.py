from types import SimpleNamespace

from typer.testing import CliRunner

from secscan.cli import app
from secscan.github_app import RepoInfo

runner = CliRunner()


def _repo(owner="octo", name="demo", size_kb=420):
    return RepoInfo(
        owner=owner,
        name=name,
        full_name=f"{owner}/{name}",
        archived=False,
        fork=False,
        size_kb=size_kb,
        default_branch="main",
        clone_url=f"https://github.com/{owner}/{name}.git",
        installation_id=0,
    )


class _FakeClient:
    def __init__(self, repos, commits):
        self._repos = repos
        self._commits = commits  # full_name -> (sha, date) or missing for empty repos
        self.last_commit_calls = []

    def iter_repositories(self, org=None, filters=None):
        yield from self._repos

    def last_commit(self, repo):
        self.last_commit_calls.append(repo.full_name)
        return self._commits.get(repo.full_name)


def _patch_auth(monkeypatch, client):
    import secscan.github_auth as github_auth

    monkeypatch.setattr(github_auth, "build_auth", lambda: SimpleNamespace(app=None, pat=client))


def test_list_repos_appends_short_sha_and_date_by_default(monkeypatch):
    client = _FakeClient([_repo()], {"octo/demo": ("a1b2c3d4e5f6", "2026-07-15")})
    _patch_auth(monkeypatch, client)
    result = runner.invoke(app, ["list-repos", "--no-db"])
    assert result.exit_code == 0
    assert "octo/demo\t420 KB\ta1b2c3d\t2026-07-15\n" in result.output


def test_list_repos_no_last_commit_skips_the_lookup(monkeypatch):
    client = _FakeClient([_repo()], {"octo/demo": ("a1b2c3d4e5f6", "2026-07-15")})
    _patch_auth(monkeypatch, client)
    result = runner.invoke(app, ["list-repos", "--no-last-commit", "--no-db"])
    assert result.exit_code == 0
    assert "octo/demo\t420 KB\n" in result.output
    assert client.last_commit_calls == []  # no API cost when opted out


def test_list_repos_empty_repo_prints_dashes(monkeypatch):
    client = _FakeClient([_repo(name="empty")], {})
    _patch_auth(monkeypatch, client)
    result = runner.invoke(app, ["list-repos", "--no-db"])
    assert result.exit_code == 0
    assert "octo/empty\t420 KB\t-\t-\n" in result.output


def _records(output_dir):
    from secscan.state import StateStore

    return StateStore(output_dir / "secscan.sqlite3").all_records()


def test_list_repos_stores_last_commit_in_state(monkeypatch, tmp_path):
    client = _FakeClient([_repo()], {"octo/demo": ("a1b2c3d4e5f6", "2026-07-15")})
    _patch_auth(monkeypatch, client)
    result = runner.invoke(app, ["list-repos", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    rec = _records(tmp_path)[0]
    assert rec.full_name == "octo/demo"
    assert rec.last_commit_sha == "a1b2c3d4e5f6"  # full sha stored, short one printed
    assert rec.last_commit_date == "2026-07-15"


def test_list_repos_does_not_store_unreadable_repo(monkeypatch, tmp_path):
    client = _FakeClient([_repo(name="empty")], {})
    _patch_auth(monkeypatch, client)
    result = runner.invoke(app, ["list-repos", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert _records(tmp_path) == []


def test_list_repos_no_db_writes_nothing(monkeypatch, tmp_path):
    client = _FakeClient([_repo()], {"octo/demo": ("a1b2c3d4e5f6", "2026-07-15")})
    _patch_auth(monkeypatch, client)
    result = runner.invoke(app, ["list-repos", "--output-dir", str(tmp_path), "--no-db"])
    assert result.exit_code == 0
    assert not (tmp_path / "secscan.sqlite3").exists()


def test_list_repos_no_last_commit_writes_nothing(monkeypatch, tmp_path):
    client = _FakeClient([_repo()], {"octo/demo": ("a1b2c3d4e5f6", "2026-07-15")})
    _patch_auth(monkeypatch, client)
    result = runner.invoke(
        app, ["list-repos", "--output-dir", str(tmp_path), "--no-last-commit"]
    )
    assert result.exit_code == 0
    assert not (tmp_path / "secscan.sqlite3").exists()  # nothing to record
