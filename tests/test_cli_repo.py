from typer.testing import CliRunner

from secscan.cli import app
from secscan.state import StateStore

runner = CliRunner()


def _db_args(tmp_path):
    return ["--output-dir", str(tmp_path)]


def test_repo_add_then_list(tmp_path):
    result = runner.invoke(app, ["repo", "add", "octo/demo", *_db_args(tmp_path)])
    assert result.exit_code == 0
    assert "Added octo/demo" in result.output

    result = runner.invoke(app, ["repo", "list", *_db_args(tmp_path)])
    assert result.exit_code == 0
    assert "octo/demo" in result.output


def test_repo_add_persists_to_state_db(tmp_path):
    runner.invoke(app, ["repo", "add", "octo/demo", *_db_args(tmp_path)])
    store = StateStore(tmp_path / "secscan.sqlite3")
    assert store.list_targets() == [("octo", "demo")]


def test_repo_add_rejects_bad_name(tmp_path):
    for bad in ("noslash", "a/b/c", "/name", "owner/"):
        result = runner.invoke(app, ["repo", "add", bad, *_db_args(tmp_path)])
        assert result.exit_code != 0, bad


def test_repo_add_duplicate_is_friendly_noop(tmp_path):
    runner.invoke(app, ["repo", "add", "octo/demo", *_db_args(tmp_path)])
    result = runner.invoke(app, ["repo", "add", "octo/demo", *_db_args(tmp_path)])
    assert result.exit_code == 0
    assert "Already a target" in result.output


def test_repo_remove(tmp_path):
    runner.invoke(app, ["repo", "add", "octo/demo", *_db_args(tmp_path)])
    result = runner.invoke(app, ["repo", "remove", "octo/demo", *_db_args(tmp_path)])
    assert result.exit_code == 0
    assert "Removed octo/demo" in result.output


def test_repo_remove_missing_exits_nonzero(tmp_path):
    result = runner.invoke(app, ["repo", "remove", "octo/none", *_db_args(tmp_path)])
    assert result.exit_code == 1


def test_repo_list_empty_hint(tmp_path):
    result = runner.invoke(app, ["repo", "list", *_db_args(tmp_path)])
    assert result.exit_code == 0
    assert "no targets" in result.output
