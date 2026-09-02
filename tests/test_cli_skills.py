from typer.testing import CliRunner

from secscan.cli import app
from secscan.skills import bundled_names

runner = CliRunner()


def test_skills_list_prints_every_bundled_skill():
    result = runner.invoke(app, ["skills", "list"])

    assert result.exit_code == 0, result.output
    for name in bundled_names():
        assert name in result.output
    assert "--skill" in result.output  # usage hint


def test_skills_show_prints_the_skill_md():
    result = runner.invoke(app, ["skills", "show", "false-positive-filter"])

    assert result.exit_code == 0, result.output
    assert "name: false-positive-filter" in result.output
    assert "exploitability triad" in result.output


def test_skills_show_path(tmp_path):
    d = tmp_path / "mine"
    d.mkdir()
    (d / "SKILL.md").write_text("---\nname: mine\ndescription: d\n---\nHello body\n")

    result = runner.invoke(app, ["skills", "show", str(d)])

    assert result.exit_code == 0, result.output
    assert "Hello body" in result.output


def test_skills_show_unknown_is_a_clean_error():
    result = runner.invoke(app, ["skills", "show", "nope"])

    assert result.exit_code == 1
    assert "nope" in result.output
