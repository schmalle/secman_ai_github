from typer.testing import CliRunner

from secscan.cli import app

runner = CliRunner()


def _capture_review_local(monkeypatch, captured):
    import secscan.orchestrator

    async def fake_review_local(cfg, path):
        captured["cfg"] = cfg
        captured["path"] = path

    monkeypatch.setattr(secscan.orchestrator, "review_local", fake_review_local)


def test_review_defaults_to_no_db(tmp_path, monkeypatch):
    captured = {}
    _capture_review_local(monkeypatch, captured)

    result = runner.invoke(app, ["review", str(tmp_path), "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert captured["cfg"].no_db is True


def test_review_store_db_enables_the_state_store(tmp_path, monkeypatch):
    captured = {}
    _capture_review_local(monkeypatch, captured)

    result = runner.invoke(
        app, ["review", str(tmp_path), "--output-dir", str(tmp_path), "--store-db"]
    )

    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.no_db is False
    assert cfg.db_url is None  # local SQLite under --output-dir
    assert cfg.state_target == tmp_path / "secscan.sqlite3"


def test_review_db_flags_reach_config(tmp_path, monkeypatch):
    captured = {}
    _capture_review_local(monkeypatch, captured)

    result = runner.invoke(
        app,
        ["review", str(tmp_path), "--output-dir", str(tmp_path), "--store-db",
         "--db-url", "mysql://host:3306/secscan",
         "--db-user", "scanner", "--db-password", "pw", "--db-ssl"],
    )

    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.state_target == "mysql://host:3306/secscan"
    assert (cfg.db_user, cfg.db_password, cfg.db_ssl) == ("scanner", "pw", True)


def test_review_db_env_vars_are_honoured(tmp_path, monkeypatch):
    monkeypatch.setenv("SECSCAN_DB_URL", "mysql://host:3306/fromenv")
    monkeypatch.setenv("DB_USERNAME", "envuser")
    monkeypatch.setenv("DB_PASSWORD", "envpw")
    monkeypatch.setenv("DB_SSL", "true")
    captured = {}
    _capture_review_local(monkeypatch, captured)

    result = runner.invoke(
        app, ["review", str(tmp_path), "--output-dir", str(tmp_path), "--store-db"]
    )

    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.state_target == "mysql://host:3306/fromenv"
    assert (cfg.db_user, cfg.db_password, cfg.db_ssl) == ("envuser", "envpw", True)


def test_review_skill_flag_loads_bundled_and_path_skills(tmp_path, monkeypatch):
    captured = {}
    _capture_review_local(monkeypatch, captured)
    custom = tmp_path / "custom-pack"
    custom.mkdir()
    (custom / "SKILL.md").write_text("---\nname: custom-pack\ndescription: d\n---\nBody\n")

    result = runner.invoke(
        app,
        ["review", str(tmp_path), "--output-dir", str(tmp_path),
         "--skill", "owasp-top10", "--skill", str(custom)],
    )

    assert result.exit_code == 0, result.output
    names = [s.name for s in captured["cfg"].skills]
    assert names == ["owasp-top10", "custom-pack"]
    assert captured["cfg"].skills[0].bundled is True


def test_review_defaults_to_no_skills(tmp_path, monkeypatch):
    captured = {}
    _capture_review_local(monkeypatch, captured)

    result = runner.invoke(app, ["review", str(tmp_path), "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert captured["cfg"].skills == []


def test_review_unknown_skill_is_a_clean_config_error(tmp_path, monkeypatch):
    captured = {}
    _capture_review_local(monkeypatch, captured)

    result = runner.invoke(
        app, ["review", str(tmp_path), "--output-dir", str(tmp_path), "--skill", "nope"]
    )

    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "--skill" in result.output and "nope" in result.output
    assert "cfg" not in captured  # failed before any review started
