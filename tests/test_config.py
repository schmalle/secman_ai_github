from pathlib import Path

from secscan.cli import _resolve_db_password, _resolve_db_ssl, _resolve_db_url, _resolve_db_user
from secscan.config import RunConfig


def test_db_url_defaults_to_none():
    cfg = RunConfig()
    assert cfg.db_url is None


def test_state_target_prefers_db_url():
    cfg = RunConfig(state_db=Path("output/secscan.sqlite3"), db_url="mysql://h/db")
    assert cfg.state_target == "mysql://h/db"


def test_state_target_falls_back_to_sqlite_path():
    cfg = RunConfig(state_db=Path("output/secscan.sqlite3"))
    assert cfg.state_target == Path("output/secscan.sqlite3")


def test_resolve_db_url_flag_wins(monkeypatch):
    monkeypatch.setenv("SECSCAN_DB_URL", "mysql://env/db")
    assert _resolve_db_url("mysql://flag/db") == "mysql://flag/db"


def test_resolve_db_url_env_fallback(monkeypatch):
    monkeypatch.setenv("SECSCAN_DB_URL", "mysql://env/db")
    assert _resolve_db_url(None) == "mysql://env/db"


def test_resolve_db_url_none_when_unset(monkeypatch):
    monkeypatch.delenv("SECSCAN_DB_URL", raising=False)
    assert _resolve_db_url(None) is None


def test_db_user_password_ssl_default_none_false():
    cfg = RunConfig()
    assert cfg.db_user is None
    assert cfg.db_password is None
    assert cfg.db_ssl is False


def test_resolve_db_user_flag_wins(monkeypatch):
    monkeypatch.setenv("DB_USERNAME", "envuser")
    assert _resolve_db_user("flaguser") == "flaguser"


def test_resolve_db_user_env_fallback(monkeypatch):
    monkeypatch.setenv("DB_USERNAME", "envuser")
    assert _resolve_db_user(None) == "envuser"


def test_resolve_db_user_none_when_unset(monkeypatch):
    monkeypatch.delenv("DB_USERNAME", raising=False)
    assert _resolve_db_user(None) is None


def test_resolve_db_password_flag_wins(monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "envpass")
    assert _resolve_db_password("flagpass") == "flagpass"


def test_resolve_db_password_env_fallback(monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "envpass")
    assert _resolve_db_password(None) == "envpass"


def test_resolve_db_ssl_flag_true_wins(monkeypatch):
    monkeypatch.delenv("DB_SSL", raising=False)
    assert _resolve_db_ssl(True) is True


def test_resolve_db_ssl_env_true_when_flag_false(monkeypatch):
    monkeypatch.setenv("DB_SSL", "true")
    assert _resolve_db_ssl(False) is True


def test_resolve_db_ssl_false_when_neither_set(monkeypatch):
    monkeypatch.delenv("DB_SSL", raising=False)
    assert _resolve_db_ssl(False) is False


def test_no_db_defaults_false():
    assert RunConfig().no_db is False
