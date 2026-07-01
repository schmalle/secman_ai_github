from pathlib import Path

from secscan.cli import _resolve_db_url
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
