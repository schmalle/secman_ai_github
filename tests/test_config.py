from pathlib import Path

import pytest

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


from secscan.config import ConfigError


def test_create_issues_and_dry_run_default_false():
    cfg = RunConfig()
    assert cfg.create_issues is False
    assert cfg.dry_run is False


def test_run_config_rejects_no_db_with_create_issues():
    import pytest
    from secscan.cli import _run_config

    with pytest.raises(ConfigError, match="no-db.*create-issues|create-issues.*no-db"):
        _run_config(
            output_dir=Path("output"), concurrency=1, model="sonnet", max_turns=1,
            max_cost_usd=None, include_archived=False, include_forks=False, max_size_mb=0,
            keep_clones=True, resume=False, limit=None, no_db=True, create_issues=True,
        )


# -- GitHub deployment URLs -------------------------------------------------------


def test_normalize_github_urls_defaults_to_public_github():
    from secscan.config import normalize_github_urls

    assert normalize_github_urls(None) == ("https://api.github.com", "https://github.com")
    assert normalize_github_urls("") == ("https://api.github.com", "https://github.com")


@pytest.mark.parametrize(
    "value,expected",
    [
        # Enterprise Cloud (SaaS) on github.com — the API lives on an api. subdomain.
        ("https://github.com", ("https://api.github.com", "https://github.com")),
        ("https://api.github.com", ("https://api.github.com", "https://github.com")),
        ("https://github.com/", ("https://api.github.com", "https://github.com")),
        # Enterprise Cloud with data residency — same api. subdomain shape.
        ("https://acme.ghe.com", ("https://api.acme.ghe.com", "https://acme.ghe.com")),
        ("https://api.acme.ghe.com", ("https://api.acme.ghe.com", "https://acme.ghe.com")),
        ("  https://api.acme.ghe.com/  ", ("https://api.acme.ghe.com", "https://acme.ghe.com")),
        # Enterprise Server — the API lives on an /api/v3 path of the same host.
        (
            "https://ghes.example.com",
            ("https://ghes.example.com/api/v3", "https://ghes.example.com"),
        ),
        (
            "https://ghes.example.com/api/v3",
            ("https://ghes.example.com/api/v3", "https://ghes.example.com"),
        ),
        (
            "https://ghes.example.com/api/v3/",
            ("https://ghes.example.com/api/v3", "https://ghes.example.com"),
        ),
        ("http://ghes.internal", ("http://ghes.internal/api/v3", "http://ghes.internal")),
    ],
)
def test_normalize_github_urls_handles_every_deployment(value, expected):
    from secscan.config import normalize_github_urls

    assert normalize_github_urls(value) == expected


@pytest.mark.parametrize(
    "value", ["ftp://ghes.example.com", "github.com", "https://ghes.example.com/api", "https://"]
)
def test_normalize_github_urls_rejects_unusable_input(value):
    from secscan.config import ConfigError, normalize_github_urls

    with pytest.raises(ConfigError):
        normalize_github_urls(value)


def test_github_host_resolve_reads_env(monkeypatch):
    from secscan.config import GithubHost

    monkeypatch.setenv("GITHUB_API_URL", "https://ghes.example.com")
    assert GithubHost.resolve().api_url == "https://ghes.example.com/api/v3"


def test_github_host_resolve_argument_beats_env(monkeypatch):
    from secscan.config import GithubHost

    monkeypatch.setenv("GITHUB_API_URL", "https://ghes.example.com")
    host = GithubHost.resolve("https://acme.ghe.com")
    assert (host.api_url, host.web_url) == ("https://api.acme.ghe.com", "https://acme.ghe.com")


def test_run_config_github_api_url_defaults_to_none():
    assert RunConfig().github_api_url is None
