"""Configuration for secscan.

Settings come from environment variables (optionally a `.env` loaded by the shell)
and are overridden by CLI flags. Secrets are read from the environment only; they are
never written to disk by this tool.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name)
    return val if val not in (None, "") else default


@dataclass
class GithubAppConfig:
    """GitHub App credentials. The private key is held in memory only."""

    app_id: str
    private_key: str

    @classmethod
    def from_env(cls) -> "GithubAppConfig":
        app_id = _env("GITHUB_APP_ID")
        if not app_id:
            raise ConfigError("GITHUB_APP_ID is required")

        key = _env("GITHUB_APP_PRIVATE_KEY")
        key_path = _env("GITHUB_APP_PRIVATE_KEY_PATH")
        if not key and key_path:
            try:
                key = Path(key_path).expanduser().read_text()
            except OSError as exc:
                raise ConfigError(f"cannot read GITHUB_APP_PRIVATE_KEY_PATH: {exc}") from exc
        if not key:
            raise ConfigError(
                "GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH is required"
            )
        return cls(app_id=app_id, private_key=key)


@dataclass
class GithubPatConfig:
    """GitHub personal access token (classic or fine-grained). Held in memory only."""

    token: str

    @classmethod
    def from_env(cls) -> "GithubPatConfig":
        token = _env("GITHUB_TOKEN")
        if not token:
            raise ConfigError("GITHUB_TOKEN is required for PAT auth")
        return cls(token=token)


@dataclass
class Filters:
    include_archived: bool = False
    include_forks: bool = False
    max_size_mb: int = 500  # GitHub reports repo `size` in KB; 0 disables the cap.


@dataclass
class RunConfig:
    """Everything needed to run a scan. Built by the CLI from flags + env."""

    output_dir: Path = Path("output")
    state_db: Path = Path("output/secscan.sqlite3")
    db_url: str | None = None  # mysql://… selects MySQL/MariaDB; None uses state_db (SQLite)
    db_user: str | None = None  # overrides any user embedded in db_url
    db_password: str | None = None  # overrides any password embedded in db_url
    db_ssl: bool = False  # encrypt the MySQL connection (no custom CA/cert/key)
    no_db: bool = False  # skip all DB storage; findings.csv still written, summary.csv skipped
    filters: Filters = field(default_factory=Filters)
    concurrency: int = 4
    model: str = "sonnet"
    provider: str = "auto"  # anthropic | openrouter | auto | usecc (see providers.py)
    max_turns: int = 60
    max_cost_usd: float | None = None  # per-repo abort threshold; None = no cap
    timeout_s: float = 900.0  # abort if the agent stalls (no messages) this long; 0 disables
    keep_clones: bool = False
    resume: bool = True  # skip repos already marked done
    limit: int | None = None  # cap number of repos (smoke tests)

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)
        self.state_db = Path(self.state_db)

    @property
    def state_target(self) -> "str | Path":
        return self.db_url or self.state_db


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""
