"""Configuration for secscan.

Settings come from environment variables (optionally a `.env` loaded by the shell)
and are overridden by CLI flags. Secrets are read from the environment only; they are
never written to disk by this tool.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_API_URL = "https://api.github.com"
DEFAULT_WEB_URL = "https://github.com"

_ACCEPTED_URL_FORMS = (
    "accepted forms: https://github.com (Enterprise Cloud), "
    "https://TENANT.ghe.com or https://api.TENANT.ghe.com (Enterprise Cloud with data "
    "residency), https://ghes.example.com or https://ghes.example.com/api/v3 "
    "(Enterprise Server)"
)


def _env(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name)
    return val if val not in (None, "") else default


def normalize_github_urls(value: str | None) -> tuple[str, str]:
    """Return (api_url, web_url) for a GitHub deployment. Empty input means public GitHub.

    The three commercial deployments address their API differently, and getting this
    wrong is a silent 404 rather than a clean error:

    - Enterprise Cloud (github.com) and Enterprise Cloud with data residency
      (`TENANT.ghe.com`) put the API on an `api.` **subdomain**.
    - Enterprise Server puts it on an `/api/v3` **path** of the same host.

    So the caller may paste either the web host or the API host and get the same result.
    """
    raw = (value or "").strip().rstrip("/")
    if not raw:
        return DEFAULT_API_URL, DEFAULT_WEB_URL

    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ConfigError(
            f"GitHub API URL must start with http:// or https:// (got {raw!r}); "
            f"{_ACCEPTED_URL_FORMS}"
        )
    host = parts.netloc
    if not host:
        raise ConfigError(f"GitHub API URL has no host (got {raw!r}); {_ACCEPTED_URL_FORMS}")

    origin = f"{parts.scheme}://{host}"
    path = parts.path

    # Enterprise Server, already pointing at the API root.
    if path == "/api/v3":
        return raw, origin
    if path:
        raise ConfigError(
            f"unexpected path in GitHub API URL {raw!r} — pass the host, or the host "
            f"plus /api/v3 for Enterprise Server; {_ACCEPTED_URL_FORMS}"
        )

    # Enterprise Cloud: github.com and data-residency tenants on *.ghe.com.
    bare = host[len("api.") :] if host.startswith("api.") else host
    if bare in ("github.com", "www.github.com") or bare.endswith(".ghe.com"):
        bare = "github.com" if bare == "www.github.com" else bare
        return f"{parts.scheme}://api.{bare}", f"{parts.scheme}://{bare}"

    # Enterprise Server, given as the web host.
    return f"{origin}/api/v3", origin


@dataclass(frozen=True)
class GithubHost:
    """Which GitHub deployment to talk to. Defaults to the public/Enterprise Cloud host."""

    api_url: str = DEFAULT_API_URL
    web_url: str = DEFAULT_WEB_URL

    @classmethod
    def resolve(cls, api_url: str | None = None) -> "GithubHost":
        """Build from an explicit override, else `GITHUB_API_URL`, else public GitHub."""
        return cls(*normalize_github_urls(api_url or _env("GITHUB_API_URL")))


@dataclass
class GithubAppConfig:
    """GitHub App credentials. The private key is held in memory only."""

    app_id: str
    private_key: str
    host: GithubHost = field(default_factory=GithubHost)

    @classmethod
    def from_env(cls, api_url: str | None = None) -> "GithubAppConfig":
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
        return cls(app_id=app_id, private_key=key, host=GithubHost.resolve(api_url))


@dataclass
class GithubPatConfig:
    """GitHub personal access token (classic or fine-grained). Held in memory only."""

    token: str
    host: GithubHost = field(default_factory=GithubHost)

    @classmethod
    def from_env(cls, api_url: str | None = None) -> "GithubPatConfig":
        token = _env("GITHUB_TOKEN")
        if not token:
            raise ConfigError("GITHUB_TOKEN is required for PAT auth")
        return cls(token=token, host=GithubHost.resolve(api_url))


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
    # GitHub deployment to talk to; None = GITHUB_API_URL, else public/Enterprise Cloud.
    github_api_url: str | None = None
    db_url: str | None = None  # mysql://… selects MySQL/MariaDB; None uses state_db (SQLite)
    db_user: str | None = None  # overrides any user embedded in db_url
    db_password: str | None = None  # overrides any password embedded in db_url
    db_ssl: bool = False  # encrypt the MySQL connection (no custom CA/cert/key)
    no_db: bool = False  # skip all DB storage; findings.csv still written, summary.csv skipped
    create_issues: bool = False  # open one GitHub issue per new High/Critical finding
    # Push this invocation's High/Critical findings to the secman backend over HTTPS
    # once the review is done; credentials come from --secman-* or SECMAN_* env.
    push_to_secman: bool = False
    secman_url: str | None = None
    secman_username: str | None = None
    secman_password: str | None = None
    # No external writes: no GitHub issues are opened and nothing is pushed to secman.
    # Reviews still run and local CSV/state is still written; see dryrun.py.
    dry_run: bool = False
    issue_prefix: str = "secscan:"  # prepended to issue titles; empty string means no prefix
    filters: Filters = field(default_factory=Filters)
    concurrency: int = 4
    model: str = "sonnet"
    provider: str = "auto"  # anthropic | openrouter | kimi | copilot | auto | usecc (providers.py)
    max_turns: int = 60
    max_cost_usd: float | None = None  # per-repo abort threshold; None = no cap
    timeout_s: float = 900.0  # abort if the agent stalls (no messages) this long; 0 disables
    keep_clones: bool = False
    branch: str | None = None  # branch to clone/review; None = each repo's default branch
    resume: bool = True  # skip repos already marked done
    limit: int | None = None  # cap number of repos (smoke tests)
    email_to: list[str] = field(default_factory=list)  # auto-email recipients; empty = no email
    email_provider: str = "custom"  # gmail | o365 | custom (see emailer.py)
    smtp_host: str | None = None
    smtp_port: int | None = None
    email_subject: str | None = None  # None = default findings-summary subject

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)
        self.state_db = Path(self.state_db)

    @property
    def state_target(self) -> "str | Path":
        return self.db_url or self.state_db


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""
