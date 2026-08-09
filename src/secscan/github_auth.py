"""GitHub authentication front-door: App and/or personal access token (PAT).

Two credential sources can coexist:

- GitHub App (`GITHUB_APP_ID` + private key): enumerates every reachable repo and
  mints short-lived installation tokens for cloning (see `github_app.py`).
- PAT (`GITHUB_TOKEN`): authenticates as a user/bot. Used to clone explicitly-added
  targets the App cannot reach, and to enumerate token-accessible repos.

`AuthContext` picks the right credential per repo: repos discovered through an App
installation carry its `installation_id`; explicit targets use `installation_id=0`
as the "clone with the PAT" sentinel.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from .config import (
    ConfigError,
    Filters,
    GithubAppConfig,
    GithubHost,
    GithubPatConfig,
    _env,
)
from .github_app import GithubAppClient, RepoInfo, fetch_last_commit, should_include
from .github_users import GithubUser, iter_org_members, iter_repo_collaborators


class GithubPatClient:
    """Thin wrapper over PyGithub token auth for PAT-scoped access."""

    def __init__(self, config: GithubPatConfig):
        self._config = config
        self._gh = None  # lazy: avoids importing PyGithub until needed

    @property
    def gh(self):
        if self._gh is None:
            from github import Auth, Github

            self._gh = Github(auth=Auth.Token(self._config.token), base_url=self._config.host.api_url)
        return self._gh

    def token_for(self, repo: RepoInfo) -> str:
        """The PAT itself; unlike installation tokens it needs no per-repo minting."""
        return self._config.token

    def iter_repositories(
        self, org: str | None = None, filters: Filters | None = None
    ) -> Iterator[RepoInfo]:
        """Yield repos accessible to the token, applying the standard filters."""
        filters = filters or Filters()
        for repo in self.gh.get_user().get_repos():
            info = RepoInfo.from_github_repo(repo, installation_id=0)
            if should_include(info, filters, org):
                yield info

    def last_commit(self, repo: RepoInfo) -> tuple[str, str] | None:
        """(sha, ISO date) of the repo's latest commit (same interface as GithubAppClient)."""
        return fetch_last_commit(self.gh, repo.full_name)

    def lookup_repo(self, owner: str, name: str) -> RepoInfo | None:
        """Fetch one repo's metadata, or None if the token cannot see it."""
        from github import GithubException

        try:
            repo = self.gh.get_repo(f"{owner}/{name}")
        except GithubException:
            return None
        return RepoInfo.from_github_repo(repo, installation_id=0)

    def iter_org_members(self, org: str) -> Iterator[GithubUser]:
        """Members of `org` with their role (same interface as GithubAppClient)."""
        return iter_org_members(self.gh, org)

    def iter_repo_collaborators(self, full_name: str) -> Iterator[GithubUser]:
        """Collaborators on `owner/name` (same interface as GithubAppClient)."""
        return iter_repo_collaborators(self.gh, full_name)


@dataclass
class AuthContext:
    """Whichever GitHub credentials are configured (at least one), and which GitHub."""

    app: GithubAppClient | None = None
    pat: GithubPatClient | None = None
    host: GithubHost = field(default_factory=GithubHost)

    def token_for(self, repo: RepoInfo) -> str:
        """Token that can clone this repo: App installation token, else the PAT."""
        if repo.installation_id and self.app:
            return self.app.token_for(repo)
        if self.pat:
            return self.pat.token_for(repo)
        raise ConfigError(f"no credentials can clone {repo.full_name}")


def build_auth(api_url: str | None = None) -> AuthContext:
    """Build the auth context from the environment (App and/or PAT).

    `api_url` selects the GitHub deployment (Enterprise Cloud, Enterprise Cloud with
    data residency, or Enterprise Server). It beats `GITHUB_API_URL`, which in turn
    beats the public/Enterprise Cloud default. See `config.normalize_github_urls`.
    """
    host = GithubHost.resolve(api_url)
    app = GithubAppClient(GithubAppConfig.from_env(api_url)) if _env("GITHUB_APP_ID") else None
    pat = GithubPatClient(GithubPatConfig.from_env(api_url)) if _env("GITHUB_TOKEN") else None
    if app is None and pat is None:
        raise ConfigError(
            "GitHub credentials required: set GITHUB_APP_ID (+ private key) or GITHUB_TOKEN"
        )
    return AuthContext(app=app, pat=pat, host=host)


def resolve_target(owner: str, name: str, auth: AuthContext) -> RepoInfo:
    """Best-effort RepoInfo for an explicit target not covered by App enumeration."""
    if auth.pat:
        info = auth.pat.lookup_repo(owner, name)
        if info:
            return info
    return RepoInfo(
        owner=owner,
        name=name,
        full_name=f"{owner}/{name}",
        archived=False,
        fork=False,
        size_kb=0,
        default_branch="",
        # The web host, not the API host — Enterprise Server and data-residency tenants
        # serve git from a different hostname than api.github.com.
        clone_url=f"{auth.host.web_url}/{owner}/{name}.git",
        installation_id=0,
    )
