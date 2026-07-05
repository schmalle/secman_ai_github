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

from dataclasses import dataclass
from typing import Iterator

from .config import ConfigError, Filters, GithubAppConfig, GithubPatConfig, _env
from .github_app import GithubAppClient, RepoInfo, should_include


class GithubPatClient:
    """Thin wrapper over PyGithub token auth for PAT-scoped access."""

    def __init__(self, config: GithubPatConfig):
        self._config = config
        self._gh = None  # lazy: avoids importing PyGithub until needed

    @property
    def gh(self):
        if self._gh is None:
            from github import Auth, Github

            self._gh = Github(auth=Auth.Token(self._config.token))
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

    def lookup_repo(self, owner: str, name: str) -> RepoInfo | None:
        """Fetch one repo's metadata, or None if the token cannot see it."""
        from github import GithubException

        try:
            repo = self.gh.get_repo(f"{owner}/{name}")
        except GithubException:
            return None
        return RepoInfo.from_github_repo(repo, installation_id=0)


@dataclass
class AuthContext:
    """Whichever GitHub credentials are configured (at least one)."""

    app: GithubAppClient | None = None
    pat: GithubPatClient | None = None

    def token_for(self, repo: RepoInfo) -> str:
        """Token that can clone this repo: App installation token, else the PAT."""
        if repo.installation_id and self.app:
            return self.app.token_for(repo)
        if self.pat:
            return self.pat.token_for(repo)
        raise ConfigError(f"no credentials can clone {repo.full_name}")


def build_auth() -> AuthContext:
    """Build the auth context from the environment (App and/or PAT)."""
    app = GithubAppClient(GithubAppConfig.from_env()) if _env("GITHUB_APP_ID") else None
    pat = GithubPatClient(GithubPatConfig.from_env()) if _env("GITHUB_TOKEN") else None
    if app is None and pat is None:
        raise ConfigError(
            "GitHub credentials required: set GITHUB_APP_ID (+ private key) or GITHUB_TOKEN"
        )
    return AuthContext(app=app, pat=pat)


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
        clone_url=f"https://github.com/{owner}/{name}.git",
        installation_id=0,
    )
