"""GitHub App authentication and repository enumeration.

Uses PyGithub's App-auth flow: a short-lived App JWT is minted from the App private
key, installations are listed, and a 1-hour installation access token is created per
installation to list (and later clone) its repositories.

Tokens are short-lived and never logged; `redact_url` strips them from any URL we log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from .config import Filters, GithubAppConfig


@dataclass
class RepoInfo:
    owner: str
    name: str
    full_name: str
    archived: bool
    fork: bool
    size_kb: int
    default_branch: str
    clone_url: str
    installation_id: int

    @classmethod
    def from_github_repo(cls, repo, installation_id: int) -> "RepoInfo":
        return cls(
            owner=repo.owner.login,
            name=repo.name,
            full_name=repo.full_name,
            archived=bool(repo.archived),
            fork=bool(repo.fork),
            size_kb=int(repo.size or 0),
            default_branch=repo.default_branch or "",
            clone_url=repo.clone_url,
            installation_id=installation_id,
        )


def should_include(repo: RepoInfo, filters: Filters, org: str | None) -> bool:
    """Pure predicate deciding whether a repo is in scope."""
    if org and repo.owner.lower() != org.lower():
        return False
    if repo.archived and not filters.include_archived:
        return False
    if repo.fork and not filters.include_forks:
        return False
    if filters.max_size_mb > 0 and repo.size_kb / 1024 > filters.max_size_mb:
        return False
    return True


def authed_clone_url(clone_url: str, token: str) -> str:
    """Insert an installation token into an https clone URL for git authentication."""
    return clone_url.replace("https://", f"https://x-access-token:{token}@", 1)


def redact_url(url: str) -> str:
    """Strip any embedded credentials so a URL is safe to log."""
    return re.sub(r"https://[^@/]+@", "https://***@", url)


class GithubAppClient:
    """Thin wrapper over PyGithub's GithubIntegration for App-scoped access."""

    def __init__(self, config: GithubAppConfig):
        self._config = config
        self._integration = None  # lazy: avoids importing PyGithub until needed

    @property
    def integration(self):
        if self._integration is None:
            from github import Auth, GithubIntegration

            auth = Auth.AppAuth(self._config.app_id, self._config.private_key)
            self._integration = GithubIntegration(auth=auth)
        return self._integration

    def installation_token(self, installation_id: int) -> str:
        """Mint a fresh ~1h installation access token (used for cloning)."""
        return self.integration.get_access_token(installation_id).token

    def _iter_raw_repos(self) -> Iterator[RepoInfo]:
        """Yield every repository reachable across all installations (unfiltered)."""
        for installation in self.integration.get_installations():
            for repo in installation.get_repos():
                yield RepoInfo.from_github_repo(repo, installation.id)

    def iter_repositories(
        self, org: str | None = None, filters: Filters | None = None
    ) -> Iterator[RepoInfo]:
        filters = filters or Filters()
        for repo in self._iter_raw_repos():
            if should_include(repo, filters, org):
                yield repo
