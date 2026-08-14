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
from .github_users import (
    GithubUser,
    OrgAccessError,
    iter_org_members,
    iter_repo_collaborators,
)


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


def redact_url(url: str) -> str:
    """Strip any embedded credentials so a URL is safe to log."""
    return re.sub(r"https://[^@/]+@", "https://***@", url)


def fetch_last_commit(gh, full_name: str) -> tuple[str, str] | None:
    """(sha, ISO date) of the repo's latest default-branch commit, or None if empty/unreadable."""
    from github import GithubException

    try:
        commit = gh.get_repo(full_name).get_commits()[0]
    except (GithubException, IndexError):
        return None  # empty repo (409) or inaccessible
    return commit.sha, commit.commit.committer.date.date().isoformat()


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
            self._integration = GithubIntegration(auth=auth, base_url=self._config.host.api_url)
        return self._integration

    def installation_token(self, installation_id: int) -> str:
        """Mint a fresh ~1h installation access token (used for cloning)."""
        return self.integration.get_access_token(installation_id).token

    def token_for(self, repo: RepoInfo) -> str:
        """Token that can clone this repo (same interface as GithubPatClient)."""
        return self.installation_token(repo.installation_id)

    def last_commit(self, repo: RepoInfo) -> tuple[str, str] | None:
        """(sha, ISO date) of the repo's latest commit (same interface as GithubPatClient)."""
        gh = self.integration.get_github_for_installation(repo.installation_id)
        return fetch_last_commit(gh, repo.full_name)

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

    def installation_for_account(self, login: str):
        """The installation `login` owns, or None if the App is not installed there."""
        for installation in self.integration.get_installations():
            account = getattr(installation, "account", None)
            if account is not None and str(account.login).lower() == login.lower():
                return installation
        return None

    def lookup_repo(self, owner: str, name: str) -> RepoInfo | None:
        """Fetch one repo's metadata via the installation `owner` owns, or None.

        Reaches repos `iter_repositories` did not enumerate (an explicitly added
        target). The RepoInfo carries a real `installation_id`, which is what lets
        `AuthContext.token_for` mint a clone token for it later.
        """
        from github import GithubException

        installation = self.installation_for_account(owner)
        if installation is None:
            return None
        gh = self.integration.get_github_for_installation(installation.id)
        try:
            repo = gh.get_repo(f"{owner}/{name}")
        except GithubException:
            return None
        return RepoInfo.from_github_repo(repo, installation.id)

    def github_for_account(self, login: str):
        """A client scoped to the installation `login` owns.

        The App's own JWT cannot read org members; only an installation token can, so
        the right installation has to be found before any user listing.
        """
        installation = self.installation_for_account(login)
        if installation is None:
            raise OrgAccessError(
                f"the GitHub App has no installation on {login!r}, so it cannot list its "
                "users. Install the App on that organization (with the Organization "
                "permission 'Members: Read'), or use a PAT."
            )
        return self.integration.get_github_for_installation(installation.id)

    def iter_org_members(self, org: str) -> Iterator[GithubUser]:
        """Members of `org` with their role (same interface as GithubPatClient)."""
        return iter_org_members(self.github_for_account(org), org)

    def iter_repo_collaborators(self, full_name: str) -> Iterator[GithubUser]:
        """Collaborators on `owner/name` (same interface as GithubPatClient)."""
        owner = full_name.partition("/")[0]
        return iter_repo_collaborators(self.github_for_account(owner), full_name)
