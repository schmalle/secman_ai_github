"""Username extraction from GitHub organizations and repositories.

Two listings, both **organization-only** — GitHub exposes no equivalent for a personal
account, so `GET /orgs/{login}/members` 404s when `login` is a user:

- **org members** (`GET /orgs/{org}/members`) with their org role (`admin` / `member`)
- **repo collaborators** (`GET /repos/{owner}/{repo}/collaborators`) with their permission
  level (`admin` / `maintain` / `write` / `triage` / `read`)

The endpoints are identical across every GitHub deployment — public/Enterprise Cloud,
Enterprise Cloud with data residency, and Enterprise Server. Only the API host differs,
and that is settled before we get here (see `config.normalize_github_urls`).

Like `github_app.fetch_last_commit` and `issues.py`, the functions here take an
already-authenticated PyGithub client rather than credentials, so they carry no auth
knowledge and are trivial to test with a fake.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

SOURCE_ORG = "org"
SOURCE_REPO = "repo"

# Repo permission flags, most privileged first: the first one set wins. Used only when
# GitHub does not return `role_name` (older Enterprise Server releases omit it).
_PERMISSION_ROLES = (
    ("admin", "admin"),
    ("maintain", "maintain"),
    ("push", "write"),
    ("triage", "triage"),
    ("pull", "read"),
)


class OrgAccessError(Exception):
    """The user listing could not be read — usually not an org, or the token can't see it."""


@dataclass
class GithubUser:
    """One username discovered in an organization or on one of its repositories."""

    login: str
    user_id: int = 0
    name: str = ""  # GitHub returns null for users with no display name
    email: str = ""  # almost always null unless the caller is an org owner
    user_type: str = ""  # "User" | "Bot"
    site_admin: bool = False
    source: str = SOURCE_ORG  # SOURCE_ORG | SOURCE_REPO
    org: str = ""  # org login; for repo rows, the repo owner
    repo: str = ""  # "" for org members
    role: str = ""  # org: admin|member — repo: admin|maintain|write|triage|read
    html_url: str = ""

    @property
    def scope(self) -> str:
        """`org` or `org/repo` — where this username was found."""
        return f"{self.org}/{self.repo}" if self.repo else self.org


def _text(value) -> str:
    """GitHub omits or nulls most profile fields; store '' rather than the string 'None'."""
    return "" if value is None else str(value)


def collaborator_role(named_user) -> str:
    """Permission level of a repo collaborator, from `role_name` or the permission flags."""
    role = getattr(named_user, "role_name", None)
    if role:
        return str(role)
    permissions = getattr(named_user, "permissions", None)
    for flag, name in _PERMISSION_ROLES:
        if getattr(permissions, flag, False):
            return name
    return ""


def user_from_named_user(
    named_user, *, source: str, org: str, repo: str = "", role: str = ""
) -> GithubUser:
    """Map a PyGithub NamedUser onto our record. Pure — no API calls."""
    return GithubUser(
        login=_text(named_user.login),
        user_id=int(getattr(named_user, "id", 0) or 0),
        name=_text(getattr(named_user, "name", "")),
        email=_text(getattr(named_user, "email", "")),
        user_type=_text(getattr(named_user, "type", "")),
        site_admin=bool(getattr(named_user, "site_admin", False)),
        source=source,
        org=org,
        repo=repo,
        role=role,
        html_url=_text(getattr(named_user, "html_url", "")),
    )


def _org_access_error(scope: str, exc: Exception) -> OrgAccessError:
    return OrgAccessError(
        f"cannot list users for {scope!r}: {exc}. These endpoints exist only for "
        "organizations — a personal account has no members — and the credential must be "
        "able to see them: a PAT held by an org member with the 'read:org' scope "
        "(classic) or read access to Members (fine-grained), or a GitHub App with the "
        "Organization permission 'Members: Read'."
    )


def iter_org_members(gh, org: str) -> Iterator[GithubUser]:
    """Yield every member of `org`, tagged `admin` or `member`.

    Costs two paginated listings, not one request per user: the admin listing is read
    first and used as a lookup while walking the full member listing.
    """
    from github import GithubException

    try:
        organization = gh.get_organization(org)
        admins = {u.login.lower() for u in organization.get_members(role="admin")}
        members = list(organization.get_members())
    except GithubException as exc:
        raise _org_access_error(org, exc) from exc

    for member in members:
        role = "admin" if _text(member.login).lower() in admins else "member"
        yield user_from_named_user(member, source=SOURCE_ORG, org=org, role=role)


def iter_repo_collaborators(gh, full_name: str) -> Iterator[GithubUser]:
    """Yield every collaborator on `owner/name`, tagged with their permission level."""
    from github import GithubException

    owner, _, repo_name = full_name.partition("/")
    try:
        collaborators = list(gh.get_repo(full_name).get_collaborators(affiliation="all"))
    except GithubException as exc:
        raise _org_access_error(full_name, exc) from exc

    for collaborator in collaborators:
        yield user_from_named_user(
            collaborator,
            source=SOURCE_REPO,
            org=owner,
            repo=repo_name,
            role=collaborator_role(collaborator),
        )
