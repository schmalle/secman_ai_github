from types import SimpleNamespace

import pytest

from secscan.github_users import (
    GithubUser,
    OrgAccessError,
    collaborator_role,
    iter_org_members,
    iter_repo_collaborators,
    user_from_named_user,
)


def _named_user(login="octocat", **kw):
    defaults = dict(
        id=1,
        name="The Octocat",
        email="octocat@example.com",
        type="User",
        site_admin=False,
        html_url=f"https://github.com/{login}",
    )
    defaults.update(kw)
    return SimpleNamespace(login=login, **defaults)


def _permissions(**kw):
    flags = dict(admin=False, maintain=False, push=False, triage=False, pull=False)
    flags.update(kw)
    return SimpleNamespace(**flags)


def _org_gh(members, admins=()):
    """A fake Github whose org returns `members`, and `admins` for role='admin'."""
    admin_users = [m for m in members if m.login in admins]

    def get_members(role=None):
        return admin_users if role == "admin" else members

    return SimpleNamespace(
        get_organization=lambda org: SimpleNamespace(get_members=get_members)
    )


def _repo_gh(collaborators):
    return SimpleNamespace(
        get_repo=lambda full_name: SimpleNamespace(
            get_collaborators=lambda affiliation=None: collaborators
        )
    )


# -- user_from_named_user ---------------------------------------------------------


def test_user_from_named_user_maps_every_field():
    user = user_from_named_user(
        _named_user(), source="org", org="acme", role="admin"
    )
    assert user == GithubUser(
        login="octocat",
        user_id=1,
        name="The Octocat",
        email="octocat@example.com",
        user_type="User",
        site_admin=False,
        source="org",
        org="acme",
        repo="",
        role="admin",
        html_url="https://github.com/octocat",
    )


def test_user_from_named_user_collapses_nulls_to_empty_strings():
    """GitHub nulls name/email for most users; 'None' must never reach the CSV."""
    user = user_from_named_user(
        _named_user(name=None, email=None, type=None), source="org", org="acme"
    )
    assert (user.name, user.email, user.user_type) == ("", "", "")


def test_user_scope_is_org_or_org_slash_repo():
    assert user_from_named_user(_named_user(), source="org", org="acme").scope == "acme"
    member = user_from_named_user(_named_user(), source="repo", org="acme", repo="webapp")
    assert member.scope == "acme/webapp"


# -- collaborator_role ------------------------------------------------------------


def test_collaborator_role_prefers_role_name():
    assert collaborator_role(_named_user(role_name="maintain")) == "maintain"


@pytest.mark.parametrize(
    "flag,expected",
    [("admin", "admin"), ("maintain", "maintain"), ("push", "write"), ("triage", "triage"), ("pull", "read")],
)
def test_collaborator_role_falls_back_to_permission_flags(flag, expected):
    """Older Enterprise Server releases omit role_name; the flags still carry it."""
    user = _named_user(permissions=_permissions(**{flag: True}))
    assert collaborator_role(user) == expected


def test_collaborator_role_prefers_the_most_privileged_flag():
    user = _named_user(permissions=_permissions(admin=True, push=True, pull=True))
    assert collaborator_role(user) == "admin"


def test_collaborator_role_empty_without_role_name_or_permissions():
    assert collaborator_role(_named_user()) == ""


# -- iter_org_members -------------------------------------------------------------


def test_iter_org_members_tags_admins_and_members():
    gh = _org_gh([_named_user("alice"), _named_user("bob")], admins={"alice"})

    users = list(iter_org_members(gh, "acme"))

    assert [(u.login, u.role, u.source, u.org, u.repo) for u in users] == [
        ("alice", "admin", "org", "acme", ""),
        ("bob", "member", "org", "acme", ""),
    ]


def test_iter_org_members_matches_admins_case_insensitively():
    gh = _org_gh([_named_user("Alice")], admins={"Alice"})
    assert [u.role for u in iter_org_members(gh, "acme")] == ["admin"]


def test_iter_org_members_raises_org_access_error_for_a_personal_account():
    from github import GithubException

    def _boom(org):
        raise GithubException(404, {"message": "Not Found"}, {})

    gh = SimpleNamespace(get_organization=_boom)
    with pytest.raises(OrgAccessError) as exc:
        list(iter_org_members(gh, "some-person"))
    assert "only for organizations" in str(exc.value)
    assert "some-person" in str(exc.value)


def test_iter_org_members_raises_org_access_error_when_forbidden():
    from github import GithubException

    def _boom(org):
        raise GithubException(403, {"message": "Must have admin rights"}, {})

    with pytest.raises(OrgAccessError, match="read:org"):
        list(iter_org_members(SimpleNamespace(get_organization=_boom), "acme"))


# -- iter_repo_collaborators ------------------------------------------------------


def test_iter_repo_collaborators_carries_permission_and_scope():
    gh = _repo_gh([_named_user("alice", role_name="admin"), _named_user("bob", role_name="read")])

    users = list(iter_repo_collaborators(gh, "acme/webapp"))

    assert [(u.login, u.role, u.source, u.org, u.repo) for u in users] == [
        ("alice", "admin", "repo", "acme", "webapp"),
        ("bob", "read", "repo", "acme", "webapp"),
    ]


def test_iter_repo_collaborators_raises_org_access_error():
    from github import GithubException

    def _boom(full_name):
        raise GithubException(403, {"message": "Resource not accessible"}, {})

    with pytest.raises(OrgAccessError, match="acme/webapp"):
        list(iter_repo_collaborators(SimpleNamespace(get_repo=_boom), "acme/webapp"))
