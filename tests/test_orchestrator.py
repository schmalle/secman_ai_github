from secscan.github_app import RepoInfo
from secscan.orchestrator import _merge_scope


def _repo(owner="octo", name="repo", installation_id=1):
    return RepoInfo(
        owner=owner,
        name=name,
        full_name=f"{owner}/{name}",
        archived=False,
        fork=False,
        size_kb=100,
        default_branch="main",
        clone_url=f"https://github.com/{owner}/{name}.git",
        installation_id=installation_id,
    )


def test_merge_scope_no_allowlist_no_targets():
    repos = [_repo(name="a"), _repo(name="b")]
    in_scope, unresolved = _merge_scope(repos, None, [])
    assert in_scope == repos
    assert unresolved == []


def test_merge_scope_allowlist_filters_enumerated():
    repos = [_repo(name="keep"), _repo(name="drop")]
    in_scope, unresolved = _merge_scope(repos, {"octo/keep"}, [])
    assert [r.full_name for r in in_scope] == ["octo/keep"]
    assert unresolved == []


def test_merge_scope_targets_add_unresolved():
    repos = [_repo(name="a")]
    in_scope, unresolved = _merge_scope(repos, None, [("other", "explicit")])
    assert in_scope == repos
    assert unresolved == [("other", "explicit")]


def test_merge_scope_enumerated_target_not_duplicated():
    repos = [_repo(name="a")]
    in_scope, unresolved = _merge_scope(repos, None, [("octo", "a")])
    assert in_scope == repos
    assert unresolved == []


def test_merge_scope_allowlist_entry_not_enumerated_goes_unresolved():
    in_scope, unresolved = _merge_scope([], {"octo/wanted"}, [])
    assert in_scope == []
    assert unresolved == [("octo", "wanted")]


def test_merge_scope_target_and_allowlist_deduped():
    in_scope, unresolved = _merge_scope([], {"octo/one"}, [("octo", "one")])
    assert unresolved == [("octo", "one")]
