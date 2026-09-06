import json
from pathlib import Path

import pytest

from secscan import dryrun
from secscan.findings import Finding
from secscan.github_app import RepoInfo
from secscan.integration_results import (
    IntegrationClient,
    IntegrationContext,
    IntegrationSubject,
    build_run_body,
    finding_external_id,
    match_subject,
    push_stored_records,
)
import secscan.orchestrator as orchestrator
from secscan.config import GithubHost, RunConfig
from secscan.providers import ProviderEnv
from secscan.reviewer import ReviewResult
from secscan.state import StateStore


def _repo(*, repo_id=123, owner="octo", name="demo"):
    return RepoInfo(
        owner=owner,
        name=name,
        full_name=f"{owner}/{name}",
        archived=False,
        fork=False,
        size_kb=1,
        default_branch="main",
        clone_url=f"https://github.example.com/{owner}/{name}.git",
        installation_id=1,
        github_repo_id=repo_id,
    )


def _subject(*, subject_id=7, repo_id=123, instance="https://github.example.com"):
    return IntegrationSubject(
        id=subject_id,
        scanner_id=9,
        asset_id=42,
        github_repository_id=81,
        name="octo/demo",
        uri="https://github.example.com/octo/demo",
        owner="owner@example.com",
        github_instance=instance,
        github_repo_id=repo_id,
    )


def _finding(**overrides):
    values = {
        "severity": "high",
        "title": "SQL injection",
        "description": "A query includes untrusted input.",
        "recommendation": "Bind the parameter.",
        "category": "CWE-89",
        "file_path": "src/db.py",
        "line_range": "10-12",
        "confidence": "high",
    }
    values.update(overrides)
    return Finding(**values)


def test_rich_success_body_uses_v1_shape_and_incomplete_coverage():
    body = build_run_body(
        scanner_id=9,
        subject=_subject(),
        status="SUCCESS",
        findings=[_finding()],
        started_at="2026-09-06T10:00:00Z",
        completed_at="2026-09-06T10:01:00Z",
        metadata={"repository": "octo/demo"},
        engine="codex",
        model="gpt-5",
        commit_sha="abc123",
        issue_urls={finding_external_id(_finding()): "https://github.example.com/octo/demo/issues/3"},
        fix_pr_url="https://github.example.com/octo/demo/pull/4",
    )

    assert body["scannerId"] == 9
    assert body["subjectId"] == 7
    assert body["status"] == "SUCCESS"
    assert body["completeCoverage"] is False
    assert json.loads(body["metadataJson"]) == {"repository": "octo/demo"}
    assert body["findings"] == [{
        "externalId": finding_external_id(_finding()),
        "legacyIds": [],
        "severity": "HIGH",
        "title": "SQL injection",
        "description": "A query includes untrusted input.",
        "recommendation": "Bind the parameter.",
        "evidence": "A query includes untrusted input.",
        "filePath": "src/db.py",
        "lineRange": "10-12",
        "url": None,
        "confidence": 0.9,
        "engine": "codex",
        "model": "gpt-5",
        "commitSha": "abc123",
        "issueUrl": "https://github.example.com/octo/demo/issues/3",
        "fixPrUrl": "https://github.example.com/octo/demo/pull/4",
        "attachments": [],
    }]


def test_zero_finding_success_is_still_submitted():
    body = build_run_body(
        scanner_id=9,
        subject=_subject(),
        status="SUCCESS",
        findings=[],
        started_at="2026-09-06T10:00:00Z",
        completed_at="2026-09-06T10:01:00Z",
    )
    assert body["findings"] == []
    assert body["completeCoverage"] is False


def test_failed_scan_has_no_findings_and_never_claims_coverage():
    body = build_run_body(
        scanner_id=9,
        subject=_subject(),
        status="FAILED",
        findings=[_finding()],
        started_at="2026-09-06T10:00:00Z",
        completed_at="2026-09-06T10:01:00Z",
        metadata={"outcome": "review failed"},
    )
    assert body["status"] == "FAILED"
    assert body["findings"] == []
    assert body["completeCoverage"] is False


def test_external_id_ignores_mutable_title_severity_and_description():
    original = _finding()
    changed = _finding(
        severity="critical",
        title="Renamed finding",
        description="Reworded details.",
    )
    assert finding_external_id(original) == finding_external_id(changed)


def test_external_id_distinguishes_two_locations_for_the_same_rule():
    assert finding_external_id(_finding(line_range="10-12")) != finding_external_id(
        _finding(line_range="50-60")
    )


def test_external_id_preserves_case_sensitive_git_paths():
    assert finding_external_id(_finding(file_path="src/Auth.py")) != finding_external_id(
        _finding(file_path="src/auth.py")
    )


def test_subject_match_requires_same_enterprise_instance_and_numeric_repo_id():
    repo = _repo()
    right = _subject(subject_id=1)
    wrong_host = _subject(subject_id=2, instance="https://other.example.com")
    wrong_id = _subject(subject_id=3, repo_id=999)

    assert match_subject([wrong_host, wrong_id, right], repo, "https://github.example.com") == right
    assert match_subject([wrong_host], repo, "https://github.example.com") is None


def test_subject_match_canonicalizes_default_https_port_and_ghe_api_host():
    repo = _repo()
    subject = _subject(instance="https://api.acme.ghe.com:443")
    assert match_subject([subject], repo, "https://acme.ghe.com") == subject


def test_subject_match_rejects_non_https_or_nondefault_port_identity():
    repo = _repo()
    assert match_subject(
        [_subject(instance="http://github.example.com")], repo, "https://github.example.com"
    ) is None


def test_subject_with_numeric_id_does_not_fall_back_to_mutable_name():
    repo = _repo(repo_id=None)
    assert match_subject([_subject()], repo, "https://github.example.com") is None
    assert match_subject(
        [_subject(instance="https://github.example.com:8443")], repo, "https://github.example.com"
    ) is None


def test_run_key_is_deterministic_for_the_same_contents():
    kwargs = dict(
        scanner_id=9,
        subject=_subject(),
        status="SUCCESS",
        findings=[_finding()],
        started_at="2026-09-06T10:00:00Z",
        completed_at="2026-09-06T10:01:00Z",
        metadata={"b": 2, "a": 1},
    )
    first = build_run_body(**kwargs)
    second = build_run_body(**kwargs)
    assert first["runKey"] == second["runKey"]
    assert first == second


def test_run_key_is_independent_of_finding_order():
    common = dict(
        scanner_id=9,
        subject=_subject(),
        status="SUCCESS",
        started_at="2026-09-06T10:00:00Z",
        completed_at="2026-09-06T10:01:00Z",
    )
    one = _finding(file_path="src/one.py")
    two = _finding(file_path="src/two.py")
    assert build_run_body(findings=[one, two], **common) == build_run_body(
        findings=[two, one], **common
    )


def test_committed_v1_fixture_pins_request_field_names_and_types():
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "integration-run-v1.json").read_text()
    )
    body = build_run_body(
        scanner_id=1,
        subject=_subject(subject_id=2),
        status="SUCCESS",
        findings=[_finding()],
        started_at="2026-09-06T10:00:00Z",
        completed_at="2026-09-06T10:01:00Z",
    )

    assert set(body) == set(fixture)
    assert {key: type(value) for key, value in body.items()} == {
        key: type(value) for key, value in fixture.items()
    }
    assert set(body["findings"][0]) == set(fixture["findings"][0])
    mandatory_strings = {
        "externalId", "severity", "title", "description", "recommendation", "evidence",
    }
    nullable_strings = {
        "filePath", "lineRange", "url", "engine", "model", "commitSha", "issueUrl", "fixPrUrl",
    }
    for request in (fixture["findings"][0], body["findings"][0]):
        assert all(isinstance(request[key], str) for key in mandatory_strings)
        assert all(request[key] is None or isinstance(request[key], str) for key in nullable_strings)
        assert isinstance(request["confidence"], (int, float))
        assert isinstance(request["legacyIds"], list)
        assert isinstance(request["attachments"], list)
    assert set(fixture["findings"][0]["attachments"][0]) == {
        "fileName", "contentType", "base64"
    }


def test_integration_client_paginates_subject_inventory(monkeypatch):
    calls = []

    class Response:
        status_code = 200

        def __init__(self, body):
            self._body = body

        def json(self):
            return self._body

    pages = [
        {"content": [{
            "id": 7, "scannerId": 9, "assetId": 42, "githubRepositoryId": 81,
            "name": "octo/demo", "uri": "https://github.example.com/octo/demo",
            "owner": "owner@example.com", "githubInstance": "https://github.example.com",
            "githubRepoId": 123,
        }], "totalElements": 2, "totalPages": 2, "number": 0, "size": 1},
        {"content": [{
            "id": 8, "scannerId": 9, "assetId": 43, "githubRepositoryId": 82,
            "name": "octo/other", "uri": "https://github.example.com/octo/other",
            "owner": None, "githubInstance": "https://github.example.com",
            "githubRepoId": 124,
        }], "totalElements": 2, "totalPages": 2, "number": 1, "size": 1},
    ]

    def fake_get(url, headers, params, timeout, allow_redirects):
        calls.append((url, headers, params, allow_redirects))
        return Response(pages[params["page"]])

    monkeypatch.setattr("secscan.integration_results.requests.get", fake_get)
    subjects = IntegrationClient("https://secman.example.com", "token").list_subjects(9, size=1)

    assert [s.id for s in subjects] == [7, 8]
    assert all(call[3] is False for call in calls)
    assert calls[0][1] == {"Authorization": "Bearer token"}


def test_dry_run_guard_blocks_run_submission_before_http(monkeypatch):
    called = []
    monkeypatch.setattr(
        "secscan.integration_results.requests.post",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )
    dryrun.activate()

    with pytest.raises(dryrun.DryRunViolation):
        IntegrationClient("https://secman.example.com", "token").submit_run({"runKey": "same"})

    assert called == []


def test_stored_push_reuses_exact_persisted_payload(tmp_path, monkeypatch):
    submitted = []
    body = build_run_body(
        scanner_id=9,
        subject=_subject(),
        status="PARTIAL",
        findings=[_finding()],
        started_at="2026-09-06T10:00:00Z",
        completed_at="2026-09-06T10:01:00Z",
        metadata={"engine": "original"},
        engine="codex",
        model="gpt-5",
        fix_pr_url="https://github.example.com/octo/demo/pull/4",
    )
    store = StateStore(tmp_path / "state.sqlite3")
    store.record_result(
        "octo", "demo", critical=1, high=0, total=1, duration_s=1,
        cost_usd=0, reviewed_at="different-time",
    )
    store.record_github_identity("octo", "demo", "https://github.example.com", 123)
    store.record_integration_payload("octo", "demo", 9, body)

    class Client:
        def __init__(self, url, token):
            pass

        def list_subjects(self, scanner_id):
            return [_subject()]

        def submit_run(self, value):
            submitted.append(value)
            return {"id": 1}

    monkeypatch.setattr("secscan.secman_client.login", lambda *args: "token")
    monkeypatch.setattr("secscan.integration_results.IntegrationClient", Client)

    pushed, failed = push_stored_records(
        store,
        url="https://secman.example.com",
        username="scanner",
        password="pw",
        scanner_id=9,
        github_instance="https://github.example.com",
        dry_run=False,
    )

    assert (pushed, failed) == (1, 0)
    assert submitted == [body]


async def test_process_repo_submits_zero_finding_success(tmp_path, monkeypatch):
    submitted = []

    class Client:
        def submit_run(self, body):
            submitted.append(body)
            return {"id": 1, "accepted": 0, "resolved": 0, "replayed": False}

    async def fake_mint(auth, repo):
        return "github-token"

    async def fake_clone(repo, token, root, branch=None):
        return tmp_path / "clone"

    async def fake_head(path):
        return ("abc123", "2026-09-06")

    async def fake_review(*args, **kwargs):
        return ReviewResult()

    monkeypatch.setattr(orchestrator, "_mint_token", fake_mint)
    monkeypatch.setattr(orchestrator, "_clone", fake_clone)
    monkeypatch.setattr(orchestrator, "head_commit", fake_head)
    monkeypatch.setattr(orchestrator, "_review", fake_review)
    monkeypatch.setattr(orchestrator, "cleanup", lambda path: None)

    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "state.sqlite3")
    cfg.integration_context = IntegrationContext(
        scanner_id=9,
        github_instance="https://github.example.com",
        subjects=[_subject()],
        client=Client(),
    )
    store = StateStore(cfg.state_target)

    await orchestrator._process_repo(
        _repo(), object(), store, cfg, __import__("asyncio").Semaphore(1), ProviderEnv(name="anthropic")
    )

    assert len(submitted) == 1
    assert submitted[0]["status"] == "SUCCESS"
    assert submitted[0]["findings"] == []
    assert submitted[0]["completeCoverage"] is False
    assert store.get("octo", "demo").github_repo_id == 123
    assert store.get_integration_payload("octo", "demo", 9) == submitted[0]


async def test_process_repo_submits_failed_terminal_outcome(tmp_path, monkeypatch):
    submitted = []

    class Client:
        def submit_run(self, body):
            submitted.append(body)
            return {"id": 1, "accepted": 0, "resolved": 0, "replayed": False}

    async def fail_mint(auth, repo):
        raise RuntimeError("clone token unavailable")

    monkeypatch.setattr(orchestrator, "_mint_token", fail_mint)
    cfg = RunConfig(output_dir=tmp_path, state_db=tmp_path / "state.sqlite3")
    cfg.integration_context = IntegrationContext(
        scanner_id=9,
        github_instance="https://github.example.com",
        subjects=[_subject()],
        client=Client(),
    )
    store = StateStore(cfg.state_target)

    result = await orchestrator._process_repo(
        _repo(), object(), store, cfg, __import__("asyncio").Semaphore(1), ProviderEnv(name="anthropic")
    )

    assert result == (0, 0)
    assert len(submitted) == 1
    assert submitted[0]["status"] == "FAILED"
    assert submitted[0]["findings"] == []


def test_prepare_integration_dry_run_makes_no_login_or_inventory_calls(monkeypatch):
    called = []
    monkeypatch.setattr(
        "secscan.secman_client.login", lambda *args: called.append(args) or "token"
    )
    cfg = RunConfig(
        push_to_secman=True,
        secman_scanner_id=9,
        dry_run=True,
    )

    context = orchestrator._prepare_integration(cfg, GithubHost(web_url="https://github.example.com"))

    assert context is None
    assert called == []


async def test_run_scan_submits_skipped_for_resumed_permitted_repo(tmp_path, monkeypatch):
    submitted = []

    class Client:
        def submit_run(self, body):
            submitted.append(body)
            return {"id": 1, "accepted": 0, "resolved": 0, "replayed": False}

    class App:
        def iter_repositories(self, org=None, filters=None):
            return iter([_repo()])

    class Auth:
        app = App()
        pat = None
        host = GithubHost(api_url="https://github.example.com/api/v3", web_url="https://github.example.com")

    context = IntegrationContext(
        scanner_id=9,
        github_instance="https://github.example.com",
        subjects=[_subject()],
        client=Client(),
    )
    monkeypatch.setattr(orchestrator, "build_auth", lambda api_url=None: Auth())
    monkeypatch.setattr(orchestrator, "_prepare_integration", lambda cfg, host: context)
    monkeypatch.setattr(orchestrator, "_resolve_provider_env", lambda cfg: ProviderEnv(name="anthropic"))

    cfg = RunConfig(
        output_dir=tmp_path,
        state_db=tmp_path / "state.sqlite3",
        push_to_secman=True,
        secman_scanner_id=9,
        secman_url="https://secman.example.com",
        secman_username="scanner",
        secman_password="pw",
    )
    store = StateStore(cfg.state_target)
    store.record_result(
        "octo", "demo", critical=0, high=0, total=0, duration_s=1,
        cost_usd=0, reviewed_at="2026-09-06T10:00:00Z",
    )
    store.close()

    await orchestrator.run_scan(cfg)

    assert len(submitted) == 1
    assert submitted[0]["status"] == "SKIPPED"
    assert submitted[0]["findings"] == []
