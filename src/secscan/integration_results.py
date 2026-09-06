"""Version-1 SecMan integration-result client and GitHub finding mapper.

This is the opt-in transport selected by ``SECMAN_SCANNER_ID``.  The legacy
``cli-add`` integration remains in :mod:`secscan.secman_push`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

import requests

from . import dryrun
from .findings import Finding
from .github_app import RepoInfo

_TIMEOUT_S = 30
_CONFIDENCE = {"high": 0.9, "medium": 0.7, "low": 0.5}
_TERMINAL_WITHOUT_FINDINGS = {"FAILED", "SKIPPED"}


class IntegrationResultError(Exception):
    """Raised when the version-1 API rejects or cannot decode a request."""


@dataclass(frozen=True)
class IntegrationSubject:
    id: int
    scanner_id: int
    asset_id: int
    github_repository_id: int | None
    name: str
    uri: str | None
    owner: str | None
    github_instance: str | None
    github_repo_id: int | None

    @classmethod
    def from_api(cls, value: Mapping[str, Any]) -> "IntegrationSubject":
        return cls(
            id=int(value["id"]),
            scanner_id=int(value["scannerId"]),
            asset_id=int(value["assetId"]),
            github_repository_id=_optional_int(value.get("githubRepositoryId")),
            name=str(value["name"]),
            uri=_optional_str(value.get("uri")),
            owner=_optional_str(value.get("owner")),
            github_instance=_optional_str(value.get("githubInstance")),
            github_repo_id=_optional_int(value.get("githubRepoId")),
        )


@dataclass(frozen=True)
class IntegrationContext:
    scanner_id: int
    github_instance: str
    subjects: list[IntegrationSubject]
    client: "IntegrationClient"


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


def validate_base_url(value: str | None) -> str:
    """Validate an operator-configured SecMan origin and remove a trailing slash."""
    if not value:
        raise IntegrationResultError("secman URL must be an absolute https URL")
    parts = urlsplit(value.strip())
    if parts.scheme != "https" or not parts.hostname:
        raise IntegrationResultError("secman URL must be an absolute https URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise IntegrationResultError("secman URL must not contain credentials, query, or fragment")
    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", ""))


def _github_instance(value: str | None) -> str | None:
    """Canonical host identity for public GitHub, GHE Cloud, or GHES."""
    if not value:
        return None
    raw = value.strip()
    parts = urlsplit(raw if "://" in raw else f"https://{raw}")
    if parts.scheme.lower() != "https":
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    if host == "api.github.com":
        host = "github.com"
    elif host.startswith("api.") and host.endswith(".ghe.com"):
        host = host[len("api.") :]
    port = f":{parts.port}" if parts.port and parts.port != 443 else ""
    return f"{host}{port}"


def subject_repository_full_name(subject: IntegrationSubject) -> str | None:
    if subject.uri:
        parts = urlsplit(subject.uri)
        segments = [part for part in parts.path.strip("/").split("/") if part]
        if len(segments) == 2:
            return f"{segments[0]}/{segments[1].removesuffix('.git')}".lower()
    return subject.name.lower() if subject.name.count("/") == 1 else None


def same_github_instance(left: str | None, right: str | None) -> bool:
    """Whether two GitHub instance URLs name the same canonical HTTPS host."""
    canonical = _github_instance(left)
    return canonical is not None and canonical == _github_instance(right)


def match_subject(
    subjects: Iterable[IntegrationSubject],
    repo: RepoInfo,
    github_instance: str,
) -> IntegrationSubject | None:
    """Find the permitted subject for a repository without crossing GitHub instances."""
    wanted_name = repo.full_name.lower()
    for subject in subjects:
        if not same_github_instance(subject.github_instance, github_instance):
            continue
        if subject.github_repo_id is not None:
            if repo.github_repo_id == subject.github_repo_id:
                return subject
            continue
        if subject_repository_full_name(subject) == wanted_name:
            return subject
    return None


def finding_external_id(finding: Finding) -> str:
    """Stable rule/location identity, intentionally excluding mutable presentation."""
    category = finding.category.strip().lower() or "uncategorized"
    path = finding.file_path.strip().replace("\\", "/")
    location = finding.line_range.strip()
    digest = hashlib.sha256(f"{category}|{path}|{location}".encode()).hexdigest()
    return f"secscan:{digest}"


def _finding_body(
    finding: Finding,
    *,
    engine: str | None,
    model: str | None,
    commit_sha: str | None,
    issue_urls: Mapping[str, str],
    fix_pr_url: str | None,
) -> dict[str, Any]:
    external_id = finding_external_id(finding)
    return {
        "externalId": external_id,
        "legacyIds": [],
        "severity": finding.severity.value.upper(),
        "title": finding.title,
        "description": finding.description,
        "recommendation": finding.recommendation,
        "evidence": finding.description,
        "filePath": finding.file_path or None,
        "lineRange": finding.line_range or None,
        "url": None,
        "confidence": _CONFIDENCE.get(finding.confidence.strip().lower(), 0.7),
        "engine": engine,
        "model": model,
        "commitSha": commit_sha,
        "issueUrl": issue_urls.get(external_id),
        "fixPrUrl": fix_pr_url,
        "attachments": [],
    }


def build_run_body(
    *,
    scanner_id: int,
    subject: IntegrationSubject,
    status: str,
    findings: Iterable[Finding],
    started_at: str,
    completed_at: str,
    metadata: Mapping[str, Any] | None = None,
    engine: str | None = None,
    model: str | None = None,
    commit_sha: str | None = None,
    issue_urls: Mapping[str, str] | None = None,
    fix_pr_url: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic version-1 terminal snapshot.

    Secscan reports only High/Critical findings, so it can never truthfully
    claim complete subject coverage.  Failed and skipped runs carry no findings.
    """
    normalized_status = status.upper()
    if normalized_status not in {"SUCCESS", "PARTIAL", "FAILED", "SKIPPED"}:
        raise IntegrationResultError(f"unsupported integration run status: {status}")
    if subject.scanner_id != scanner_id:
        raise IntegrationResultError("integration subject belongs to a different scanner")
    finding_list = list(findings)
    if len(finding_list) > 500:
        raise IntegrationResultError("integration run exceeds the 500 finding limit")
    mapped = [] if normalized_status in _TERMINAL_WITHOUT_FINDINGS else [
        _finding_body(
            finding,
            engine=engine,
            model=model,
            commit_sha=commit_sha,
            issue_urls=issue_urls or {},
            fix_pr_url=fix_pr_url,
        )
        for finding in finding_list
    ]
    mapped.sort(key=lambda finding: finding["externalId"])
    external_ids = [finding["externalId"] for finding in mapped]
    if len(external_ids) != len(set(external_ids)):
        raise IntegrationResultError("integration run contains duplicate finding identities")
    body: dict[str, Any] = {
        "scannerId": scanner_id,
        "subjectId": subject.id,
        "status": normalized_status,
        "completeCoverage": False,
        "startedAt": started_at,
        "completedAt": completed_at,
        "metadataJson": json.dumps(metadata or {}, sort_keys=True, separators=(",", ":")),
        "findings": mapped,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    body["runKey"] = "secscan-v1:" + hashlib.sha256(canonical.encode()).hexdigest()
    return body


class IntegrationClient:
    """Authenticated client for permitted subjects and atomic run submission."""

    def __init__(self, base_url: str, token: str):
        self._base_url = validate_base_url(base_url)
        self._headers = {"Authorization": f"Bearer {token}"}

    def list_subjects(self, scanner_id: int, *, size: int = 100) -> list[IntegrationSubject]:
        if size < 1 or size > 100:
            raise ValueError("subject page size must be between 1 and 100")
        subjects: list[IntegrationSubject] = []
        page = 0
        while True:
            response = requests.get(
                f"{self._base_url}/api/integrations/v1/scanners/{scanner_id}/subjects",
                headers=self._headers,
                params={"page": page, "size": size},
                timeout=_TIMEOUT_S,
                allow_redirects=False,
            )
            if response.status_code != 200:
                raise IntegrationResultError(
                    f"secman subject discovery failed with HTTP {response.status_code}"
                )
            try:
                payload = response.json()
                subjects.extend(IntegrationSubject.from_api(row) for row in payload["content"])
                total_pages = int(payload["totalPages"])
            except (KeyError, TypeError, ValueError) as exc:
                raise IntegrationResultError("secman subject discovery returned an invalid response") from exc
            page += 1
            if page >= total_pages:
                return subjects

    def submit_run(self, body: Mapping[str, Any]) -> dict[str, Any]:
        dryrun.guard("submit an integration run to secman")
        response = requests.post(
            f"{self._base_url}/api/integrations/v1/runs",
            json=dict(body),
            headers=self._headers,
            timeout=_TIMEOUT_S,
            allow_redirects=False,
        )
        if response.status_code not in (200, 201):
            raise IntegrationResultError(
                f"secman integration run was rejected with HTTP {response.status_code}"
            )
        try:
            return response.json()
        except (TypeError, ValueError) as exc:
            raise IntegrationResultError("secman integration run returned an invalid response") from exc


def push_stored_records(
    store,
    *,
    url: str | None,
    username: str | None,
    password: str | None,
    scanner_id: int,
    github_instance: str,
    dry_run: bool,
) -> tuple[int, int]:
    """Submit terminal snapshots already present in the state database."""
    records = store.all_records()
    if dry_run:
        return len(records), 0

    from . import secman_client
    from .findings import fingerprint

    base_url = validate_base_url(url)
    token = secman_client.login(base_url, username, password)
    client = IntegrationClient(base_url, token)
    subjects = client.list_subjects(scanner_id)
    pushed = failed = 0
    for record in records:
        stored_body = store.get_integration_payload(record.owner, record.repo, scanner_id)
        if stored_body is not None:
            permitted_ids = {subject.id for subject in subjects}
            if stored_body.get("subjectId") not in permitted_ids:
                failed += 1
                continue
            try:
                client.submit_run(stored_body)
                pushed += 1
            except IntegrationResultError:
                failed += 1
            continue

        instance = record.github_instance or github_instance
        repo = RepoInfo(
            owner=record.owner,
            name=record.repo,
            full_name=record.full_name,
            archived=False,
            fork=False,
            size_kb=0,
            default_branch="",
            clone_url=f"{instance.rstrip('/')}/{record.full_name}.git",
            installation_id=0,
            github_repo_id=record.github_repo_id,
        )
        subject = match_subject(subjects, repo, instance)
        if subject is None:
            failed += 1
            continue
        findings = [Finding.model_validate(row) for row in store.get_findings(record.owner, record.repo)]
        issue_urls = {}
        for finding in findings:
            issue = store.find_issue(record.owner, record.repo, fingerprint(finding))
            if issue is not None:
                issue_urls[finding_external_id(finding)] = issue.issue_url
        status = {
            "done": "SUCCESS",
            "failed": "FAILED",
            "skipped": "SKIPPED",
        }.get(record.status.value)
        if status is None:
            continue
        timestamp = record.reviewed_at or datetime.now(timezone.utc).isoformat()
        body = build_run_body(
            scanner_id=scanner_id,
            subject=subject,
            status=status,
            findings=findings,
            started_at=timestamp,
            completed_at=timestamp,
            metadata={
                "repository": record.full_name,
                "githubInstance": instance,
                "githubRepoId": record.github_repo_id,
                "highCriticalOnly": True,
                "storedReplay": True,
            },
            commit_sha=record.last_commit_sha or None,
            issue_urls=issue_urls,
        )
        store.record_integration_payload(record.owner, record.repo, scanner_id, body)
        try:
            client.submit_run(body)
            pushed += 1
        except IntegrationResultError:
            failed += 1
    return pushed, failed
