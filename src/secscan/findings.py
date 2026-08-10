"""Security finding schema, parsing, and CSV output.

The review agent is asked to emit findings as a JSON object. Because LLM output is
not perfectly reliable, `parse_findings` tolerates prose around the JSON and silently
drops entries that do not validate against the `Finding` schema.
"""

from __future__ import annotations

import csv
import dataclasses
import hashlib
import io
import json
import re
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, Field, field_validator

from .redact import redact_secrets


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    severity: Severity
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    file_path: str = ""
    line_range: str = ""
    category: str = ""  # e.g. "CWE-89" / OWASP category
    recommendation: str = ""
    confidence: str = "medium"

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.strip().lower()
        return v

    @field_validator("line_range", "category", "recommendation", mode="before")
    @classmethod
    def _coerce_optional_str(cls, v: Any) -> str:
        if v is None:
            return ""
        return str(v)

    @field_validator("title", "description", "recommendation", mode="after")
    @classmethod
    def _redact_secrets(cls, v: str) -> str:
        # Mask likely secret material once, here, so every sink (CSV, GitHub
        # issue, email, state DB) that later reads this Finding is protected
        # without having to remember to redact independently. See redact.py.
        return redact_secrets(v)


# Column order for per-repo findings CSV (`repo` prepended to the Finding fields).
FINDING_FIELDS = [
    "repo",
    "severity",
    "title",
    "category",
    "file_path",
    "line_range",
    "confidence",
    "description",
    "recommendation",
]

# Column order for the aggregate summary CSV.
SUMMARY_FIELDS = [
    "owner",
    "repo",
    "status",
    "critical_count",
    "high_count",
    "total_findings",
    "duration_s",
    "cost_usd",
    "reviewed_at",
    "error",
]

# Column order for the org/repo usernames CSV (`secscan list-users`).
USER_FIELDS = [
    "source",
    "org",
    "repo",
    "login",
    "role",
    "user_type",
    "site_admin",
    "user_id",
    "name",
    "email",
    "html_url",
]

_HIGH_CRITICAL = {Severity.CRITICAL, Severity.HIGH}


def _extract_json(text: str) -> Any | None:
    """Best-effort extraction of a JSON value from a string that may contain prose."""
    text = text.strip()
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass

    # Fenced ```json ... ``` (or plain ``` ... ```) block.
    fence = re.search(r"```(?:json)?\s*(.+?)\s*```", text, re.DOTALL)
    if fence:
        try:
            return json.loads(fence.group(1))
        except ValueError:
            pass

    # First balanced {...} or [...] span.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except ValueError:
                        break
    return None


def parse_findings(data: Any) -> list[Finding]:
    """Parse agent output into validated Findings, dropping malformed entries."""
    if isinstance(data, str):
        data = _extract_json(data)
        if data is None:
            return []

    if isinstance(data, Mapping):
        items = data.get("findings")
        if items is None:
            return []
    elif isinstance(data, list):
        items = data
    else:
        return []

    if not isinstance(items, list):
        return []

    findings: list[Finding] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        try:
            findings.append(Finding.model_validate(dict(item)))
        except Exception:
            continue  # discard anything that doesn't fit the schema
    return findings


def filter_high_critical(findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if f.severity in _HIGH_CRITICAL]


def fingerprint(finding: Finding) -> str:
    """Stable content hash for a finding — excludes line_range/description so
    minor LLM rewording or line drift between reruns doesn't change the
    identity used for GitHub issue dedup (Part B) and the secman cve value
    (Part C)."""
    key = f"{finding.severity.value}|{finding.category}|{finding.title}|{finding.file_path}"
    return hashlib.sha256(key.encode()).hexdigest()


def _severity_rank(f: Finding) -> int:
    return 0 if f.severity is Severity.CRITICAL else 1


# Cell values can originate from an attacker-chosen file_path in the scanned
# repo, or from LLM output describing that repo's content. Excel/LibreOffice
# treat a leading '=', '+', '-', '@', tab, or CR as the start of a formula, so
# any cell starting with one of these must be neutralized before writing —
# otherwise opening findings.csv/summary.csv can execute attacker-controlled
# formulas (data exfiltration via WEBSERVICE/HYPERLINK, or legacy DDE).
_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value: Any) -> Any:
    if value is None:
        return value
    text = str(value)
    if text.startswith(_FORMULA_LEADERS):
        return "'" + text
    return value


def write_findings_csv(path: Path, repo_full_name: str, findings: Iterable[Finding]) -> Path:
    """Write one repo's findings to CSV. Always writes a header row."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(findings, key=_severity_rank)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FINDING_FIELDS)
        writer.writeheader()
        for f in ordered:
            row = {
                "repo": _csv_cell(repo_full_name),
                "severity": f.severity.value,
                "title": _csv_cell(f.title),
                "category": _csv_cell(f.category),
                "file_path": _csv_cell(f.file_path),
                "line_range": _csv_cell(f.line_range),
                "confidence": f.confidence,
                "description": _csv_cell(f.description),
                "recommendation": _csv_cell(f.recommendation),
            }
            writer.writerow(row)
    return path


def _row_to_dict(row: Any) -> Mapping[str, Any]:
    if dataclasses.is_dataclass(row) and not isinstance(row, type):
        return dataclasses.asdict(row)
    if isinstance(row, Mapping):
        return row
    raise TypeError(f"summary row must be a mapping or dataclass, got {type(row)!r}")


def write_summary_csv(path: Path, rows: Iterable[Any]) -> Path:
    """Write the aggregate index. Accepts dicts or dataclasses (e.g. RepoRecord)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=SUMMARY_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            d = _row_to_dict(row)
            writer.writerow({k: _csv_cell(_csv_value(d.get(k, ""))) for k in SUMMARY_FIELDS})
    return path


def _write_users(fh, users: Iterable[Any]) -> None:
    writer = csv.DictWriter(fh, fieldnames=USER_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for row in users:
        d = _row_to_dict(row)
        # A GitHub display name is free text the account holder chooses, so it reaches
        # the spreadsheet exactly as attacker-controlled as a finding does.
        writer.writerow({k: _csv_cell(_csv_value(d.get(k, ""))) for k in USER_FIELDS})


def write_users_csv(path: Path, users: Iterable[Any]) -> Path:
    """Write org members / repo collaborators to CSV. Accepts dicts or GithubUser."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        _write_users(fh, users)
    return path


def render_users_csv(users: Iterable[Any]) -> str:
    """The same rows as `write_users_csv`, as a string — for stdout or `--output`.

    Line endings are `\\n`, not the `\\r\\n` the csv module writes to files: this text is
    echoed to a terminal or piped, where stray carriage returns are noise.
    """
    buf = io.StringIO()
    _write_users(buf, users)
    return buf.getvalue().replace("\r\n", "\n")


def _csv_value(v: Any) -> Any:
    return v.value if isinstance(v, Enum) else ("" if v is None else v)
