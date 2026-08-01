"""Mask likely secret material inside LLM-authored finding text.

secscan's own system prompt (see prompts.py) explicitly instructs the review
agent to include "evidence" when it reports a hardcoded/leaked credential —
which means a real finding about a real leaked secret is highly likely to
reproduce that secret's actual value inside `Finding.description`. That value
then flows, unmodified until this module existed, into every sink secscan
writes to: a public-by-default GitHub issue, an emailed report, findings.csv,
and the SQLite/MySQL state DB — each with a wider or more persistent audience
than the original leak. A tool whose purpose is finding leaked secrets must
not become a louder distribution channel for them.

This is a best-effort regex pass, not a secret scanner in its own right: it
trades some false positives (a description that happens to mention a
40-character hex hash) for never letting a matched credential-shaped string
reach a sink verbatim. Applied once at Finding construction (see
`findings.Finding`) so every current and future sink is covered automatically.
"""

from __future__ import annotations

import re

_REDACTED = "[REDACTED]"


def _mask_match(m: re.Match) -> str:
    value = m.group(0)
    if len(value) <= 8:
        return _REDACTED
    return f"{value[:4]}…{_REDACTED}…{value[-4:]}"


# Each pattern matches the secret value itself (not just a labelled context),
# so redaction survives whatever prose the model wraps around it.
_PATTERNS = [
    # AWS access key id
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # AWS secret access key (assignment-context, base64-ish, exactly 40 chars)
    re.compile(
        r"(?i)\b(aws_secret_access_key|secret_access_key)\s*[:=]\s*['\"]?"
        r"[A-Za-z0-9/+=]{40}['\"]?"
    ),
    # GitHub tokens (classic + fine-grained PAT)
    re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    # Slack tokens
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    # PEM-encoded private key blocks
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    # JWT-shaped tokens (header.payload.signature)
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    # Generic Bearer/Authorization header value
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}"),
    # Generic labelled secret assignment: password/api_key/secret/token = <value>
    re.compile(
        r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
        r"auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"]?([^\s'\",;]{6,})['\"]?"
    ),
]


def redact_secrets(text: str) -> str:
    """Return `text` with likely secret material masked. Idempotent."""
    if not text:
        return text
    for pattern in _PATTERNS:
        text = pattern.sub(_mask_match, text)
    return text
