"""Thin HTTP client for pushing findings into secman via POST /api/vulnerabilities/cli-add.

Mirrors secman's own CLI (CliHttpClient.authenticate in the secman repo): the
login response carries no token in its JSON body — the JWT only appears in the
Set-Cookie: secman_auth=<jwt> response header. Subsequent requests send it as
a standard Authorization: Bearer header (Micronaut's bearer-token reader stays
active alongside cookie auth on the secman backend).
"""

from __future__ import annotations

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from . import dryrun

_TIMEOUT_S = 30
_RETRY = dict(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=20),
    retry=retry_if_exception_type(requests.exceptions.ConnectionError),
    reraise=True,
)


class SecmanPushError(Exception):
    """Raised on login failure or a rejected cli-add call."""


def _extract_cookie_token(set_cookie_header: str, cookie_name: str = "secman_auth") -> str | None:
    for part in set_cookie_header.split(";"):
        part = part.strip()
        if part.startswith(f"{cookie_name}="):
            return part[len(f"{cookie_name}="):]
    return None


@retry(**_RETRY)
def login(base_url: str, username: str, password: str) -> str:
    """POST /api/auth/login, return the JWT extracted from Set-Cookie."""
    dryrun.guard("authenticate against secman")
    resp = requests.post(
        f"{base_url}/api/auth/login",
        json={"username": username, "password": password},
        timeout=_TIMEOUT_S,
    )
    if resp.status_code != 200:
        raise SecmanPushError(f"secman login failed: {resp.status_code} {resp.text[:300]}")

    set_cookie = resp.headers.get("Set-Cookie", "")
    token = _extract_cookie_token(set_cookie)
    if not token:
        raise SecmanPushError("secman login succeeded but no auth token found in Set-Cookie response header")
    return token


@retry(**_RETRY)
def push_vulnerability(
    base_url: str,
    token: str,
    *,
    hostname: str,
    cve: str,
    criticality: str,
    days_open: int,
) -> dict:
    """POST /api/vulnerabilities/cli-add with Authorization: Bearer {token}."""
    dryrun.guard(f"push {cve} for {hostname} to secman")
    resp = requests.post(
        f"{base_url}/api/vulnerabilities/cli-add",
        json={"hostname": hostname, "cve": cve, "criticality": criticality, "daysOpen": days_open},
        headers={"Authorization": f"Bearer {token}"},
        timeout=_TIMEOUT_S,
    )
    if resp.status_code != 200:
        raise SecmanPushError(f"cli-add failed: {resp.status_code} {resp.text[:300]}")
    return resp.json()
