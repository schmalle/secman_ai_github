"""Unit tests for the shared push helper that `push-to-secman`, `scan`, and `run`
all route through (`secscan.secman_push`)."""

import pytest

import secscan.secman_client as secman_client
from secscan.findings import Finding
from secscan.state import StateStore


def _store(tmp_path, *repos):
    store = StateStore(tmp_path / "secscan.sqlite3")
    for owner, name in repos:
        store.record_result(
            owner, name,
            critical=1, high=1, total=3,
            duration_s=1.0, cost_usd=0.1, reviewed_at="2026-07-01T00:00:00+00:00",
        )
        store.replace_findings(
            owner, name,
            [
                Finding(severity="critical", title="SQLi", description="d", file_path="a.py", category="CWE-89"),
                Finding(severity="high", title="XSS", description="d", file_path="b.py"),
                Finding(severity="medium", title="Weak crypto", description="d", file_path="c.py"),
            ],
        )
    return store


def _stub_client(monkeypatch, pushed, fail_first=False):
    monkeypatch.setattr(secman_client, "login", lambda url, u, p: "tok")

    def fake_push(url, token, *, hostname, cve, criticality, days_open):
        pushed.append({"hostname": hostname, "cve": cve, "criticality": criticality, "days_open": days_open})
        if fail_first and len(pushed) == 1:
            raise secman_client.SecmanPushError("400 bad request")
        return {"operation": "CREATED"}

    monkeypatch.setattr(secman_client, "push_vulnerability", fake_push)


def test_push_records_pushes_only_high_and_critical(tmp_path, monkeypatch):
    from secscan import secman_push

    store = _store(tmp_path, ("octo", "demo"))
    pushed = []
    _stub_client(monkeypatch, pushed)

    counts = secman_push.push_records(
        store, store.all_records(),
        url="https://secman.example.com", username="vulnbot", password="pw", dry_run=False,
    )

    assert counts == (2, 0)
    assert {p["criticality"] for p in pushed} == {"CRITICAL", "HIGH"}
    assert {p["hostname"] for p in pushed} == {"octo/demo"}


def test_push_records_pushes_only_the_records_it_is_given(tmp_path, monkeypatch):
    """scan / run push what they just reviewed, not the whole state DB."""
    from secscan import secman_push

    store = _store(tmp_path, ("octo", "demo"), ("octo", "other"))
    pushed = []
    _stub_client(monkeypatch, pushed)

    only_demo = [r for r in store.all_records() if r.full_name == "octo/demo"]
    counts = secman_push.push_records(
        store, only_demo,
        url="https://secman.example.com", username="vulnbot", password="pw", dry_run=False,
    )

    assert counts == (2, 0)
    assert {p["hostname"] for p in pushed} == {"octo/demo"}


def test_push_records_one_failure_does_not_stop_the_rest(tmp_path, monkeypatch):
    from secscan import secman_push

    store = _store(tmp_path, ("octo", "demo"))
    pushed = []
    _stub_client(monkeypatch, pushed, fail_first=True)

    counts = secman_push.push_records(
        store, store.all_records(),
        url="https://secman.example.com", username="vulnbot", password="pw", dry_run=False,
    )

    assert counts == (1, 1)
    assert len(pushed) == 2  # both attempted


def test_push_records_raises_on_login_failure(tmp_path, monkeypatch):
    """Login failure is the caller's decision to act on, not an exit from here."""
    from secscan import secman_push

    store = _store(tmp_path, ("octo", "demo"))

    def boom(url, u, p):
        raise secman_client.SecmanPushError("secman login failed: 401")

    monkeypatch.setattr(secman_client, "login", boom)

    with pytest.raises(secman_client.SecmanPushError):
        secman_push.push_records(
            store, store.all_records(),
            url="https://secman.example.com", username="vulnbot", password="bad", dry_run=False,
        )


def test_push_records_dry_run_makes_no_calls(tmp_path, monkeypatch):
    from secscan import secman_push

    store = _store(tmp_path, ("octo", "demo"))
    called = []
    monkeypatch.setattr(secman_client, "login", lambda *a, **kw: called.append("login") or "tok")
    monkeypatch.setattr(secman_client, "push_vulnerability", lambda *a, **kw: called.append("push"))

    counts = secman_push.push_records(
        store, store.all_records(),
        url=None, username=None, password=None, dry_run=True,
    )

    assert counts == (2, 0)
    assert called == []


def test_push_records_cve_carries_category_and_fingerprint(tmp_path, monkeypatch):
    from secscan import secman_push

    store = _store(tmp_path, ("octo", "demo"))
    pushed = []
    _stub_client(monkeypatch, pushed)

    secman_push.push_records(
        store, store.all_records(),
        url="https://secman.example.com", username="vulnbot", password="pw", dry_run=False,
    )

    sqli = next(p for p in pushed if p["criticality"] == "CRITICAL")
    assert sqli["cve"].startswith("SECSCAN:CWE-89:")
    assert sqli["days_open"] == 0  # no issue_tracking row for this finding


def test_push_records_caps_an_attacker_controlled_category(tmp_path, monkeypatch):
    """category is LLM output about untrusted repo content; it must not become an
    arbitrarily long identifier in secman (mirrors the GitHub-issue field caps)."""
    from secscan import secman_push

    store = StateStore(tmp_path / "secscan.sqlite3")
    store.record_result(
        "octo", "demo",
        critical=1, high=0, total=1,
        duration_s=1.0, cost_usd=0.1, reviewed_at="2026-07-01T00:00:00+00:00",
    )
    store.replace_findings(
        "octo", "demo",
        [Finding(severity="critical", title="Injected", description="d", file_path="a.py", category="D" * 1000)],
    )
    pushed = []
    _stub_client(monkeypatch, pushed)

    secman_push.push_records(
        store, store.all_records(),
        url="https://secman.example.com", username="vulnbot", password="pw", dry_run=False,
    )

    assert "D" * 1000 not in pushed[0]["cve"]
    assert len(pushed[0]["cve"]) < 300


def test_resolve_credentials_prefers_flags_over_env(monkeypatch):
    from secscan import secman_push

    monkeypatch.setenv("SECMAN_URL", "https://env.example.com")
    monkeypatch.setenv("SECMAN_USERNAME", "envuser")
    monkeypatch.setenv("SECMAN_PASSWORD", "envpw")

    assert secman_push.resolve_credentials("https://flag.example.com", None, "flagpw") == (
        "https://flag.example.com", "envuser", "flagpw",
    )


def test_resolve_credentials_falls_back_to_env(monkeypatch):
    from secscan import secman_push

    monkeypatch.setenv("SECMAN_URL", "https://env.example.com")
    monkeypatch.setenv("SECMAN_USERNAME", "envuser")
    monkeypatch.setenv("SECMAN_PASSWORD", "envpw")

    assert secman_push.resolve_credentials(None, None, None) == (
        "https://env.example.com", "envuser", "envpw",
    )
