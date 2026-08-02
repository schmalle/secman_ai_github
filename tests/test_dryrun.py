import pytest

from secscan import dryrun


def test_guard_is_a_noop_until_activated():
    assert dryrun.is_active() is False
    dryrun.guard("do something external")  # must not raise


def test_guard_raises_once_activated():
    dryrun.activate()

    assert dryrun.is_active() is True
    with pytest.raises(dryrun.DryRunViolation) as exc:
        dryrun.guard("open a GitHub issue on octo/demo")
    assert "open a GitHub issue on octo/demo" in str(exc.value)


def test_reset_disarms_the_guard():
    dryrun.activate()
    dryrun.reset()

    assert dryrun.is_active() is False
    dryrun.guard("do something external")


def test_resolve_honours_the_flag():
    assert dryrun.resolve(True) is True
    assert dryrun.resolve(False) is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", " true "])
def test_resolve_honours_truthy_env(monkeypatch, value):
    monkeypatch.setenv("SECSCAN_DRY_RUN", value)
    assert dryrun.resolve(False) is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "maybe"])
def test_resolve_ignores_falsy_env(monkeypatch, value):
    monkeypatch.setenv("SECSCAN_DRY_RUN", value)
    assert dryrun.resolve(False) is False


def test_secman_client_refuses_to_login_or_push_while_armed():
    """The guard is the backstop: even a caller that forgot to branch on the flag
    cannot reach secman."""
    from secscan import secman_client

    dryrun.activate()

    with pytest.raises(dryrun.DryRunViolation):
        secman_client.login("https://secman.example.com", "u", "p")
    with pytest.raises(dryrun.DryRunViolation):
        secman_client.push_vulnerability(
            "https://secman.example.com", "tok",
            hostname="octo/demo", cve="SECSCAN:CWE-89:abc", criticality="HIGH", days_open=0,
        )


def test_issue_creation_refuses_while_armed(tmp_path):
    from secscan.findings import Finding
    from secscan.issues import process_finding
    from secscan.state import StateStore

    store = StateStore(tmp_path / "secscan.sqlite3")
    finding = Finding(severity="high", title="SQLi", description="d", file_path="app.py")

    class _ExplodingRepo:
        def create_issue(self, **kwargs):
            raise AssertionError("create_issue must never be reached during a dry run")

    dryrun.activate()

    # dry_run=False simulates a caller that failed to propagate the flag.
    with pytest.raises(dryrun.DryRunViolation):
        process_finding(
            _ExplodingRepo(), store, "octo", "demo", finding,
            seen_at="2026-07-12T00:00:00+00:00", dry_run=False,
        )
