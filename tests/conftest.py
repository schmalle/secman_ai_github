import pytest

from secscan import dryrun


@pytest.fixture(autouse=True)
def _reset_dry_run_guard():
    """The dry-run guard is process-wide state; a test that arms it must not leak
    into the next one (nor a stray SECSCAN_DRY_RUN in the developer's shell)."""
    dryrun.reset()
    yield
    dryrun.reset()


@pytest.fixture(autouse=True)
def _clear_dry_run_env(monkeypatch):
    monkeypatch.delenv("SECSCAN_DRY_RUN", raising=False)
