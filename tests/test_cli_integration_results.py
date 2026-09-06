from typer.testing import CliRunner

import secscan.orchestrator as orchestrator
import secscan.integration_results as integration_results
from secscan.cli import app


runner = CliRunner()


def _clear_secman(monkeypatch):
    for name in ("SECMAN_URL", "SECMAN_USERNAME", "SECMAN_PASSWORD", "SECMAN_SCANNER_ID"):
        monkeypatch.delenv(name, raising=False)


def test_scan_scanner_id_selects_v1_transport(tmp_path, monkeypatch):
    _clear_secman(monkeypatch)
    monkeypatch.setenv("SECMAN_PASSWORD", "pw")
    captured = {}

    async def fake_scan(cfg, owner, name):
        captured["cfg"] = cfg

    monkeypatch.setattr(orchestrator, "scan_repo", fake_scan)
    result = runner.invoke(app, [
        "scan", "octo/demo", "--output-dir", str(tmp_path), "--push-to-secman",
        "--secman-scanner-id", "17", "--secman-url", "https://secman.example.com",
        "--secman-username", "scanner",
    ])

    assert result.exit_code == 0, result.output
    assert captured["cfg"].secman_scanner_id == 17


def test_scanner_id_can_come_from_environment(tmp_path, monkeypatch):
    _clear_secman(monkeypatch)
    monkeypatch.setenv("SECMAN_URL", "https://secman.example.com")
    monkeypatch.setenv("SECMAN_USERNAME", "scanner")
    monkeypatch.setenv("SECMAN_PASSWORD", "pw")
    monkeypatch.setenv("SECMAN_SCANNER_ID", "23")
    captured = {}

    async def fake_scan(cfg, owner, name):
        captured["cfg"] = cfg

    monkeypatch.setattr(orchestrator, "scan_repo", fake_scan)
    result = runner.invoke(
        app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--push-to-secman"]
    )

    assert result.exit_code == 0, result.output
    assert captured["cfg"].secman_scanner_id == 23


def test_scanner_id_without_explicit_push_does_not_upload(tmp_path, monkeypatch):
    _clear_secman(monkeypatch)
    captured = {}

    async def fake_scan(cfg, owner, name):
        captured["cfg"] = cfg

    monkeypatch.setattr(orchestrator, "scan_repo", fake_scan)
    result = runner.invoke(
        app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--secman-scanner-id", "17"]
    )

    assert result.exit_code != 0
    assert "--push-to-secman" in result.output
    assert captured == {}


def test_v1_dry_run_needs_no_secman_credentials(tmp_path, monkeypatch):
    _clear_secman(monkeypatch)
    captured = {}

    async def fake_scan(cfg, owner, name):
        captured["cfg"] = cfg

    monkeypatch.setattr(orchestrator, "scan_repo", fake_scan)
    result = runner.invoke(app, [
        "scan", "octo/demo", "--output-dir", str(tmp_path), "--push-to-secman",
        "--secman-scanner-id", "17", "--dry-run",
    ])

    assert result.exit_code == 0, result.output
    assert captured["cfg"].dry_run is True
    assert captured["cfg"].secman_scanner_id == 17


def test_v1_scan_can_upload_without_local_state_database(tmp_path, monkeypatch):
    _clear_secman(monkeypatch)
    monkeypatch.setenv("SECMAN_URL", "https://secman.example.com")
    monkeypatch.setenv("SECMAN_USERNAME", "scanner")
    monkeypatch.setenv("SECMAN_PASSWORD", "pw")
    captured = {}

    async def fake_scan(cfg, owner, name):
        captured["cfg"] = cfg

    monkeypatch.setattr(orchestrator, "scan_repo", fake_scan)
    result = runner.invoke(app, [
        "scan", "octo/demo", "--output-dir", str(tmp_path), "--no-db",
        "--push-to-secman", "--secman-scanner-id", "17",
    ])

    assert result.exit_code == 0, result.output
    assert captured["cfg"].no_db is True


def test_invalid_environment_scanner_id_fails_before_scan(tmp_path, monkeypatch):
    _clear_secman(monkeypatch)
    monkeypatch.setenv("SECMAN_SCANNER_ID", "not-an-id")
    started = []

    async def fake_scan(cfg, owner, name):
        started.append(1)

    monkeypatch.setattr(orchestrator, "scan_repo", fake_scan)
    result = runner.invoke(
        app, ["scan", "octo/demo", "--output-dir", str(tmp_path), "--push-to-secman"]
    )

    assert result.exit_code != 0
    assert "SECMAN_SCANNER_ID" in result.output
    assert started == []


def test_standalone_push_uses_v1_when_scanner_id_is_set(tmp_path, monkeypatch):
    _clear_secman(monkeypatch)
    monkeypatch.setenv("SECMAN_PASSWORD", "pw")
    captured = {}

    def fake_push(store, *, url, username, password, scanner_id, github_instance, dry_run):
        captured.update(
            scanner_id=scanner_id,
            github_instance=github_instance,
            dry_run=dry_run,
        )
        return (2, 0)

    monkeypatch.setattr(integration_results, "push_stored_records", fake_push)
    result = runner.invoke(app, [
        "push-to-secman", "--output-dir", str(tmp_path),
        "--secman-url", "https://secman.example.com", "--secman-username", "scanner",
        "--secman-scanner-id", "31", "--github-api-url", "https://github.example.com",
    ])

    assert result.exit_code == 0, result.output
    assert captured == {
        "scanner_id": 31,
        "github_instance": "https://github.example.com",
        "dry_run": False,
    }
