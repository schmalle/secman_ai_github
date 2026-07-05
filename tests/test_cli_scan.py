from typer.testing import CliRunner

from secscan.cli import app

runner = CliRunner()


def test_scan_rejects_bad_name(tmp_path):
    for bad in ("noslash", "a/b/c", "/name", "owner/"):
        result = runner.invoke(app, ["scan", bad, "--output-dir", str(tmp_path)])
        assert result.exit_code != 0, bad
