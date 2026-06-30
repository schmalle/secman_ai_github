from pathlib import Path

from secscan.cloner import build_clone_command, cleanup


def test_build_clone_command_is_shallow_and_noninteractive():
    cmd = build_clone_command("https://x-access-token:tok@github.com/o/r.git", Path("/tmp/o__r"))
    assert cmd[:2] == ["git", "clone"]
    assert "--depth" in cmd and "1" in cmd
    assert "--single-branch" in cmd
    assert cmd[-1] == "/tmp/o__r"


def test_cleanup_removes_tree(tmp_path):
    d = tmp_path / "clone"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "f.txt").write_text("x")
    cleanup(d)
    assert not d.exists()


def test_cleanup_is_safe_on_missing(tmp_path):
    cleanup(tmp_path / "does-not-exist")  # must not raise
