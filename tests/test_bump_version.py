"""Tests for scripts/bump_version.py."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "bump_version.py"


def make_project(root: Path, version: str = "0.0.1") -> None:
    (root / "backuper").mkdir(parents=True, exist_ok=True)
    (root / "backuper" / "__init__.py").write_text(
        f'__version__ = "{version}"\n', encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndynamic = ["version"]\n',
        encoding="utf-8")


def run(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), *args],
        capture_output=True, text=True, check=False)


def test_bump_math():
    from scripts.bump_version import bump
    assert bump("0.0.1", "patch") == "0.0.2"
    assert bump("0.0.1", "minor") == "0.1.0"
    assert bump("0.0.1", "major") == "1.0.0"
    assert bump("1.2.3", "none") == "1.2.3"
    assert bump("1.2.9", "patch") == "1.2.10"


def test_patch_writes_init(tmp_path):
    make_project(tmp_path, "0.0.1")
    r = run(tmp_path, "--part", "patch")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "0.0.2"
    assert '__version__ = "0.0.2"' in (tmp_path / "backuper" / "__init__.py").read_text()


def test_set_explicit(tmp_path):
    make_project(tmp_path, "0.0.1")
    r = run(tmp_path, "--set", "1.5.0")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "1.5.0"
    assert '__version__ = "1.5.0"' in (tmp_path / "backuper" / "__init__.py").read_text()


def test_dry_run_does_not_write(tmp_path):
    make_project(tmp_path, "0.0.1")
    before = (tmp_path / "backuper" / "__init__.py").read_text()
    r = run(tmp_path, "--part", "patch", "--dry-run")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "0.0.2"
    assert (tmp_path / "backuper" / "__init__.py").read_text() == before


def test_invalid_set_fails(tmp_path):
    make_project(tmp_path, "0.0.1")
    r = run(tmp_path, "--set", "not-a-version")
    assert r.returncode != 0


def test_none_part_keeps_version(tmp_path):
    make_project(tmp_path, "0.0.1")
    r = run(tmp_path, "--part", "none")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "0.0.1"
    assert '__version__ = "0.0.1"' in (tmp_path / "backuper" / "__init__.py").read_text()


def test_missing_init_fails(tmp_path):
    (tmp_path / "backuper").mkdir()
    (tmp_path / "backuper" / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    r = run(tmp_path, "--part", "patch")
    assert r.returncode != 0
