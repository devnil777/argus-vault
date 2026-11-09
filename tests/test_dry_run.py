"""Tests for --dry-run (full/diff) and the low-disk-space advisory."""

import conftest
import pytest
from conftest import run_cli

from backuper.archiver import space_problem

pytestmark = pytest.mark.skipif(conftest.RAR_PATH is None, reason="Rar.exe not found")


def test_full_dry_run_scans_but_writes_nothing(job, capsys):
    job.make_source(a="x", **{"sub/b.bin": bytes(range(256))})
    assert run_cli(["full", "--dry-run", job.dir]) == 0
    out = capsys.readouterr().out
    assert "scan:" in out and "files" in out and " dirs (" in out
    assert "dry run: would archive" in out  # 2 files + the fixture vault.pst
    assert not list(job.dir.glob("*-*-*"))          # no epoch dir, no archives
    assert not list(job.dir.glob("*.rar*"))


def test_full_dry_run_missing_config_is_exit5_no_side_effects(tmp_path):
    job_dir = tmp_path / "job"
    assert run_cli(["full", "--dry-run", str(job_dir)]) == 5
    assert not job_dir.exists()                     # dry run creates nothing


def test_diff_dry_run_shows_delta_without_archiving(job, capsys):
    job.make_source(a="x")
    assert run_cli(["full", job.dir]) == 0
    capsys.readouterr()
    epoch = job.latest_epoch()

    (job.src / "b.txt").write_text("new", encoding="utf-8")
    (job.src / "a").unlink()                      # make_source(a=...) has no ext
    assert run_cli(["diff", "--dry-run", job.dir]) == 0
    out = capsys.readouterr().out
    assert "diff: +1 files" in out and "-1 deleted files" in out
    assert "dry run: no archive created" in out
    assert len(list(epoch.glob("*_diff.rar"))) == 0  # nothing was written
    assert not list(epoch.glob("*nothing*"))         # no no-op log either


def test_diff_dry_run_no_changes(job, capsys):
    job.make_source(a="x")
    assert run_cli(["full", job.dir]) == 0
    capsys.readouterr()
    assert run_cli(["diff", "--dry-run", job.dir]) == 0
    assert "no changes detected" in capsys.readouterr().out


def test_space_problem_boundaries():
    # enough space (bound = 10_500_000 + 1_000_000)
    assert space_problem(free=12_000_000, needed=10_000_000) is None
    # short: free below the bound -> warning naming both sizes
    msg = space_problem(free=5_000_000, needed=10_000_000)
    assert msg is not None and "MiB" in msg and "free" in msg
    # nothing to store -> never warns
    assert space_problem(free=0, needed=0) is None
