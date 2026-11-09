"""CLI wiring tests: exit codes through backuper.cli.main."""

import os
import subprocess
import sys

import conftest
import pytest

from backuper import __version__
from backuper.lock import JobLock


def test_list_empty_job_exit0(job, capsys):
    assert conftest.run_cli(["list", job.dir]) == 0
    assert "no epochs" in capsys.readouterr().out


def test_list_with_epoch_exit0(job, capsys):
    job.make_source(a="x")
    assert conftest.run_cli(["full", job.dir]) == 0
    capsys.readouterr()
    assert conftest.run_cli(["list", job.dir]) == 0
    out = capsys.readouterr().out
    assert "full:" in out and "_full.rar" in out


def test_no_command_prints_usage_and_exit5(capsys):
    assert conftest.run_cli([]) == 5
    assert "usage" in capsys.readouterr().err.lower()


def test_backup_level_is_gone():
    # The old nested "backup" group must not linger as a hidden alias.
    with pytest.raises(SystemExit) as ei:
        conftest.run_cli(["backup", "full", "whatever"])
    assert ei.value.code == 2  # argparse: invalid choice


def test_diagnose_help_is_systemexit_zero():
    with pytest.raises(SystemExit) as ei:
        conftest.run_cli(["diagnose", "--help"])
    assert ei.value.code == 0


def test_noop_diff_maps_to_exit6(job):
    job.make_source(a="x")
    assert conftest.run_cli(["full", job.dir]) == 0
    assert conftest.run_cli(["diff", job.dir]) == 6


def test_full_without_config_is_exit5(tmp_path):
    job_dir = tmp_path / "job"
    job_dir.mkdir()                      # no config.yaml inside
    assert conftest.run_cli(["full", job_dir]) == 5


def test_full_with_missing_source_is_exit1(job):
    gone = job.src.parent / "does_not_exist"
    job.write_config(f"source: {gone.as_posix()}\n")
    assert conftest.run_cli(["full", job.dir]) == 1


def test_lock_held_maps_to_exit4(job):
    job.make_source(a="x")
    lock = JobLock(job.dir)
    lock.acquire()
    try:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(conftest.PROJECT_ROOT)
        r = subprocess.run(
            [sys.executable, "-m", "backuper", "full", str(job.dir)],
            cwd=str(conftest.PROJECT_ROOT), env=env,
            capture_output=True, text=True, timeout=300,
        )
        assert r.returncode == 4, r.stdout + r.stderr
    finally:
        lock.release()


def test_python_m_version_subprocess():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(conftest.PROJECT_ROOT)
    r = subprocess.run(
        [sys.executable, "-m", "backuper", "--version"],
        cwd=str(conftest.PROJECT_ROOT), env=env,
        capture_output=True, text=True, timeout=120,
    )
    assert r.returncode == 0, r.stderr
    assert f"backuper {__version__}" in r.stdout
