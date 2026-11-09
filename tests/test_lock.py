"""Unit tests for backuper.lock: OS-level job locking semantics."""

import os
import subprocess
import sys

import conftest
import pytest

from backuper.lock import JobLock

# Second-acquire probe run in a SEPARATE process: byte-range locks are
# per-handle, so a foreign process is the honest "another backuper".
_SECOND_ACQUIRE = (
    "import sys\n"
    "from backuper.lock import JobLock\n"
    "from backuper.errors import LockHeldError\n"
    "try:\n"
    "    JobLock(sys.argv[1]).acquire()\n"
    "except LockHeldError:\n"
    "    print('LOCKED')\n"
    "    raise SystemExit(3)\n"
    "print('ACQUIRED')\n"
    "raise SystemExit(0)\n"
)


def _subprocess_acquire(job_dir: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(conftest.PROJECT_ROOT)
    return subprocess.run(
        [sys.executable, "-c", _SECOND_ACQUIRE, job_dir],
        env=env, capture_output=True, text=True, timeout=120,
    )


def test_second_process_acquire_raises_lock_held(tmp_path):
    lock = JobLock(tmp_path)
    lock.acquire()
    try:
        r = _subprocess_acquire(str(tmp_path))
        assert r.returncode == 3, r.stdout + r.stderr
        assert "LOCKED" in r.stdout
    finally:
        lock.release()


def test_release_then_reacquire(tmp_path):
    lock = JobLock(tmp_path)
    lock.acquire()
    lock.release()
    lock2 = JobLock(tmp_path)  # fresh instance, same dir
    lock2.acquire()
    lock2.release()


def test_lock_file_persists_after_release(tmp_path):
    lock_path = tmp_path / ".lock"
    lock = JobLock(tmp_path)
    lock.acquire()
    assert lock_path.is_file()
    lock.release()
    assert lock_path.is_file()  # NEVER deleted (race avoidance by design)


def test_context_manager_form(tmp_path):
    lock_path = tmp_path / ".lock"
    with JobLock(tmp_path) as lock:
        assert lock_path.is_file()
        assert lock._fd is not None
    # after the with block the lock must be free again
    lock2 = JobLock(tmp_path)
    lock2.acquire()
    lock2.release()


def test_release_is_idempotent(tmp_path):
    lock = JobLock(tmp_path)
    lock.acquire()
    lock.release()
    lock.release()  # must not raise
    with JobLock(tmp_path):
        pass


def test_double_acquire_same_instance_rejected(tmp_path):
    lock = JobLock(tmp_path)
    lock.acquire()
    try:
        with pytest.raises(RuntimeError):
            lock.acquire()
    finally:
        lock.release()


def test_holder_info_written(tmp_path):
    import os as _os

    lock_path = tmp_path / ".lock"
    with JobLock(tmp_path):
        pass
    # read AFTER release: the byte-range lock on byte 0 blocks readers
    text = lock_path.read_text(encoding="utf-8")
    assert f"PID {_os.getpid()}" in text
