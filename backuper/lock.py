"""OS-level exclusive lock on a backup job directory.

Uses the lock file ``<job_dir>/.lock`` plus an ``msvcrt.locking`` byte-range
lock on byte 0, so the kernel releases the lock automatically when the
process dies for any reason -- no stale-lock detection is ever needed.

Deliberate rules:

- The lock file is NEVER deleted. Deleting it creates a 3-way race
  (holder A has it locked, B has the same file open and waits, A deletes
  and unlocks, C creates a NEW file and locks it while B still waits on
  the now-unlinked one). The file stays on disk as a 0-byte-plus-info file.
- The file descriptor is held in an instance attribute for the object's
  lifetime: if it were garbage collected the Windows byte-range lock
  would silently vanish with it.
- After acquiring, a short info line (PID + UTC time) is written into the
  file on a best-effort basis for human inspection; a failure to write it
  never fails the run.
"""

from __future__ import annotations

import datetime
import msvcrt
import os
from pathlib import Path

from backuper.errors import LockHeldError


class JobLock:
    """Exclusive lock on ``<job_dir>/.lock``, held for the object's lifetime.

    Context manager::

        with JobLock(job_dir):
            ...  # only this process may run the job now
    """

    def __init__(self, job_dir: Path) -> None:
        self._path = Path(job_dir) / ".lock"
        self._fd: int | None = None

    def acquire(self) -> None:
        """Take the exclusive lock (raises :class:`LockHeldError` if held elsewhere)."""
        if self._fd is not None:
            raise RuntimeError(f"JobLock already acquired: {self._path}")
        fd = os.open(self._path, os.O_CREAT | os.O_RDWR | os.O_BINARY)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            os.close(fd)
            raise LockHeldError(
                f"job is locked by another backuper process ({self._holder_desc()})"
            ) from exc
        self._fd = fd
        # Best-effort info line for humans peeking at .lock; never fail the
        # run over it. Back to offset 0 for any future reader of this fd.
        try:
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, f"locked by PID {os.getpid()} at {self._utc_now_iso()}\n".encode())
            os.lseek(fd, 0, os.SEEK_SET)
        except OSError:
            pass

    def release(self) -> None:
        """Unlock byte 0 and close the fd; idempotent. The .lock file stays."""
        fd = self._fd
        if fd is None:
            return
        self._fd = None
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(fd)  # closes the last handle -> kernel drops any lock anyway

    def __enter__(self) -> JobLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.release()

    def _holder_desc(self) -> str:
        """Best-effort description of the current holder for the error message."""
        try:
            with open(self._path, encoding="utf-8", errors="replace") as fh:
                line = fh.readline(200).strip()
        except OSError:
            line = ""
        return line if line else f"lock file: {self._path}"

    @staticmethod
    def _utc_now_iso() -> str:
        now = datetime.datetime.now(datetime.UTC)
        return now.isoformat(timespec="seconds").replace("+00:00", "Z")
