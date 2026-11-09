"""Exception hierarchy with CLI exit codes.

Every error carries a human-readable message. ``cli`` catches
``BackuperError`` and exits with the class ``exit_code``:

    1 preflight failed (rar not found, source missing, bad job dir layout)
    2 a RAR invocation returned nonzero
    3 verification failed
    4 job lock held by another backuper process
    5 config/epoch error
    6 no-op: a diff had nothing to do (not really an error -- raised to
      unwind to cli, which maps it to exit code 6)
"""

from __future__ import annotations


class BackuperError(Exception):
    """Base class for all backuper errors; carries a CLI exit code."""

    exit_code: int = 1


class PreflightError(BackuperError):
    """Pre-run checks failed: rar not found, source missing, bad job dir layout."""

    exit_code = 1


class RarError(BackuperError):
    """A RAR invocation returned a nonzero exit code."""

    exit_code = 2


class VerificationError(BackuperError):
    """Post-archive verification or chain verification failed."""

    exit_code = 3


class LockHeldError(BackuperError):
    """The job is locked by another backuper process."""

    exit_code = 4


class ConfigError(BackuperError):
    """config.yaml is missing or invalid."""

    exit_code = 5


class EpochError(ConfigError):
    """Epoch problem: metadata missing/broken, previous archive unavailable, duplicate full."""

    exit_code = 5


class NoOpResult(BackuperError):
    """A diff found nothing to do. Not a real error -- raised to unwind to cli."""

    exit_code = 6
