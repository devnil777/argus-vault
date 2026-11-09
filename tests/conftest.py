"""Shared fixtures and helpers for the backuper test suite.

The suite runs the REAL Rar.exe end-to-end (kept under ~3 minutes by
using tiny KB-range archives); every RAR-dependent test module skips
together with reason "Rar.exe not found" when find_rar fails. Pure-python
modules (models/config/lock/scanner/diffing) are tested without RAR.

Ground rules: everything lives under pytest tmp dirs + the project root;
no network; each test gets a fresh job dir; cleanup is handled by
pytest's tmp_path.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import subprocess  # noqa: F401 — re-exported for test modules' convenience
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backuper import chain, rar_runner  # noqa: E402

try:
    RAR_PATH: Path | None = rar_runner.find_rar(None)
except FileNotFoundError:
    RAR_PATH = None

# Sentinel for make_tree/Job.make_source: create the path as an EMPTY dir.
EMPTY_DIR = object()


def default_config_text(src: Path) -> str:
    """The standard job config used by the ``job`` fixture."""
    return (
        f"source: {Path(src).as_posix()}\n"
        "exclude_extensions:\n"
        "  - .tmp\n"
        "lock_check_extensions:\n"
        "  - .pst\n"
    )


def make_tree(src: Path, spec: dict, uid: str | None = None) -> None:
    """Create source entries ``{'rel/path.txt': content}`` (long-path safe).

    content: str/bytes (file payload; str gets a unique ``uid`` prefix),
    None (unique default content) or EMPTY_DIR (empty directory, parents
    created). All writes go through ``\\\\?\\`` paths so >260-char trees
    work regardless of the machine's long-path policy.
    """
    prefix = f"{uid}:" if uid else ""
    for rel, content in spec.items():
        rel = rel.replace("\\", "/").strip("/")
        target = src.joinpath(*rel.split("/"))
        os.makedirs(rar_runner.winapi_path(target.parent), exist_ok=True)
        if content is EMPTY_DIR:
            os.makedirs(rar_runner.winapi_path(target), exist_ok=True)
            continue
        if content is None:
            data = f"{prefix}{rel}\n".encode()
        elif isinstance(content, bytes):
            data = content
        else:
            data = f"{prefix}{rel}:{content}\n".encode()
        with open(rar_runner.winapi_path(target), "wb") as fh:
            fh.write(data)


@dataclass
class Job:
    """A backup job directory + source dir + convenience accessors."""

    dir: Path
    src: Path
    uid: str
    rar: rar_runner.RarRunner

    def make_source(self, **spec) -> None:
        """Create files/empty dirs under the source root (see make_tree)."""
        make_tree(self.src, spec, uid=self.uid)

    # -- config -------------------------------------------------------------
    def config_path(self) -> Path:
        return self.dir / "config.yaml"

    def write_config(self, text: str) -> None:
        self.config_path().write_text(text, encoding="utf-8", newline="")

    # -- chain accessors ------------------------------------------------------
    def epoch_dirs(self) -> list[Path]:
        return chain.list_epochs(self.dir)

    def latest_epoch(self) -> Path:
        return chain.latest_epoch(self.dir)

    def archives(self) -> list[Path]:
        return chain.epoch_archives(self.latest_epoch())

    def full_archive(self) -> Path:
        return chain.epoch_full(self.latest_epoch())

    def tip(self) -> Path:
        return chain.tip_archive(self.latest_epoch())

    def manifest_of(self, archive: Path):
        return chain.load_manifest(self.rar, archive)

    def snapshot_of(self, archive: Path):
        return chain.load_snapshot(self.rar, archive)


@pytest.fixture()
def rar():
    """A RarRunner bound to the discovered Rar.exe (skip when absent)."""
    if RAR_PATH is None:
        pytest.skip("Rar.exe not found")
    return rar_runner.RarRunner(RAR_PATH)


@pytest.fixture()
def job(tmp_path, rar):
    """Fresh backup job: job dir + config.yaml + unique lock-check file.

    The source dir contains one small unique ``vault.pst`` (the configured
    lock_check_extensions target) plus whatever the test adds via
    ``job.make_source(**spec)``.
    """
    jb = tmp_path / "job"
    src = tmp_path / "src"
    jb.mkdir()
    src.mkdir()
    j = Job(dir=jb, src=src, uid=uuid.uuid4().hex[:8], rar=rar)
    j.write_config(default_config_text(src))
    j.make_source(**{"vault.pst": None})
    return j


def run_cli(argv) -> int:
    """Invoke ``backuper.cli.main`` in-process; returns the exit code.

    Commands all take explicit dir args, so no cwd monkeypatching is
    needed. Console noise is swallowed by pytest's capsys when asserted
    on, and simply discarded otherwise.
    """
    from backuper.cli import main

    return main([str(a) for a in argv])


# ---------------------------------------------------------------------------
# OS-level exclusive file lock (share-mode 0) held from a helper thread
# ---------------------------------------------------------------------------

_GENERIC_READ = 0x80000000
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _hold_exclusive(path: str, ready: threading.Event,
                    release: threading.Event, result: dict) -> None:
    """Open ``path`` with share-mode 0 and hold it until ``release``."""
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    ]
    k32.CloseHandle.restype = ctypes.c_bool
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = k32.CreateFileW(path, _GENERIC_READ, 0, None,
                             _OPEN_EXISTING, _FILE_ATTRIBUTE_NORMAL, None)
    if handle is None or handle == _INVALID_HANDLE_VALUE:
        result["handle"] = None
        result["error"] = ctypes.GetLastError()
    else:
        result["handle"] = handle
    ready.set()
    release.wait(60)
    if result.get("handle"):
        k32.CloseHandle(result["handle"])


@contextlib.contextmanager
def exclusive_lock(path: Path):
    """Hold an exclusive (share-mode 0) open on ``path`` for the block."""
    ready, release = threading.Event(), threading.Event()
    result: dict = {}
    t = threading.Thread(target=_hold_exclusive,
                         args=(str(path), ready, release, result), daemon=True)
    t.start()
    if not ready.wait(10):
        release.set()
        t.join(5)
        pytest.fail(f"lock holder thread never became ready for {path}")
    if not result.get("handle"):
        release.set()
        t.join(5)
        pytest.fail(f"could not open {path} exclusively (error {result.get('error')})")
    try:
        yield
    finally:
        release.set()
        t.join(5)


# ---------------------------------------------------------------------------
# Archive introspection helpers
# ---------------------------------------------------------------------------

def stored_files(job: Job, archive: Path) -> tuple[dict[str, int], set[str]]:
    """(files name->size, folders) stored in ``archive``; asserts no dupes."""
    from backuper.archiver import split_entries

    entries = rar_runner.list_entries(job.rar, archive)
    files, folders, problems = split_entries(entries)
    assert not problems, problems
    return files, folders


def member_text(job: Job, archive: Path, member: str) -> str:
    """Read one stored member (e.g. '.backup/delete_files.txt') as text."""
    raw = rar_runner.read_service_member(job.rar, archive, member)
    return raw.decode("utf-8")
