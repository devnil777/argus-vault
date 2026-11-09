"""Filesystem scan of the source directory -> :class:`Snapshot` + warnings.

Walks the ``\\\\?\\``-prefixed source tree once with ``os.scandir`` recursion
and records every archivable file as a :class:`~backuper.models.FileEntry`.

Long paths
    Every filesystem operation goes through
    :func:`backuper.rar_runner.winapi_path` prefixed paths. Relative ``fn``
    values are computed by string slicing from the prefixed root length
    (``os.path.relpath`` cannot parse ``\\\\?\\`` paths) and use forward
    slashes.

Reparse points
    Symlinks (``IO_REPARSE_TAG_SYMLINK``) and junctions/mount points
    (``IO_REPARSE_TAG_MOUNT_POINT``) are skipped entirely: not recorded,
    not recursed into, one warning each. Any OTHER reparse tag (OneDrive
    cloud placeholders and friends) is treated as a normal file/dir.

Exclusions
    Files whose extension is in ``config.exclude_extensions`` and dirs
    matching ``config.exclude_dirs`` are dropped silently (no warning, no
    recursion, no entry). Bare directory names match that name anywhere in
    the tree; absolute Windows full paths match that directory and its
    descendants. Matching is case-insensitive.
    Exclusions are evaluated BEFORE the reparse-point and readability
    checks: an excluded entry never warns (a junction named like an
    excluded dir is pruned silently) and an unreadable excluded entry is
    dropped silently too.

Lock probing
    Files whose extension is in ``config.lock_check_extensions`` are
    probed with ``CreateFileW(GENERIC_READ, share=read|write)``; an open
    failure (INVALID_HANDLE_VALUE -> sharing violation) means the file
    cannot be archived: it is recorded with ``skipped=True`` KEEPING its
    real size/mtime from stat, plus a ``locked:`` warning.

Empty dirs
    Computed bottom-up from the recursion's return value: a directory is
    in ``Snapshot.empty_dirs`` iff its subtree contains ZERO recorded
    files (a dir holding only empty subdirs is itself empty). The top
    source dir itself is never listed anywhere.

Case handling: ``fn`` keys are case-SENSITIVE and never casefolded -- two
names differing only by case are legal on NTFS and stay distinct entries.
Only the exclusion matching is case-insensitive (as configured).
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from backuper.config import Config, normalize_exclude_dir
from backuper.models import FileEntry, Snapshot
from backuper.rar_runner import winapi_path

# Reparse tags that mean "a link": skip the entry entirely. Any other
# reparse tag (e.g. OneDrive placeholders) is a normal file/dir for us.
IO_REPARSE_TAG_SYMLINK = 0xA000000C
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
_LINK_REPARSE_TAGS = frozenset({IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT})

# CreateFileW constants for the lock probe (see _probe_readable).
_GENERIC_READ = 0x80000000
_FILE_SHARE_READWRITE = 0x00000003  # FILE_SHARE_READ | FILE_SHARE_WRITE
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _probe_readable(path: str) -> bool:
    """Best-effort read-open probe: False means the file is locked.

    ``CreateFileW`` with GENERIC_READ and FILE_SHARE_READ|FILE_SHARE_WRITE
    succeeds on any file no other process holds an exclusive share over;
    a sharing violation (INVALID_HANDLE_VALUE, error retrievable via
    ``ctypes.GetLastError``) means RAR would fail on it too -- the caller
    records the file as ``skipped`` instead of letting the run die.
    Modeled after ``diagnose._hold_exclusive_lock``.
    """
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    ]
    k32.CloseHandle.restype = ctypes.c_bool
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = k32.CreateFileW(
        path,
        _GENERIC_READ,
        _FILE_SHARE_READWRITE,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle is None or handle == _INVALID_HANDLE_VALUE:
        return False
    k32.CloseHandle(handle)
    return True


def is_excluded_dir_name(name: str, exclude_dirs: list[str]) -> bool:
    """Case-insensitive single-component directory-name match.

    Absolute Windows paths in ``exclude_dirs`` are not name matches;
    ``name`` is one path component as delivered by ``os.scandir``.
    """
    lowered = name.lower()
    return any(
        not ntpath.isabs(normalized := normalize_exclude_dir(entry))
        and lowered == normalized
        for entry in exclude_dirs
    )


def _path_is_excluded(path: str, exclude_paths: tuple[str, ...]) -> bool:
    """Match an absolute Windows path or a descendant on a component edge."""
    canonical = normalize_exclude_dir(path)
    return any(
        canonical == excluded
        or canonical.startswith(excluded.rstrip("\\") + "\\")
        for excluded in exclude_paths
    )


def leaves(empty_dirs: list[str]) -> list[str]:
    """Dirs from the set that have NO other dir from the set below them.

    ``d`` is not a leaf if any ``e != d`` starts with ``d + "/"``. Sorted.
    This is what goes into RAR listfiles and cross-checks: restoring the
    leaves restores all ancestors implicitly.
    """
    result = [
        d for d in empty_dirs
        if not any(e != d and e.startswith(d + "/") for e in empty_dirs)
    ]
    return sorted(result)


@dataclass
class ScanStats:
    """Mutable counters filled while ``scan_source`` walks the tree.

    ``files`` counts the entries RECORDED in the snapshot (both archivable
    and skipped); ``bytes`` covers archivable ones only. ``dirs`` counts the
    directories actually walked (excluded and reparse-point dirs are not
    walked). ``empty_dirs`` is only known post-walk (= len of the snapshot
    list, mirrored here for one-stop reporting).
    """

    files: int = 0
    bytes: int = 0
    dirs: int = 0
    empty_dirs: int = 0
    files_excluded: int = 0      # dropped by exclude_extensions
    dirs_excluded: int = 0       # pruned by exclude_dirs (subtree not walked)
    links_skipped: int = 0       # junction/symlink entries (files + dirs)
    files_skipped: int = 0       # locked or unreadable (recorded as skipped)


def scan_source(source: Path, config: Config, *,
                stats: ScanStats | None = None,
                progress: Callable[[], None] | None = None,
                ) -> tuple[Snapshot, list[str]]:
    """Walk ``source`` and return ``(snapshot, warnings)``.

    The snapshot's ``files`` are sorted by ``fn`` (case-sensitive) and
    ``empty_dirs`` is sorted; ``fn`` values are relative forward-slash
    paths. ``warnings`` holds English one-liners (may be empty) for every
    skipped reparse point, locked file and unreadable entry. Raises
    ``OSError`` if the source itself cannot be stated.

    ``stats``, when given, is updated in place with the per-category
    counters (a fresh one is created otherwise). ``progress``, when given,
    is called after every visited entry — throttling the repaints is the
    renderer's job (see progress.ScanProgress).
    """
    if stats is None:
        stats = ScanStats()
    root = winapi_path(source)
    os.lstat(root)  # fail fast with the real OSError if the source is gone

    files: list[FileEntry] = []
    empty_dirs: list[str] = []
    warnings: list[str] = []
    exclude_exts = frozenset(config.exclude_extensions)
    lock_exts = frozenset(config.lock_check_extensions)
    exclude_paths = tuple(
        normalized
        for entry in config.exclude_dirs
        if ntpath.isabs(normalized := normalize_exclude_dir(entry))
    )

    # The source root is not visited as a child entry, so prune it explicitly
    # when it is itself excluded or lies below an excluded absolute path.
    if _path_is_excluded(root, exclude_paths):
        stats.dirs_excluded += 1
        stats.empty_dirs = 0
        return Snapshot(files=[], empty_dirs=[]), warnings

    def rel_of(full: str) -> str:
        """Relative forward-slash path by slicing off the prefixed root."""
        return full[len(root):].lstrip("\\").replace("\\", "/")

    def scan_dir(dir_path: str) -> bool:
        """Scan one directory; return True iff its subtree has any file.

        ``dir_path`` is a ``\\\\?\\``-prefixed path under ``root``.
        """
        has_files = False
        try:
            with os.scandir(dir_path) as it:
                # Materialize (and sort) while the handle is open; DirEntry
                # keeps its find data, so attributes stay valid afterwards.
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            warnings.append(f"unreadable: {rel_of(dir_path) or '.'} ({exc})")
            return True  # cannot verify emptiness -> never report as empty

        for entry in entries:
            if progress is not None:
                progress()
            rel = rel_of(entry.path)
            ext = os.path.splitext(entry.name)[1].lower()
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                # Trailing-dot/reserved names and friends: name-based
                # exclusions still apply silently; otherwise record without
                # size/mtime, keeping the entry out of the warning-less void.
                if _path_is_excluded(entry.path, exclude_paths):
                    stats.dirs_excluded += 1
                elif ext in exclude_exts:
                    stats.files_excluded += 1
                elif is_excluded_dir_name(entry.name, config.exclude_dirs):
                    stats.dirs_excluded += 1
                else:
                    files.append(FileEntry(fn=rel, sz=0, mt_ns=0, skipped=True))
                    warnings.append(f"unreadable: {rel} ({exc})")
                    stats.files += 1
                    stats.files_skipped += 1
                    has_files = True
                continue

            is_dir = stat.S_ISDIR(st.st_mode)

            # Exclusions are evaluated FIRST (before the reparse-point check):
            # an excluded entry is dropped silently whatever its readability
            # or link status is -- no warning, no snapshot record.
            if is_dir and (
                    is_excluded_dir_name(entry.name, config.exclude_dirs)
                    or _path_is_excluded(entry.path, exclude_paths)):
                stats.dirs_excluded += 1
                continue  # prune the whole subtree, silently
            if not is_dir and ext in exclude_exts:
                stats.files_excluded += 1
                continue  # silently

            if (st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
                    and st.st_reparse_tag in _LINK_REPARSE_TAGS):
                warnings.append(
                    f"skipped reparse point (junction/symlink): {rel}")
                stats.links_skipped += 1
                continue  # no recursion, no record
            # Other reparse tags: fall through, treated as normal.

            if is_dir:
                stats.dirs += 1
                if scan_dir(entry.path):
                    has_files = True
                else:
                    empty_dirs.append(rel)
                continue

            # A file (or a non-link reparse entry such as a cloud placeholder).
            # Regular files get a plain os.stat after the reparse check so
            # sz/mt_ns come from the real file, not cached find data.
            try:
                fst = os.stat(entry.path)
            except OSError as exc:
                files.append(FileEntry(fn=rel, sz=0, mt_ns=0, skipped=True))
                warnings.append(f"unreadable: {rel} ({exc})")
                stats.files += 1
                stats.files_skipped += 1
                has_files = True
                continue

            if ext in lock_exts and not _probe_readable(entry.path):
                files.append(FileEntry(
                    fn=rel, sz=fst.st_size, mt_ns=fst.st_mtime_ns, skipped=True))
                warnings.append(f"locked: {rel}")
                stats.files += 1
                stats.files_skipped += 1
            else:
                files.append(FileEntry(fn=rel, sz=fst.st_size, mt_ns=fst.st_mtime_ns))
                stats.files += 1
                stats.bytes += fst.st_size
            has_files = True

        return has_files

    scan_dir(root)  # the top source dir itself is not recorded anywhere
    files.sort(key=lambda e: e.fn)
    empty_dirs.sort()
    stats.empty_dirs = len(empty_dirs)
    return Snapshot(files=files, empty_dirs=empty_dirs), warnings
