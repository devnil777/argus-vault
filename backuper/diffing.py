"""Diff of the previous snapshot against the current scan -> DiffResult.

The comparison key is ``(fn, sz, mt_ns)``. The "skipped" semantics from
the spec map onto the rules below (``prev``/``cur`` are the entries for
the same ``fn`` in the previous and current snapshot):

1. prev ``skipped``, cur readable -> **added** regardless of sz/mt: its
   current content is in NO archive of the chain (the last archive does
   not contain it).
2. prev ``skipped``, cur ``skipped`` again -> nothing (carried skip; it
   never lands in ``deleted_files`` while present).
3. prev entry (skipped or not) missing in cur -> ``deleted_files`` (a
   skipped-and-now-gone file belongs into ``delete_files.txt``).
4. prev archived, cur ``skipped`` -> nothing added, nothing deleted: the
   old version stays authoritative in the chain.
5. both archived -> added iff ``sz != prev.sz or mt_ns != prev.mt_ns``
   (an mtime-only change counts; a content-only change with identical
   size and mtime is an accepted miss).
6. in cur, not in prev -> added, UNLESS cur is skipped (a file that
   cannot be read is in no archive yet; treat as a carried skip and
   retry later). Renames naturally appear as a delete plus an add.
"""

from __future__ import annotations

from dataclasses import dataclass

from backuper.models import Snapshot


@dataclass
class DiffResult:
    """What one diff run has to store and delete."""

    added: list[str]             # fn to store in this diff archive (sorted)
    deleted_files: list[str]     # for .backup/delete_files.txt (sorted; ALL
                                 # vanished files incl. those under deleted dirs)
    deleted_dirs: list[str]      # for .backup/delete_dirs.txt (sorted; TOPMOST
                                 # deleted dirs only)
    added_empty_dirs: list[str]  # NEW empty dirs this diff must store (sorted;
                                 # empty dirs absent from prev.dir_set())

    @property
    def is_no_op(self) -> bool:
        """True iff there is nothing to do -> run produces <name>_nothing.log."""
        return not (self.added or self.deleted_files
                    or self.deleted_dirs or self.added_empty_dirs)


def _topmost_dirs(dirs: set[str]) -> list[str]:
    """Reduce a set of vanished dirs to its topmost members.

    Drops ``d`` if a strict ancestor of ``d`` (a proper prefix of its
    components) is also in the set -- deleting ``x`` deletes ``x/y`` and
    ``x/y/z`` implicitly. Sorted.
    """
    result: list[str] = []
    for d in dirs:
        parts = d.split("/")
        if any("/".join(parts[:i]) in dirs for i in range(1, len(parts))):
            continue
        result.append(d)
    return sorted(result)


def compute_diff(prev: Snapshot, current: Snapshot) -> DiffResult:
    """Compare the previous snapshot with the current scan result."""
    prev_map = prev.file_map()
    cur_map = current.file_map()

    added: list[str] = []
    for fn, cur in cur_map.items():
        old = prev_map.get(fn)
        if old is None:
            if not cur.skipped:                 # rule 6 (renames: half 2)
                added.append(fn)                # new skipped -> carried skip, retry later
        elif old.skipped:
            if not cur.skipped:
                added.append(fn)                # rule 1: re-add regardless of sz/mt
            # else rule 2: carried skip, nothing to do
        elif cur.skipped:
            continue                            # rule 4: old version stays authoritative
        elif cur.sz != old.sz or cur.mt_ns != old.mt_ns:
            added.append(fn)                    # rule 5 (mtime-only change counts)

    deleted_files: list[str] = [
        fn for fn in prev_map if fn not in cur_map  # rule 3 (incl. skipped-and-gone)
    ]

    prev_dirs = prev.dir_set()
    cur_dirs = current.dir_set()
    deleted_dirs = _topmost_dirs(prev_dirs - cur_dirs)

    # An existing dir that BECAME empty does not count: it is still in
    # prev.dir_set(), and its vanished files already make the diff non-empty.
    added_empty_dirs = sorted(set(current.empty_dirs) - prev_dirs)

    return DiffResult(
        added=sorted(added),
        deleted_files=sorted(deleted_files),
        deleted_dirs=deleted_dirs,
        added_empty_dirs=added_empty_dirs,
    )
