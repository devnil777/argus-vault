"""Unit tests for backuper.diffing: the six comparison rules and friends."""

from backuper.diffing import compute_diff
from backuper.models import FileEntry, Snapshot


def F(fn, sz=1, mt=1000, skipped=False):
    return FileEntry(fn=fn, sz=sz, mt_ns=mt, skipped=skipped)


def snap(entries=(), empty_dirs=()):
    return Snapshot(files=list(entries), empty_dirs=list(empty_dirs))


# --- rule 1: prev skipped, now readable -> re-add regardless of sz/mt ------

def test_rule1_skipped_readded_when_readable():
    prev = snap([F("f", 10, 100, skipped=True)])
    cur = snap([F("f", 2, 200)])
    d = compute_diff(prev, cur)
    assert d.added == ["f"]


def test_rule1_skipped_readded_even_with_identical_sz_and_mtime():
    prev = snap([F("f", 10, 100, skipped=True)])
    cur = snap([F("f", 10, 100)])
    assert compute_diff(prev, cur).added == ["f"]


# --- rule 2: carried skip -> nothing to do, never a delete ------------------

def test_rule2_carried_skip_not_added_not_deleted():
    prev = snap([F("f", 10, 100, skipped=True), F("gone.txt", 1, 1)])
    cur = snap([F("f", 11, 101, skipped=True)])
    d = compute_diff(prev, cur)
    assert d.added == []
    assert d.deleted_files == ["gone.txt"]      # only the really-gone file
    assert not d.is_no_op                        # because of gone.txt


# --- rule 3: gone (skipped or not) -> deleted_files --------------------------

def test_rule3_skipped_and_gone_is_deleted():
    prev = snap([F("f", 10, 100, skipped=True)])
    cur = snap([])
    d = compute_diff(prev, cur)
    assert d.deleted_files == ["f"]


def test_rule3_archived_and_gone_is_deleted():
    prev = snap([F("f", 10, 100)])
    cur = snap([])
    assert compute_diff(prev, cur).deleted_files == ["f"]


# --- rule 4: archived before, locked now -> old version stays ---------------

def test_rule4_archived_now_skipped_stays_authoritative():
    prev = snap([F("f", 10, 100)])
    cur = snap([F("f", 10, 100, skipped=True)])
    d = compute_diff(prev, cur)
    assert d.added == []
    assert d.deleted_files == []
    assert d.is_no_op


# --- rule 5: sz / mt comparison for both-archived ----------------------------

def test_rule5_size_change_detected():
    prev = snap([F("f", 10, 100)])
    cur = snap([F("f", 11, 100)])
    assert compute_diff(prev, cur).added == ["f"]


def test_rule5_mtime_only_change_detected():
    prev = snap([F("f", 10, 100)])
    cur = snap([F("f", 10, 200)])
    assert compute_diff(prev, cur).added == ["f"]


def test_rule5_unchanged_not_added():
    prev = snap([F("f", 10, 100)])
    cur = snap([F("f", 10, 100)])
    d = compute_diff(prev, cur)
    assert d.added == [] and d.is_no_op


# --- rule 6: new files and renames -------------------------------------------

def test_rule6_new_file_added():
    prev = snap([F("a.txt", 1, 1)])
    cur = snap([F("a.txt", 1, 1), F("b.txt", 1, 1)])
    assert compute_diff(prev, cur).added == ["b.txt"]


def test_rule6_rename_is_delete_plus_add():
    prev = snap([F("old.txt", 1, 1)])
    cur = snap([F("new.txt", 1, 1)])
    d = compute_diff(prev, cur)
    assert d.added == ["new.txt"]
    assert d.deleted_files == ["old.txt"]


# --- deleted_dirs: topmost reduction ------------------------------------------

def test_deleted_dirs_reduced_to_topmost():
    prev = snap([F("x/y/z.txt", 1, 1), F("x/w.txt", 1, 1), F("p/keep.txt", 1, 1)])
    cur = snap([F("p/keep.txt", 1, 1)])
    d = compute_diff(prev, cur)
    assert d.deleted_dirs == ["x"]
    assert d.deleted_files == ["x/w.txt", "x/y/z.txt"]   # ALL vanished files


def test_deleted_dirs_partial_subtree():
    prev = snap([F("x/y/a.txt", 1, 1), F("x/b.txt", 1, 1)])
    cur = snap([F("x/b.txt", 1, 1)])
    d = compute_diff(prev, cur)
    assert d.deleted_dirs == ["x/y"]
    assert d.deleted_files == ["x/y/a.txt"]


# --- added_empty_dirs vs prev.dir_set() ---------------------------------------

def test_new_empty_dirs_all_added():
    prev = snap([F("a.txt", 1, 1)])
    cur = snap([F("a.txt", 1, 1)], empty_dirs=["n1", "n1/n2", "n1/n2/n3"])
    d = compute_diff(prev, cur)
    assert d.added_empty_dirs == ["n1", "n1/n2", "n1/n2/n3"]


def test_new_empty_subdir_under_existing_dir_added():
    prev = snap([F("d/f.txt", 1, 1)])                 # "d" exists (has a file)
    cur = snap([F("d/f.txt", 1, 1)], empty_dirs=["d/empty_child"])
    d = compute_diff(prev, cur)
    assert d.added_empty_dirs == ["d/empty_child"]


def test_dir_becoming_empty_is_not_an_added_empty_dir():
    prev = snap([F("d/f.txt", 1, 1)])                 # "d" in prev.dir_set()
    cur = snap([], empty_dirs=["d"])                  # "d" still exists, now empty
    d = compute_diff(prev, cur)
    assert d.added_empty_dirs == []
    assert d.deleted_files == ["d/f.txt"]


# --- is_no_op -------------------------------------------------------------------

def test_is_no_op():
    prev = snap([F("a", 1, 1)])
    assert compute_diff(prev, snap([F("a", 1, 1)])).is_no_op
    assert not compute_diff(prev, snap([F("a", 1, 2)])).is_no_op
    assert not compute_diff(prev, snap([F("a", 2, 1)])).is_no_op
    assert not compute_diff(prev, snap([], empty_dirs=["n"])).is_no_op
    d = compute_diff(prev, snap([]))
    assert not d.is_no_op and d.deleted_files == ["a"]
