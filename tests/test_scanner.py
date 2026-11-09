"""Unit tests for backuper.scanner (no RAR needed)."""

import os
import subprocess
from pathlib import Path

import conftest
import pytest

from backuper.config import config_from_bytes
from backuper.rar_runner import winapi_path
from backuper.scanner import ScanStats, leaves, scan_source

EMPTY_DIR = conftest.EMPTY_DIR


def cfg_for(src, **extra):
    """Build a Config via the public bytes path (source + YAML list extras)."""
    lines = [f"source: {Path(src).as_posix()}"]
    for key, val in extra.items():
        lines.append(f"{key}: {val}")
    return config_from_bytes("\n".join(lines).encode("utf-8"))


def fns(snapshot):
    return [e.fn for e in snapshot.files]


def test_extension_exclusion_case_insensitive(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    conftest.make_tree(src, {"keep.txt": "k", "skip.TMP": "s", "archive.bak": "b"})
    stats = ScanStats()
    snap, warnings = scan_source(src, cfg_for(src, exclude_extensions="['.tmp', '.BAK']"),
                                 stats=stats)
    assert fns(snap) == ["keep.txt"]
    assert warnings == []
    # make_tree writes str payloads as "{rel}:{content}\n" -> "keep.txt:k\n" = 11 B
    assert (stats.files, stats.files_excluded, stats.bytes) == (1, 2, 11)


def test_dir_name_pruning_case_insensitive(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    conftest.make_tree(src, {
        "Node_Modules/x.js": "x",
        "keep.txt": "k",
        "docs/readme.txt": "r",
        "docs/node_modules/nested.js": "n",
    })
    stats = ScanStats()
    snap, warnings = scan_source(src, cfg_for(src, exclude_dirs="['node_modules']"),
                                 stats=stats)
    assert fns(snap) == ["docs/readme.txt", "keep.txt"]
    assert warnings == []
    assert snap.empty_dirs == []
    assert (stats.dirs, stats.dirs_excluded) == (1, 2)  # docs walked; both name matches pruned


def test_absolute_dir_exclusion_matches_exact_path_and_subtree_not_prefix_sibling(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    conftest.make_tree(src, {
        "archive/exact.txt": "x",
        "archive/child/deep.txt": "d",
        "archive2/keep.txt": "k",
        "keep.txt": "r",
    })
    stats = ScanStats()
    snap, warnings = scan_source(
        src,
        cfg_for(src, exclude_dirs=repr([str(src / "archive")])),
        stats=stats,
    )

    assert fns(snap) == ["archive2/keep.txt", "keep.txt"]
    assert warnings == []
    assert stats.dirs_excluded == 1


def test_absolute_dir_exclusion_normalizes_case_slashes_and_winapi_entry_paths(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    conftest.make_tree(src, {
        "Folder/Target/excluded.txt": "x",
        "Folder/Target2/kept.txt": "k",
    })
    excluded = str(src / "Folder" / "Target").replace("\\", "/").upper()
    snap, warnings = scan_source(
        src, cfg_for(src, exclude_dirs=repr([excluded])))

    assert fns(snap) == ["Folder/Target2/kept.txt"]
    assert warnings == []


@pytest.mark.parametrize("exclude_source_itself", [True, False])
def test_absolute_exclusion_prunes_source_root(tmp_path, exclude_source_itself):
    excluded = tmp_path / "excluded"
    src = excluded if exclude_source_itself else excluded / "source"
    src.mkdir(parents=True)
    conftest.make_tree(src, {"would-be-included.txt": "x"})
    stats = ScanStats()

    snap, warnings = scan_source(
        src,
        cfg_for(src, exclude_dirs=repr([str(excluded)])),
        stats=stats,
    )

    assert fns(snap) == []
    assert snap.empty_dirs == []
    assert warnings == []
    assert stats.dirs_excluded == 1


def test_empty_dir_semantics(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    conftest.make_tree(src, {
        "a/b/c": EMPTY_DIR,          # whole chain empty -> all three listed
        "top/inner1": EMPTY_DIR,     # dir with only empty subdirs is itself empty
        "top/inner2": EMPTY_DIR,
        "full/f.txt": "f",
        "full/emptysub": EMPTY_DIR,  # only the leaf subdir is empty
    })
    snap, warnings = scan_source(src, cfg_for(src))
    assert snap.empty_dirs == [
        "a", "a/b", "a/b/c",
        "full/emptysub",
        "top", "top/inner1", "top/inner2",
    ]
    assert warnings == []
    assert leaves(snap.empty_dirs) == [
        "a/b/c", "full/emptysub", "top/inner1", "top/inner2",
    ]


def test_junction_skipped_with_warning(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    target = tmp_path / "outside"
    conftest.make_tree(target, {"secret.txt": "s"})
    r = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(src / "link"), str(target)],
        capture_output=True,   # bytes: cmd prints OEM-encoded text
    )
    if r.returncode != 0:
        pytest.skip("junction creation failed: "
                    + (r.stderr or r.stdout).decode("utf-8", errors="replace").strip())
    conftest.make_tree(src, {"real.txt": "r"})

    stats = ScanStats()
    snap, warnings = scan_source(src, cfg_for(src), stats=stats)
    assert fns(snap) == ["real.txt"]          # link/secret.txt NOT recorded
    assert stats.links_skipped == 1
    assert "link" not in snap.empty_dirs
    assert any("link" in w and "reparse" in w for w in warnings)


def test_excluded_dir_junction_is_pruned_silently(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    target = tmp_path / "outside"
    conftest.make_tree(target, {"secret.txt": "s"})
    r = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(src / "node_modules"), str(target)],
        capture_output=True,   # bytes: cmd prints OEM-encoded text
    )
    if r.returncode != 0:
        pytest.skip("junction creation failed: "
                    + (r.stderr or r.stdout).decode("utf-8", errors="replace").strip())
    conftest.make_tree(src, {"real.txt": "r"})

    stats = ScanStats()
    snap, warnings = scan_source(src, cfg_for(src, exclude_dirs="['node_modules']"),
                                 stats=stats)
    assert fns(snap) == ["real.txt"]
    assert warnings == []                    # exclusion wins over reparse warning
    assert stats.dirs_excluded == 1
    assert stats.links_skipped == 0
    assert "node_modules" not in snap.empty_dirs


def test_long_path_file_captured_with_exact_size(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    rel = "/".join(["d" * 40] * 6 + ["f" * 20 + ".bin"])
    payload = os.urandom(1234)
    conftest.make_tree(src, {rel: payload})
    assert len(str(src.joinpath(*rel.split("/")))) > 260

    snap, warnings = scan_source(src, cfg_for(src))
    assert warnings == []
    assert len(snap.files) == 1
    entry = snap.files[0]
    assert entry.fn == rel
    assert entry.sz == 1234
    assert not entry.skipped


def test_lock_probe_marks_locked_pst_with_real_size_mtime(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    conftest.make_tree(src, {"db.pst": b"p" * 80, "free.pst": b"f" * 40})
    st = os.stat(winapi_path(src / "db.pst"))

    stats = ScanStats()
    with conftest.exclusive_lock(src / "db.pst"):
        snap, warnings = scan_source(src, cfg_for(src, lock_check_extensions="['.pst']"),
                                     stats=stats)
    assert stats.files_skipped == 1           # db.pst locked, free.pst fine
    fmap = snap.file_map()
    assert fmap["db.pst"].skipped is True
    assert fmap["db.pst"].sz == 80                       # real size kept
    assert fmap["db.pst"].mt_ns == st.st_mtime_ns        # real mtime kept
    assert fmap["free.pst"].skipped is False             # unlocked control
    assert any("locked: db.pst" in w for w in warnings)

    # after the lock is gone the file is archivable again
    snap2, warnings2 = scan_source(src, cfg_for(src, lock_check_extensions="['.pst']"))
    assert snap2.file_map()["db.pst"].skipped is False
    assert warnings2 == []


def test_case_sensitive_names_preserved(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    conftest.make_tree(src, {"MiXeD.txt": "m", "skip.TMP": "s"})
    snap, _ = scan_source(src, cfg_for(src, exclude_extensions="['.tmp']"))
    assert fns(snap) == ["MiXeD.txt"]     # fn keys never casefolded


def test_files_sorted_by_fn(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    conftest.make_tree(src, {"b.txt": "b", "a.txt": "a", "sub/z.txt": "z"})
    snap, _ = scan_source(src, cfg_for(src))
    assert fns(snap) == ["a.txt", "b.txt", "sub/z.txt"]
