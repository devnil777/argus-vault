"""Pure-python tests of the runner startup sweep (no real Rar.exe needed)."""

from __future__ import annotations

from backuper import runner


def test_sweep_removes_rartemp_and_other_leftovers(tmp_path):
    epoch = tmp_path / "epoch"
    epoch.mkdir()
    leftovers = [
        "2026-01-01_000000_full.rar.tmp",
        "fixed.2026-01-01_000000_full.rar",
        "rebuilt.2026-01-01_000000_full.rar",
        "__rar_1234.5678.rartemp",
        "__rar_9.10.rartemp",
    ]
    keep = ["2026-01-01_000000_full.rar", "__rar_5.6.other", "notes.txt"]
    for name in leftovers + keep:
        (epoch / name).write_bytes(b"x")

    runner._sweep_tmp_files(tmp_path / "missing", epoch)

    for name in leftovers:
        assert not (epoch / name).exists(), name
    for name in keep:
        assert (epoch / name).is_file(), name


def test_sweep_missing_dir_is_noop(tmp_path):
    runner._sweep_tmp_files(tmp_path / "nope")  # must not raise
