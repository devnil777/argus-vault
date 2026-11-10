"""Pure-python tests of the runner startup sweep (no real Rar.exe needed)."""

from __future__ import annotations

from backuper import runner


def test_sweep_removes_tmp_and_rartemp(tmp_path):
    epoch = tmp_path / "epoch"
    epoch.mkdir()
    removed = [
        "2026-01-01_000000_full.rar.tmp",
        "__rar_1234.5678.rartemp",
        "__rar_9.10.rartemp",
    ]
    kept = [
        "2026-01-01_000000_full.rar",
        "fixed.2026-01-01_000000_full.rar",
        "rebuilt.2026-01-01_000000_full.rar",
        "__rar_5.6.other",
        "notes.txt",
    ]
    for name in removed + kept:
        (epoch / name).write_bytes(b"x")

    runner._sweep_tmp_files(tmp_path / "missing", epoch)

    for name in removed:
        assert not (epoch / name).exists(), name
    for name in kept:
        assert (epoch / name).is_file(), name


def test_sweep_missing_dir_is_noop(tmp_path):
    runner._sweep_tmp_files(tmp_path / "nope")  # must not raise


def test_is_repair_artifact():
    from backuper import chain
    assert chain.is_repair_artifact("fixed.x.rar")
    assert chain.is_repair_artifact("rebuilt.x.rar")
    assert not chain.is_repair_artifact("2026-01-01_000000_full.rar")


def test_epoch_archives_excludes_repair_artifacts(tmp_path):
    from backuper import chain
    epoch = tmp_path / "epoch"
    epoch.mkdir()
    for name in ("2026-01-01_000000_full.rar",
                 "fixed.2026-01-01_000000_full.rar",
                 "rebuilt.2026-01-01_000000_full.rar"):
        (epoch / name).write_bytes(b"x")
    names = [p.name for p in chain.epoch_archives(epoch)]
    assert names == ["2026-01-01_000000_full.rar"]
