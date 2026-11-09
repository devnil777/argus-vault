"""End-to-end tests: real Rar.exe full/diff runs with on-disk + in-archive checks."""

import hashlib
import os
import re
import shutil

import conftest
import pytest
from conftest import EMPTY_DIR, exclusive_lock, member_text, run_cli, stored_files

from backuper import rar_runner

pytestmark = pytest.mark.skipif(conftest.RAR_PATH is None, reason="Rar.exe not found")

SVC_FULL = {".backup/manifest.json", ".backup/files.json", ".backup/config.yaml"}
SVC_DIFF = SVC_FULL | {".backup/delete_files.txt", ".backup/delete_dirs.txt"}


def test_full_happy_path(job, capsys):
    job.make_source(readme="hello world", **{"sub/data.bin": bytes(range(256))},
                    **{"empty/leaf": EMPTY_DIR})
    with exclusive_lock(job.src / "vault.pst"):     # vault.pst -> skipped
        assert run_cli(["full", job.dir]) == 0

    epoch = job.latest_epoch()
    full = job.full_archive()
    assert full.parent == epoch and full.name.endswith("_full.rar")
    sidecar = full.with_name(full.name + ".sha256")
    log = full.with_name(full.name + ".log")
    assert sidecar.is_file() and log.is_file()

    # sidecar: certutil/sha256sum form "<64hex> *<name>", hash matches file
    m = re.fullmatch(rf"([0-9a-f]{{64}}) \*{re.escape(full.name)}\n",
                     sidecar.read_text(encoding="utf-8"))
    assert m, sidecar.read_text(encoding="utf-8")
    assert m.group(1) == hashlib.sha256(full.read_bytes()).hexdigest()

    # manifest fields
    man = job.manifest_of(full)
    assert man.archive_type == "full"
    assert man.previous_manifest_id is None
    assert man.previous_filename is None
    assert man.base_full is None
    assert man.config_sha256 == hashlib.sha256(job.config_path().read_bytes()).hexdigest()
    assert man.rar_version                      # set from the real Rar.exe
    assert man.filename == full.name

    # archive content: exactly the user files + .backup/* members
    files, folders = stored_files(job, full)
    assert set(files) == {"readme", "sub/data.bin"} | SVC_FULL   # vault.pst skipped
    assert "empty/leaf" in folders               # empty leaf dir stored as Folder
    assert "result: OK" in log.read_text(encoding="utf-8")

    # skipped file: not in the archive, but in files.json with skipped:true
    snap = job.snapshot_of(full)
    fmap = snap.file_map()
    assert fmap["vault.pst"].skipped is True
    assert fmap["vault.pst"].sz == (job.src / "vault.pst").stat().st_size
    assert "vault.pst" not in files
    assert man.counters["skipped"] == 1
    assert man.counters["files"] == 2

    out = capsys.readouterr().out
    assert "staged" in out
    assert "archived" in out
    assert "sha256 sidecar:" in out


def test_immediate_diff_is_noop(job):
    job.make_source(a="x")
    assert run_cli(["full", job.dir]) == 0
    before = job.archives()

    assert run_cli(["diff", job.dir]) == 6      # NoOpResult -> exit 6

    epoch = job.latest_epoch()
    nothing_logs = list(epoch.glob("*_diff_nothing.log"))
    assert len(nothing_logs) == 1
    assert "no changes detected" in nothing_logs[0].read_text(encoding="utf-8")
    assert job.archives() == before                        # no new .rar


def test_diff_with_changes(job):
    job.make_source(
        **{"a.txt": "v1", "b.txt": "delete me", "keep.txt": "same",
           "sub/old.txt": "old", "doomed/x.txt": "bye"},
    )
    with exclusive_lock(job.src / "vault.pst"):
        assert run_cli(["full", job.dir]) == 0
    full = job.full_archive()
    full_man = job.manifest_of(full)

    # mutate: new file, changed file (rewrite + distinct ns mtime), deleted
    # file, deleted subtree, new nested empty dirs; vault.pst stays locked.
    (job.src / "a.txt").write_bytes(b"v2 with a different size")
    changed_ns = 1_600_000_000_123_456_700                 # distinct from prev mt
    os.utime(job.src / "a.txt", ns=(changed_ns, changed_ns))
    (job.src / "b.txt").unlink()
    shutil.rmtree(job.src / "doomed")
    (job.src / "new.txt").write_bytes(b"brand new")
    os.makedirs(job.src / "fresh" / "l1" / "l2")
    with exclusive_lock(job.src / "vault.pst"):
        assert run_cli(["diff", job.dir]) == 0

    diff = job.tip()
    assert diff.name.endswith("_diff.rar") and diff != full

    # chain linkage
    man = job.manifest_of(diff)
    assert man.archive_type == "diff"
    assert man.base_full == full.name
    assert man.previous_manifest_id == full_man.manifest_id
    assert man.previous_filename == full.name

    # added set: only the new + changed files
    files, folders = stored_files(job, diff)
    assert set(files) == {"a.txt", "new.txt"} | SVC_DIFF
    assert "fresh/l1/l2" in folders                        # leaf of the new empty dirs

    # delete lists
    assert member_text(job, diff, ".backup/delete_files.txt").splitlines() == \
        ["b.txt", "doomed/x.txt"]
    assert member_text(job, diff, ".backup/delete_dirs.txt").splitlines() == ["doomed"]

    # diff's files.json = the CURRENT snapshot
    snap = job.snapshot_of(diff)
    fmap = snap.file_map()
    assert "b.txt" not in fmap and "doomed/x.txt" not in fmap
    assert "new.txt" in fmap and fmap["new.txt"].skipped is False
    assert fmap["a.txt"].mt_ns == changed_ns
    assert fmap["vault.pst"].skipped is True               # carried skip
    assert "vault.pst" not in files
    assert "vault.pst" not in member_text(job, diff, ".backup/delete_files.txt")
    assert snap.empty_dirs == ["fresh", "fresh/l1", "fresh/l1/l2"]


def test_deletes_only_diff(job, capsys):
    job.make_source(**{"a.txt": "x", "b.txt": "y"})
    assert run_cli(["full", job.dir]) == 0

    (job.src / "a.txt").unlink()
    assert run_cli(["diff", job.dir]) == 0

    diff = job.tip()
    files, _folders = stored_files(job, diff)
    assert set(files) == SVC_DIFF                          # zero user files
    assert member_text(job, diff, ".backup/delete_files.txt").splitlines() == ["a.txt"]
    assert run_cli(["verify", job.dir, "--chain"]) == 0
    out = capsys.readouterr().out
    assert "preparing chain verification (" in out
    assert "metadata loaded in" in out
    assert "listing " in out


def test_rar_failure_on_unlisted_locked_file(job):
    # blob.bin is NOT in lock_check_extensions -> the scanner cannot know;
    # RAR must fail and the whole run must fail cleanly (exit 2).
    job.make_source(keep="ok", **{"blob.bin": b"x" * 1000})
    with exclusive_lock(job.src / "blob.bin"):
        rc = run_cli(["full", job.dir])
    assert rc == 2

    epoch = job.latest_epoch()
    failed_logs = list(epoch.glob("*_failed.log"))
    assert len(failed_logs) == 1
    text = failed_logs[0].read_text(encoding="utf-8")
    assert "failed" in text.lower()
    assert "rar add" in text

    # no half-written archive left behind
    assert list(epoch.glob("*.rar")) == []
    assert list(epoch.glob("*.rar.tmp")) == []


def test_long_path_survives_full_diff_verify(job):
    rel = "/".join(["d" * 40] * 6 + ["deep_file_" + "f" * 20 + ".bin"])
    payload = os.urandom(3000)
    job.make_source(**{rel: payload})
    assert len(str(job.src.joinpath(*rel.split("/")))) > 260

    assert run_cli(["full", job.dir]) == 0

    target = job.src.joinpath(*rel.split("/"))
    with open(rar_runner.winapi_path(target), "ab") as fh:
        fh.write(b"-more-data")
    assert run_cli(["diff", job.dir]) == 0

    diff = job.tip()
    snap = job.snapshot_of(diff)
    assert rel in snap.file_map()
    files, _folders = stored_files(job, diff)
    assert rel in files

    assert run_cli(["verify", job.dir, "--chain"]) == 0


def test_relative_job_dir_full_and_diff(tmp_path, monkeypatch):
    """Regression: a relative job dir must not break the RAR create steps.

    The service step runs RAR with cwd=staging; a relative target used to
    resolve there and fail with exit 9 ("cannot find the path").
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "config.yaml").write_text(
        f"source: {src.as_posix()}\nexclude_extensions: ['.tmp']\n",
        encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert run_cli(["full", "test"]) == 0
    epoch = next((tmp_path / "test").glob("2*-*-*"))
    assert list(epoch.glob("*_full.rar"))

    (src / "b.txt").write_text("more", encoding="utf-8")
    assert run_cli(["diff", "test"]) == 0
    assert list(epoch.glob("*_diff.rar"))
    assert run_cli(["verify", "test", "--chain"]) == 0
