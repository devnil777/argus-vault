"""Tests for the archiver hashing / sidecar helpers (no RAR required)."""

import hashlib
import os
import uuid

import backuper.archiver as archiver
import backuper.rar_runner as rar_runner
from backuper.archiver import (
    CreateOutcome,
    CreateSpec,
    create_archive,
    hash_file_with_progress,
    sha256_file,
    write_sidecar,
    write_sidecar_with_progress,
)
from backuper.errors import EpochError
from backuper.models import Manifest, Snapshot


def _payload() -> bytes:
    """~2 MiB + 123 bytes of deterministic data (spans several 1 MiB chunks)."""
    block = bytes(range(256)) * 4096          # 1 MiB
    return block * 2 + bytes(123)


def test_sha256_file_progress_matches_hashlib(tmp_path):
    data = _payload()
    path = tmp_path / "payload.bin"
    path.write_bytes(data)

    seen: list[int] = []
    digest = sha256_file(path, progress=seen.append)

    assert digest == hashlib.sha256(data).hexdigest()
    assert seen == sorted(seen) and len(set(seen)) == len(seen)   # strictly increasing
    assert seen[-1] == len(data)


def test_sha256_file_without_progress(tmp_path):
    data = _payload()
    path = tmp_path / "payload.bin"
    path.write_bytes(data)

    assert sha256_file(path) == hashlib.sha256(data).hexdigest()


def test_write_sidecar_uses_precomputed_digest(tmp_path, monkeypatch):
    path = tmp_path / "archive.rar"
    path.write_bytes(b"pretend archive")
    digest = "a" * 64

    def _fail(_path, **_kwargs):
        raise AssertionError("sha256_file must not be called with a precomputed digest")

    monkeypatch.setattr(archiver, "sha256_file", _fail)

    assert write_sidecar(path, digest=digest) == (True, digest)
    sidecar = tmp_path / "archive.rar.sha256"
    assert sidecar.read_bytes() == f"{digest} *{path.name}\n".encode()
    assert not sidecar.read_bytes().startswith(b"\xef\xbb\xbf")   # no BOM


def test_hash_file_with_progress_prints_start_and_summary(capsys, tmp_path):
    data = _payload()
    path = tmp_path / "payload.bin"
    path.write_bytes(data)

    digest = hash_file_with_progress(path, "testing", label="sha256 test")
    out = capsys.readouterr().out

    assert digest == hashlib.sha256(data).hexdigest()
    assert "hashing" in out
    assert "sha256 test:" in out
    assert " in " in out


def test_write_sidecar_with_progress(capsys, tmp_path):
    data = _payload()
    path = tmp_path / "archive.rar"
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()

    written, returned = write_sidecar_with_progress(path)
    out = capsys.readouterr().out

    assert written is True
    assert returned == digest
    sidecar = tmp_path / "archive.rar.sha256"
    assert sidecar.read_text(encoding="utf-8") == f"{digest} *{path.name}\n"
    assert "sha256 sidecar:" in out


# ---------------------------------------------------------------------------
# stage 1.3 / 1.4: commit boundary + no-overwrite guard (direct, no RAR)
# ---------------------------------------------------------------------------

def _make_spec(tmp_path, name_ts="2026-01-01_000000"):
    epoch = tmp_path / "epoch"
    epoch.mkdir(exist_ok=True)
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    manifest = Manifest(
        manifest_id=str(uuid.uuid4()),
        filename=f"{name_ts}_full.rar",
        archive_type="full",
        created_utc="2026-01-01T00:00:00Z",
        config_name="config.yaml",
        config_sha256="0" * 64,
        script_version="0.0.5",
        rar_version="7.22",
        sources=[str(src)],
        base_full=None,
        previous_manifest_id=None,
        previous_filename=None,
        excludes={"extensions": [], "dirs": []},
        added_empty_dirs=[],
        counters={"files": 0, "empty_dirs": 0, "skipped": 0, "bytes": 0,
                  "deleted_files": 0, "deleted_dirs": 0, "added_empty_dirs": 0},
    )
    snapshot = Snapshot(files=[], empty_dirs=[])
    return CreateSpec(
        epoch_dir=epoch, source=src, archive_type="full", name_ts=name_ts,
        manifest=manifest, snapshot=snapshot, config_bytes=b"source: x\n",
        compression=0, files_to_add=[], empty_dirs_to_add=[], warnings=[],
        config=None, dek=None, signing_private_pem=None,
    ), epoch


def test_create_archive_sidecar_interrupted_still_committed(tmp_path, monkeypatch):
    spec, epoch = _make_spec(tmp_path)
    ts = spec.name_ts

    class _Res:
        def __init__(self):
            self.exit_code = 0
            self.cmd = []

        @property
        def ok(self):
            return True

        def stdout(self):
            return ""

        def stderr(self):
            return ""

    def _fake_create_step(runner, target, cwd, names, *, final, compression,
                          progress_callback=None, bom=False, password=None):
        # RAR writes the .tmp target; create it so os.replace succeeds.
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(b"fake archive")
        return _Res()

    monkeypatch.setattr(rar_runner, "create_step", _fake_create_step)
    monkeypatch.setattr(archiver, "cross_check", lambda *a, **k: [])

    def _boom(*a, **k):
        raise KeyboardInterrupt()

    monkeypatch.setattr(archiver, "write_sidecar_with_progress", _boom)

    outcome = create_archive(object(), spec, progress=False)
    assert isinstance(outcome, CreateOutcome)
    assert outcome.committed is True
    assert outcome.archive.is_file()
    assert outcome.sidecar_written is False
    assert not (epoch / f"{ts}_full.rar.sha256").is_file()
    # no failed-run log was written by create_archive itself
    assert not (epoch / f"{ts}_full_failed.log").is_file()


def test_create_archive_existing_target_raises(tmp_path):
    spec, epoch = _make_spec(tmp_path)
    target = epoch / f"{spec.name_ts}_full.rar"
    target.write_bytes(b"pre-existing")

    before = target.read_bytes()
    try:
        create_archive(object(), spec, progress=False)
    except EpochError:
        pass
    else:
        raise AssertionError("expected EpochError")
    assert target.read_bytes() == before
    assert not (epoch / f"{spec.name_ts}_full.rar.tmp").is_file()
