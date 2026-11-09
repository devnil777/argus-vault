"""Tests for the archiver hashing / sidecar helpers (no RAR required)."""

import hashlib

import backuper.archiver as archiver
from backuper.archiver import (
    hash_file_with_progress,
    sha256_file,
    write_sidecar,
    write_sidecar_with_progress,
)


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
