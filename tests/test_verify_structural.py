"""Pure unit tests for backuper.verify._structural_check (no RAR required)."""

import hashlib

from backuper import verify
from backuper.archiver import SERVICE_MEMBERS_FULL
from backuper.models import Manifest, Snapshot


def _config_bytes() -> bytes:
    return b"source: C:/Data\n"


def _make_manifest(config_sha256: str) -> Manifest:
    return Manifest(
        manifest_id="11112222-3333-4444-5555-666677778888",
        filename="2026-01-01_000000_full.rar",
        archive_type="full",
        created_utc="2026-01-01T00:00:00Z",
        config_name="config.yaml",
        config_sha256=config_sha256,
        script_version="test",
        rar_version="test",
        sources=["C:/Data"],
        base_full=None,
        previous_manifest_id=None,
        previous_filename=None,
        excludes={"extensions": [], "dirs": []},
        added_empty_dirs=[],
        counters={"files": 0, "empty_dirs": 0, "skipped": 0, "bytes": 0,
                  "deleted_files": 0, "deleted_dirs": 0, "added_empty_dirs": 0},
    )


def _run(monkeypatch, config_sha256: str):
    config_bytes = _config_bytes()
    store = {
        ".backup/manifest.json": b"{}",
        ".backup/files.json": b"{}",
        ".backup/config.yaml": config_bytes,
    }

    def fake_read_service_member(runner_obj, archive, member):
        if member not in store:
            raise RuntimeError(f"member {member!r} not in archive")
        return store[member]

    monkeypatch.setattr(verify, "read_service_member", fake_read_service_member)

    manifest = _make_manifest(config_sha256)
    snapshot = Snapshot(files=[], empty_dirs=[])
    expected_files = {e.fn: e.sz for e in snapshot.files if not e.skipped}
    entries = [
        {"Name": m, "Type": "file", "Size": len(store[m])}
        for m in SERVICE_MEMBERS_FULL
    ]
    return verify._structural_check(
        object(), "archive.rar", manifest, snapshot, expected_files, entries)


def test_structural_check_config_sha_ok(monkeypatch):
    config_bytes = _config_bytes()
    problems = _run(monkeypatch, hashlib.sha256(config_bytes).hexdigest())
    assert problems == []


def test_structural_check_config_sha_wrong(monkeypatch):
    problems = _run(monkeypatch, "f" * 64)
    assert len(problems) == 1
    assert "config_sha256" in problems[0]
