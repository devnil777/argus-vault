"""Unit tests for backuper.models: mtime codec, JSON round-trips, dir_set."""

import json
import re

import pytest

from backuper.models import (
    SCHEMA_VERSION,
    FileEntry,
    Manifest,
    Snapshot,
    iso_to_ns,
    json_bytes,
    ns_to_iso,
)

_ISO_SHAPE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$")


# ---------------------------------------------------------------------------
# mtime codec
# ---------------------------------------------------------------------------

def test_mtime_roundtrip_over_ntfs_ticks():
    base = 1_793_644_800 * 10**9  # ~2026-11-02, NTFS-realistic range
    values = [
        0,
        100,
        999_999_900,
        base - 10**9 * 86400 * 365 * 56,          # far past (1970)
        base,
        base + 123_456_700,
        base + 999_999_900,
        -1_000_000_000,                            # pre-1970
        -100,
        -86_400_000_000_000 + 700,                 # 1969-12-31 + fraction
        2**62 - (2**62 % 100),                     # huge but valid
    ]
    for ns in values:
        iso = ns_to_iso(ns)
        assert _ISO_SHAPE.fullmatch(iso), iso
        assert iso_to_ns(iso) == ns, ns


def test_mtime_flooring_to_100ns_tick():
    # Only 100 ns-aligned values round-trip exactly; others floor.
    assert iso_to_ns(ns_to_iso(1)) == 0
    assert iso_to_ns(ns_to_iso(99)) == 0
    assert iso_to_ns(ns_to_iso(1234567)) == 1234500
    assert iso_to_ns(ns_to_iso(-1)) == -100
    assert iso_to_ns(ns_to_iso(-99)) == -100
    assert iso_to_ns(ns_to_iso(-101)) == -200


def test_ns_to_iso_known_values():
    assert ns_to_iso(0) == "1970-01-01T00:00:00.0000000Z"
    assert ns_to_iso(100) == "1970-01-01T00:00:00.0000001Z"
    assert ns_to_iso(-100) == "1969-12-31T23:59:59.9999999Z"
    # 1_234_567_891 s = 2009-02-13T23:31:31 UTC; frac .2345679 = 234567900 ns
    assert ns_to_iso(1_234_567_891_234_567_900) == "2009-02-13T23:31:31.2345679Z"


def test_iso_to_ns_rejects_malformed():
    for bad in [
        "",
        "not-a-date",
        123,
        None,
        "2026-11-02 03:00:00.0000000Z",          # space instead of T
        "2026-11-02T03:00:00,1234567Z",          # comma fraction
        "2026-11-02T03:00:00.123456Z",           # 6 digits
        "2026-11-02T03:00:00.12345678Z",         # 8 digits
        "2026-13-01T00:00:00.0000000Z",          # month 13 (calendar check)
        "2026-11-32T00:00:00.0000000Z",          # day 32
    ]:
        with pytest.raises(ValueError):
            iso_to_ns(bad)


# ---------------------------------------------------------------------------
# FileEntry
# ---------------------------------------------------------------------------

def test_file_entry_roundtrip():
    e = FileEntry(fn="sub/file.txt", sz=1234, mt_ns=1_793_644_800_123_456_700)
    assert FileEntry.from_json(e.to_json()) == e

    s = FileEntry(fn="locked.pst", sz=5, mt_ns=-100, skipped=True)
    assert FileEntry.from_json(s.to_json()) == s


def test_file_entry_skipped_key_only_when_true():
    d = FileEntry(fn="a", sz=1, mt_ns=0).to_json()
    assert "skipped" not in d                      # absence means archived
    d2 = FileEntry(fn="a", sz=1, mt_ns=0, skipped=True).to_json()
    assert d2["skipped"] is True


def test_file_entry_from_json_rejects():
    with pytest.raises(ValueError):
        FileEntry.from_json({})                          # missing keys
    with pytest.raises(ValueError):
        FileEntry.from_json({"fn": "", "sz": 1, "mt": ns_to_iso(0)})
    with pytest.raises(ValueError):
        FileEntry.from_json({"fn": "a", "sz": "1", "mt": ns_to_iso(0)})
    with pytest.raises(ValueError):
        FileEntry.from_json({"fn": "a", "sz": True, "mt": ns_to_iso(0)})
    with pytest.raises(ValueError):
        FileEntry.from_json({"fn": "a", "sz": 1, "mt": "garbage"})
    with pytest.raises(ValueError):
        FileEntry.from_json({"fn": "a", "sz": 1, "mt": ns_to_iso(0), "skipped": "yes"})


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

def make_snapshot() -> Snapshot:
    return Snapshot(
        files=[
            FileEntry("a.txt", 3, 100),
            FileEntry("sub/b.txt", 4, 200, skipped=True),
        ],
        empty_dirs=["e1", "e1/e2"],
    )


def test_snapshot_roundtrip():
    s = make_snapshot()
    raw = json_bytes(s.to_json())
    s2 = Snapshot.from_json(json.loads(raw))
    assert s2.files == s.files
    assert s2.empty_dirs == s.empty_dirs
    assert s2.to_json() == s.to_json()


def test_snapshot_to_json_schema_version():
    d = make_snapshot().to_json()
    assert d["schema_version"] == SCHEMA_VERSION == 1
    assert [f["fn"] for f in d["files"]] == ["a.txt", "sub/b.txt"]


def test_snapshot_from_json_rejects():
    good = json.loads(json_bytes(make_snapshot().to_json()))
    with pytest.raises(ValueError):
        Snapshot.from_json({**good, "schema_version": 2})
    with pytest.raises(ValueError):
        Snapshot.from_json({**good, "schema_version": "1"})
    with pytest.raises(ValueError):
        Snapshot.from_json({k: v for k, v in good.items() if k != "files"})
    with pytest.raises(ValueError):
        Snapshot.from_json({k: v for k, v in good.items() if k != "empty_dirs"})
    with pytest.raises(ValueError):
        Snapshot.from_json(["not", "a", "dict"])
    with pytest.raises(ValueError):
        Snapshot.from_json({**good, "empty_dirs": ["ok", ""]})
    with pytest.raises(ValueError):
        Snapshot.from_json({**good, "empty_dirs": [42]})


def test_snapshot_empty_dirs_normalized():
    s = Snapshot.from_json({"schema_version": 1, "files": [], "empty_dirs": ["a\\b/", "c"]})
    assert s.empty_dirs == ["a/b", "c"]


def test_snapshot_dir_set():
    s = Snapshot(
        files=[FileEntry("a/b/c.txt", 1, 0), FileEntry("top.txt", 1, 0)],
        empty_dirs=["x/y", "x\\z/", "q"],
    )
    # ancestors of FILE paths are implied; empty_dirs are added as-is
    # (normalized); the root "" is excluded.
    assert s.dir_set() == {"a", "a/b", "x/y", "x/z", "q"}
    assert Snapshot(files=[], empty_dirs=[]).dir_set() == set()


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def make_manifest() -> Manifest:
    return Manifest(
        manifest_id="11111111-1111-4111-8111-111111111111",
        filename="2026-11-02_030000_full.rar",
        archive_type="full",
        created_utc="2026-11-02T03:00:00Z",
        config_name="config.yaml",
        config_sha256="a" * 64,
        script_version="0.2.0",
        rar_version="7.22",
        sources=["D:/Data"],
        base_full=None,
        previous_manifest_id=None,
        previous_filename=None,
        excludes={"extensions": [".tmp"], "dirs": []},
        added_empty_dirs=[],
        counters={"files": 2, "empty_dirs": 0, "skipped": 1, "bytes": 7,
                  "deleted_files": 0, "deleted_dirs": 0, "added_empty_dirs": 0},
    )


def test_manifest_roundtrip():
    m = make_manifest()
    assert Manifest.from_json(m.to_json()) == m
    m2 = Manifest.from_json(json.loads(json_bytes(m.to_json())))
    assert m2 == m


def test_manifest_null_fields_explicit_and_roundtrip():
    d = make_manifest().to_json()
    assert d["base_full"] is None                       # explicit null, key present
    assert d["previous_manifest_id"] is None
    assert d["previous_filename"] is None

    diff = make_manifest()
    diff.archive_type = "diff"
    diff.base_full = "2026-11-02_030000_full.rar"
    diff.previous_manifest_id = "22222222-2222-4222-8222-222222222222"
    diff.previous_filename = "2026-11-02_030000_full.rar"
    assert Manifest.from_json(diff.to_json()) == diff


def test_manifest_from_json_rejects():
    good = make_manifest().to_json()
    with pytest.raises(ValueError):
        Manifest.from_json({**good, "schema_version": 99})
    with pytest.raises(ValueError):
        Manifest.from_json("nope")
    for key in ("manifest_id", "filename", "archive_type", "created_utc",
                "config_name", "config_sha256", "script_version", "rar_version",
                "sources", "excludes", "added_empty_dirs", "counters"):
        broken = {k: v for k, v in good.items() if k != key}
        with pytest.raises(ValueError):
            Manifest.from_json(broken)
    with pytest.raises(ValueError):
        Manifest.from_json({**good, "archive_type": "incr"})
    with pytest.raises(ValueError):
        Manifest.from_json({**good, "counters": {"files": "2"}})
    with pytest.raises(ValueError):
        Manifest.from_json({**good, "sources": [1]})
    with pytest.raises(ValueError):
        Manifest.from_json({**good, "previous_manifest_id": 5})
    with pytest.raises(ValueError):
        Manifest.from_json({**good, "base_full": 7})
