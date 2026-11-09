"""Core data model: file entries, snapshot payload, manifest payload.

Also hosts the exact mtime codec and the JSON/bytes helpers shared by
the archive-writing and archive-reading code paths.

mtime codec
-----------
Mtimes are carried around as integer nanoseconds (``os.stat`` ->
``st_mtime_ns`` is exact on NTFS) and serialized as ISO-8601 UTC strings
with exactly 7 fractional digits: ``YYYY-MM-DDTHH:MM:SS.1234567Z``.
7 digits = 100 ns resolution = one NTFS timestamp tick (and the precision
of ``rar lt`` output), so every mtime NTFS can produce round-trips exactly.

Consequences of the 100 ns wire format, by design:

- ``iso_to_ns(ns_to_iso(ns)) == ns`` holds exactly for every multiple of
  100 (i.e. every real NTFS mtime).
- Values not aligned to 100 ns are floored to the containing tick:
  1 -> 0, 1234567 -> 1234500, -1 -> -100.

Implementation notes (pure integer math, no float anywhere):

- ``divmod(ns, 10**9)`` floors: for negative ns ``sec`` is the floor and
  ``rem`` is the non-negative remainder (0..999_999_999), so the
  fractional digits stay positive and the 100 ns truncation
  (``f"{rem:09d}"[:7]`` -- drop the last two of nine digits) is correct
  for pre-1970 timestamps too (e.g. ns=-1 -> sec=-1, rem=999_999_999 ->
  "1969-12-31T23:59:59.9999999Z" -> back to -100).
- Whole seconds are converted to a date via ``_EPOCH_DT + timedelta``,
  NOT ``datetime.fromtimestamp``: the latter raises ``OSError`` for
  large negative values on Windows. Arithmetic on datetime objects is
  exact and platform independent.
"""

from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA_VERSION = 1
# NOTE: SCHEMA_VERSION deliberately stays at 1 despite the encryption
# envelope: its fields (see Manifest) are strictly ADDITIVE and OPTIONAL --
# absent on legacy manifests, ignored by readers that predate them, and
# reconstructed as None by new readers when missing. from_json still
# accepts exactly 1, and to_json keeps writing 1. A hard version bump
# would make every old reader refuse every new archive for no benefit.

# Literal algorithm tag stored in Manifest.encryption when the archive's
# content step was encrypted with the manifest DEK.
ENCRYPTION_DATA = "data"

# Where the detached manifest signature (crypto.Signature.to_json
# serialized) lives inside an archive. The signature covers the EXACT
# ".backup/manifest.json" member bytes. Verified against the signing key
# pinned in the external signing_public.pem file).
MANIFEST_SIGNATURE_MEMBER = ".backup/manifest.json.sig"

_UTC = datetime.UTC
_EPOCH_DT = datetime.datetime(1970, 1, 1, tzinfo=_UTC)
_EPOCH_DAY = datetime.date(1970, 1, 1).toordinal()
_NS = 1_000_000_000

# Strict ASCII, full match: YYYY-MM-DDTHH:MM:SS + "." + exactly 7 digits + "Z".
_ISO_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{7})Z",
                     re.ASCII)


# ---------------------------------------------------------------------------
# mtime codec
# ---------------------------------------------------------------------------

def ns_to_iso(ns: int) -> str:
    """Format mtime nanoseconds as ``YYYY-MM-DDTHH:MM:SS.1234567Z`` (UTC).

    Exactly 7 fractional digits (100 ns); sub-100 ns precision is floored
    away. Works for pre-1970 (negative) ns as well.
    """
    sec, rem = divmod(ns, _NS)
    frac7 = f"{rem:09d}"[:7]  # top 7 of 9 digits = 100 ns ticks (floor)
    dt = _EPOCH_DT + datetime.timedelta(seconds=sec)
    return (f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}"
            f"T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}.{frac7}Z")


def iso_to_ns(s: str) -> int:
    """Exact inverse of :func:`ns_to_iso` (ValueError on a malformed string).

    Reconstructs ``ns = sec * 10**9 + int(frac7) * 100`` with integer math
    only; no float timestamps, so no microsecond truncation anywhere.
    """
    if not isinstance(s, str):
        raise ValueError(f"mtime must be a string, got {type(s).__name__}")
    m = _ISO_RE.fullmatch(s)
    if m is None:
        raise ValueError(f"malformed mtime {s!r}: expected YYYY-MM-DDTHH:MM:SS.#######Z")
    year, month, day, hour, minute, second, frac7 = (int(g) for g in m.groups())
    # Constructing the datetime validates the calendar date and the time
    # ranges (ValueError for e.g. month 13 or hour 24); the arithmetic
    # below stays purely integral.
    dt = datetime.datetime(year, month, day, hour, minute, second, tzinfo=_UTC)
    sec = (dt.toordinal() - _EPOCH_DAY) * 86400 + hour * 3600 + minute * 60 + second
    return sec * _NS + int(frac7) * 100


# ---------------------------------------------------------------------------
# JSON/bytes helpers
# ---------------------------------------------------------------------------

def json_bytes(obj: object) -> bytes:
    """Serialize to pretty UTF-8 JSON bytes (no BOM) with a trailing newline."""
    return (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def json_bytes_compact(obj: object) -> bytes:
    """Serialize to single-line UTF-8 JSON bytes (no BOM) + trailing newline.

    No ``indent`` keeps json on its C encoder — mandatory for big payloads
    such as a 198k-entry files.json, where the pure-Python pretty encoder
    stalls for minutes at 100% of one core.
    """
    return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
            + "\n").encode("utf-8")


def write_text_file(path: Path, text: str) -> None:
    """Write UTF-8 text (no BOM), translating nothing (newline kept as given)."""
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def _normalize_dir(name: str) -> str:
    """Normalize a directory path to forward slashes without a trailing slash."""
    return name.replace("\\", "/").rstrip("/")


def _parent_dir(fn: str) -> str:
    """Parent directory of a relative file path ("" for a root-level file)."""
    fn = fn.replace("\\", "/")
    if "/" not in fn:
        return ""
    return fn.rsplit("/", 1)[0]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FileEntry:
    """One file in a snapshot.

    ``fn`` is the path relative to the source dir with forward slashes
    (e.g. ``"sub/file.txt"``) and is a case-SENSITIVE key. ``sz``/``mt_ns``
    are 0 for unstatable (skipped) entries. ``skipped`` is serialized only
    when True (absence means "archived").
    """

    fn: str
    sz: int
    mt_ns: int
    skipped: bool = False

    def to_json(self) -> dict:
        d: dict = {"fn": self.fn, "sz": self.sz, "mt": ns_to_iso(self.mt_ns)}
        if self.skipped:
            d["skipped"] = True
        return d

    @classmethod
    def from_json(cls, d: dict) -> FileEntry:
        """Rebuild from a JSON object (ValueError on missing/malformed keys)."""
        try:
            fn = d["fn"]
            sz = d["sz"]
            mt = d["mt"]
        except (KeyError, TypeError) as exc:
            raise ValueError(f"FileEntry: missing key {exc}") from exc
        if not isinstance(fn, str) or not fn:
            raise ValueError(f"FileEntry: 'fn' must be a non-empty string, got {fn!r}")
        if not isinstance(sz, int) or isinstance(sz, bool):
            raise ValueError(f"FileEntry: 'sz' must be an int, got {sz!r}")
        if not isinstance(mt, str):
            raise ValueError(f"FileEntry: 'mt' must be an ISO mtime string, got {mt!r}")
        skipped = d.get("skipped", False)
        if not isinstance(skipped, bool):
            raise ValueError(f"FileEntry: 'skipped' must be a bool, got {skipped!r}")
        return cls(fn=fn, sz=sz, mt_ns=iso_to_ns(mt), skipped=skipped)


@dataclass
class Snapshot:
    """Payload of ``files.json`` stored inside every archive.

    Invariants kept by the snapshot builder: ``files`` is sorted by ``fn``
    and ``empty_dirs`` is sorted; ``empty_dirs`` lists directories with NO
    files anywhere in their subtree (which makes it closed under ancestors).
    """

    files: list[FileEntry]
    empty_dirs: list[str]

    def to_json(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "files": [f.to_json() for f in self.files],
            "empty_dirs": list(self.empty_dirs),
        }

    @classmethod
    def from_json(cls, d: dict) -> Snapshot:
        """Rebuild from a JSON object; accepts ``schema_version == 1`` only."""
        if not isinstance(d, dict):
            raise ValueError(f"snapshot payload must be a JSON object, got {type(d).__name__}")
        if d.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported snapshot schema_version {d.get('schema_version')!r} "
                f"(expected {SCHEMA_VERSION})")
        raw_files = d.get("files")
        if not isinstance(raw_files, list):
            raise ValueError(f"snapshot 'files' must be a list, got {raw_files!r}")
        files = [FileEntry.from_json(item) for item in raw_files]
        raw_dirs = d.get("empty_dirs")
        if not isinstance(raw_dirs, list):
            raise ValueError(f"snapshot 'empty_dirs' must be a list, got {raw_dirs!r}")
        empty_dirs: list[str] = []
        for item in raw_dirs:
            if not isinstance(item, str) or not item:
                raise ValueError(f"snapshot 'empty_dirs' entries must be non-empty strings, got {item!r}")
            empty_dirs.append(_normalize_dir(item))
        return cls(files=files, empty_dirs=empty_dirs)

    def file_map(self) -> dict[str, FileEntry]:
        """Map ``fn`` -> entry."""
        return {e.fn: e for e in self.files}

    def dir_set(self) -> set[str]:
        """Every directory implied by the snapshot.

        All parent dirs (grandparents included) of each file ``fn`` plus
        all ``empty_dirs``. Normalized to forward slashes, no trailing
        slash, with the root ``""`` excluded.
        """
        dirs: set[str] = set()
        for entry in self.files:
            parent = _parent_dir(entry.fn)
            if not parent:
                continue
            parts = parent.split("/")
            for i in range(1, len(parts) + 1):
                dirs.add("/".join(parts[:i]))
        for d in self.empty_dirs:
            norm = _normalize_dir(d)
            if norm:
                dirs.add(norm)
        dirs.discard("")
        return dirs


_MANIFEST_KEYS: tuple[str, ...] = (
    "schema_version", "manifest_id", "filename", "archive_type", "created_utc",
    "config_name", "config_sha256", "script_version", "rar_version", "sources",
    "base_full", "previous_manifest_id", "previous_filename", "excludes",
    "added_empty_dirs", "counters",
)


@dataclass
class Manifest:
    """Payload of ``.backup/manifest.json`` stored inside every archive.

    ``manifest_id`` is a uuid4 string and also serves as the human
    "run_id" from the spec -- one field for both purposes.
    """

    schema_version: int = field(default=SCHEMA_VERSION, kw_only=True)
    manifest_id: str
    filename: str               # archive file name, e.g. "2026-11-02_030000_full.rar"
    archive_type: str           # "full" | "diff"
    created_utc: str            # ISO UTC of run start
    config_name: str            # "config.yaml"
    config_sha256: str          # sha256 hex of the raw config.yaml bytes in the archive
    script_version: str
    rar_version: str
    sources: list[str]          # single-element list: the source dir as configured
    base_full: str | None       # epoch's full archive filename; None for full
    previous_manifest_id: str | None
    previous_filename: str | None
    excludes: dict              # {"extensions": [...], "dirs": [...]}
    added_empty_dirs: list[str] # diff only: newly created empty dirs this diff stores
    counters: dict              # {"files", "empty_dirs", "skipped", "bytes",
                                #  "deleted_files", "deleted_dirs", "added_empty_dirs"} -- ints

    # --- additive encryption envelope (all optional; absent = legacy) -------
    # "data" when the archive's content step was encrypted with the DEK.
    encryption: str | None = field(default=None, kw_only=True)
    # crypto.WrappedKey.to_json() dicts: the DEK wrapped for each recipient.
    wrapped_keys: list[dict] | None = field(default=None, kw_only=True)
    signing_key_id: str | None = field(default=None, kw_only=True)

    def to_json(self) -> dict:
        """All legacy keys present; None serializes as explicit null (UTF-8 friendly).

        The encryption-envelope fields (encryption/wrapped_keys/
        signing_key_id) are included ONLY when set, so
        legacy unencrypted manifests gain no extra keys at all.
        """
        d: dict = {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "filename": self.filename,
            "archive_type": self.archive_type,
            "created_utc": self.created_utc,
            "config_name": self.config_name,
            "config_sha256": self.config_sha256,
            "script_version": self.script_version,
            "rar_version": self.rar_version,
            "sources": list(self.sources),
            "base_full": self.base_full,
            "previous_manifest_id": self.previous_manifest_id,
            "previous_filename": self.previous_filename,
            "excludes": dict(self.excludes),
            "added_empty_dirs": list(self.added_empty_dirs),
            "counters": dict(self.counters),
        }
        if self.encryption is not None:
            d["encryption"] = self.encryption
        if self.wrapped_keys is not None:
            d["wrapped_keys"] = [dict(item) for item in self.wrapped_keys]
        if self.signing_key_id is not None:
            d["signing_key_id"] = self.signing_key_id
        return d

    @classmethod
    def from_json(cls, d: dict) -> Manifest:
        """Rebuild from a JSON object; ``schema_version == 1`` required."""
        if not isinstance(d, dict):
            raise ValueError(f"manifest payload must be a JSON object, got {type(d).__name__}")
        if d.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported manifest schema_version {d.get('schema_version')!r} "
                f"(expected {SCHEMA_VERSION})")
        missing = [k for k in _MANIFEST_KEYS if k not in d]
        if missing:
            raise ValueError(f"manifest is missing required key(s): {', '.join(missing)}")
        for key in ("manifest_id", "filename", "archive_type", "created_utc",
                    "config_name", "config_sha256", "script_version", "rar_version"):
            if not isinstance(d[key], str):
                raise ValueError(f"manifest field {key!r} must be a string, got {d[key]!r}")
        if d["archive_type"] not in ("full", "diff"):
            raise ValueError(f"manifest 'archive_type' must be 'full' or 'diff', got {d['archive_type']!r}")
        for key in ("base_full", "previous_manifest_id", "previous_filename"):
            if d[key] is not None and not isinstance(d[key], str):
                raise ValueError(f"manifest field {key!r} must be a string or null, got {d[key]!r}")
        sources = d["sources"]
        if not isinstance(sources, list) or any(not isinstance(x, str) for x in sources):
            raise ValueError(f"manifest 'sources' must be a list of strings, got {sources!r}")
        added = d["added_empty_dirs"]
        if not isinstance(added, list) or any(not isinstance(x, str) for x in added):
            raise ValueError(f"manifest 'added_empty_dirs' must be a list of strings, got {added!r}")
        excludes = d["excludes"]
        if not isinstance(excludes, dict):
            raise ValueError(f"manifest 'excludes' must be an object, got {excludes!r}")
        counters = d["counters"]
        if not isinstance(counters, dict) or any(
                not isinstance(v, int) or isinstance(v, bool) for v in counters.values()):
            raise ValueError(f"manifest 'counters' must map names to ints, got {counters!r}")

        # --- additive encryption envelope (tolerated absent, legacy) ---------
        encryption = d.get("encryption")
        if encryption is not None and (not isinstance(encryption, str) or not encryption):
            raise ValueError(
                f"manifest 'encryption' must be a non-empty string or null, got {encryption!r}")
        wrapped_keys = d.get("wrapped_keys")
        if wrapped_keys is not None and (
                not isinstance(wrapped_keys, list)
                or any(not isinstance(item, dict) for item in wrapped_keys)):
            raise ValueError(
                f"manifest 'wrapped_keys' must be a list of objects, got {wrapped_keys!r}")
        signing_key_id = d.get("signing_key_id")
        if signing_key_id is not None and not isinstance(signing_key_id, str):
            raise ValueError(
                f"manifest 'signing_key_id' must be a string or null, got {signing_key_id!r}")
        return cls(
            manifest_id=d["manifest_id"],
            filename=d["filename"],
            archive_type=d["archive_type"],
            created_utc=d["created_utc"],
            config_name=d["config_name"],
            config_sha256=d["config_sha256"],
            script_version=d["script_version"],
            rar_version=d["rar_version"],
            sources=list(sources),
            base_full=d["base_full"],
            previous_manifest_id=d["previous_manifest_id"],
            previous_filename=d["previous_filename"],
            excludes=dict(excludes),
            added_empty_dirs=list(added),
            counters=dict(counters),
            encryption=encryption,
            wrapped_keys=[dict(item) for item in wrapped_keys] if wrapped_keys is not None else None,
            signing_key_id=signing_key_id,
        )
