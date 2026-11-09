"""Epoch/chain layer: discovery, tip resolution, archive metadata reading.

This module owns everything around the on-disk "chain" layout of a job::

    <job_dir>/
      config.yaml
      .lock
      <YYYY-MM-DD>/                  # epoch dir, name = date of the full run
        2026-11-02_030000_full.rar
        2026-11-02_030000_full.rar.sha256
        2026-11-02_030000_full.rar.log
        2026-11-02_050000_diff.rar ...

Responsibilities:

- epoch discovery (``list_epochs``/``latest_epoch``/``resolve_epoch``),
- per-epoch archive listing and full/tip resolution (``epoch_archives``,
  ``epoch_full``, ``tip_archive``, ``archive_base_names``),
- reading the self-describing ``.backup/`` service members out of an
  archive (``load_manifest``, ``load_snapshot``, ``load_embedded_config``),
  including the detached manifest-signature verification for encrypted
  manifests (against the config-pinned trusted Ed25519 public key),
- validating that a candidate base archive is usable for a diff run
  (``check_base_archive`` -- the explicit "previous archive unavailable"
  checks, including the chain-sanity check of the referenced previous
  archive),
- comparing the job config against the config embedded in the previous
  archive (``config_mismatch_warning``) so a diff run can warn when the
  configuration semantics changed without warning on mere editor
  re-saves (BOM/CRLF/key order).

Every failure raised here is :class:`backuper.errors.EpochError` (CLI
exit code 5). Directory listings use plain pathlib: job/epoch dirs are
chosen by the user, so no ``\\\\?\\`` path handling is applied here.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from backuper import rar_runner
from backuper.config import (
    CONFIG_NAME,
    Config,
    normalize_exclude_dir,
    normalize_ext,
    semantic_key,
)
from backuper.errors import EpochError
from backuper.models import (
    ENCRYPTION_DATA,
    MANIFEST_SIGNATURE_MEMBER,
    Manifest,
    Snapshot,
)

# The crypto layer is imported defensively (see backuper.config): without
# it, key-bearing embedded configs still compare via None ids (guaranteed
# mismatch) and only signature verification is unavailable.
try:
    from backuper import crypto as _crypto
except ImportError:  # pragma: no cover - exercised without the layer
    _crypto = None
from backuper.rar_runner import read_service_member

# Strict ASCII full match: an epoch directory is named exactly YYYY-MM-DD.
# fullmatch (not match + $) so a trailing newline cannot sneak through.
EPOCH_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$", re.ASCII)

# Service members stored inside every archive (forward-slash spelling;
# read_service_member accepts both separator spellings).
_MANIFEST_MEMBER = ".backup/manifest.json"
_SNAPSHOT_MEMBER = ".backup/files.json"
_CONFIG_MEMBER = f".backup/{CONFIG_NAME}"

# Aspects compared by config_mismatch_warning, in semantic_key order.
_ASPECT_NAMES: tuple[str, ...] = (
    "source",
    "exclude_extensions",
    "exclude_dirs",
    "lock_check_extensions",
    "compression",
    "recipient_public_key",
    "signing_public_key",
)


# ---------------------------------------------------------------------------
# Epoch discovery / tip resolution
# ---------------------------------------------------------------------------

def list_epochs(job_dir: Path) -> list[Path]:
    """Return the epoch directories of ``job_dir``, sorted ascending by name.

    An epoch is a subdirectory whose name matches :data:`EPOCH_DIR_RE`
    (``YYYY-MM-DD``). A missing or non-directory ``job_dir`` yields an
    empty list (a fresh job simply has no epochs yet).
    """
    job_dir = Path(job_dir)
    if not job_dir.is_dir():
        return []
    epochs = [
        p for p in job_dir.iterdir()
        if p.is_dir() and EPOCH_DIR_RE.fullmatch(p.name) is not None
    ]
    return sorted(epochs, key=lambda p: p.name)


def latest_epoch(job_dir: Path) -> Path:
    """Return the newest epoch directory (max name)."""
    epochs = list_epochs(job_dir)
    if not epochs:
        raise EpochError(f"no epochs found in {job_dir}")
    return epochs[-1]


def resolve_epoch(job_dir: Path, name: str | None) -> Path:
    """Resolve the epoch to operate on.

    ``name=None`` selects :func:`latest_epoch`. Otherwise ``name`` is
    user CLI input (e.g. ``--epoch``): it must be a bare ``YYYY-MM-DD``
    name -- matching :data:`EPOCH_DIR_RE` and containing no path
    separators, so ``..\\x`` cannot escape the job dir -- and the epoch
    directory must exist. Failures raise :class:`EpochError`; the
    not-found message lists the available epochs.
    """
    if name is None:
        return latest_epoch(job_dir)
    name = str(name)
    if "/" in name or "\\" in name:
        raise EpochError(
            f"invalid epoch {name!r}: epoch names must not contain path separators")
    if EPOCH_DIR_RE.fullmatch(name) is None:
        raise EpochError(
            f"invalid epoch {name!r}: expected an epoch directory named YYYY-MM-DD")
    epoch_dir = Path(job_dir) / name
    if not epoch_dir.is_dir():
        available = [p.name for p in list_epochs(job_dir)]
        avail_txt = ", ".join(available) if available else "none"
        raise EpochError(
            f"epoch {name!r} does not exist in {job_dir} (available epochs: {avail_txt})")
    return epoch_dir


# ---------------------------------------------------------------------------
# Per-epoch archive listing
# ---------------------------------------------------------------------------

def epoch_archives(epoch_dir: Path) -> list[Path]:
    """Return the ``*.rar`` archives in the epoch, sorted by filename.

    Only plain ``.rar`` files: ``.rar.tmp``, ``.rar.sha256`` and
    ``.rar.log`` siblings do not match the ``*.rar`` glob.
    """
    epoch_dir = Path(epoch_dir)
    rars = [p for p in epoch_dir.glob("*.rar") if p.is_file()]
    return sorted(rars, key=lambda p: p.name)


def epoch_full(epoch_dir: Path) -> Path:
    """Return the epoch's single ``*_full.rar`` archive."""
    fulls = [p for p in epoch_archives(epoch_dir) if p.name.endswith("_full.rar")]
    if not fulls:
        raise EpochError(f"epoch {epoch_dir.name} has no full archive")
    if len(fulls) > 1:
        names = ", ".join(p.name for p in fulls)
        raise EpochError(f"epoch {epoch_dir.name} has multiple full archives: {names}")
    return fulls[0]


def tip_archive(epoch_dir: Path) -> Path:
    """Return the epoch's newest archive (last ``*.rar`` by filename)."""
    archives = epoch_archives(epoch_dir)
    if not archives:
        raise EpochError(f"epoch {epoch_dir.name} contains no archives")
    return archives[-1]


def archive_base_names(epoch_dir: Path) -> set[str]:
    """Basenames (with extension) of all ``.rar`` archives in the epoch.

    Used for previous-archive reference checks: a manifest's
    ``previous_filename`` must name one of these.
    """
    return {p.name for p in epoch_archives(epoch_dir)}


# ---------------------------------------------------------------------------
# Self-describing metadata inside an archive
# ---------------------------------------------------------------------------

def _reason(exc: BaseException) -> str:
    """One-line reason string for an exception (type name + message)."""
    text = str(exc).strip()
    if not text:
        return type(exc).__name__
    return f"{type(exc).__name__}: {text}"


def load_manifest(
    runner: rar_runner.RarRunner,
    archive: Path,
    *,
    trusted_signing_pem: bytes | None = None,
    require_signature: bool = False,
) -> Manifest:
    """Read and parse ``.backup/manifest.json`` from the archive.

    For an ENCRYPTED manifest (``encryption == ENCRYPTION_DATA``) the
    detached signature member ``.backup/manifest.json.sig`` is read
    (passwordless -- service members are open) and, when a trusted
    signing PUBLIC key is supplied, verified against it over the exact
    manifest member bytes (raising :class:`EpochError` on a missing,
    malformed or non-verifying signature). Legacy manifests (``encryption
    is None``) are never signature-checked and a stray ``.sig`` member is
    simply ignored.

    ``trusted_signing_pem``: the config-pinned Ed25519 public PEM (never
    the trusted signing key from the external file).

    ``require_signature``: when True, an encrypted manifest WITHOUT a
    trusted key is already an error (verifiers that must fail closed).
    """
    try:
        raw = read_service_member(runner, archive, _MANIFEST_MEMBER)
        data = json.loads(raw)
        manifest = Manifest.from_json(data)
    except Exception as exc:  # noqa: BLE001 — any read/parse failure is an EpochError
        raise EpochError(
            f"manifest of {archive.name} is unreadable: {_reason(exc)}") from exc

    if manifest.encryption == ENCRYPTION_DATA:
        if require_signature and trusted_signing_pem is None:
            raise EpochError(
                f"manifest of {archive.name} is encrypted but no trusted signing "
                f"key was provided to verify its mandatory signature")
        if trusted_signing_pem is not None:
            if _crypto is None:  # pragma: no cover - offered only with crypto
                raise EpochError(
                    f"manifest of {archive.name} is encrypted but the crypto "
                    f"layer is unavailable for signature verification")
            try:
                sig_bytes = read_service_member(
                    runner, archive, MANIFEST_SIGNATURE_MEMBER)
            except Exception as exc:  # noqa: BLE001 — absence is a failure
                raise EpochError(
                    f"encrypted manifest of {archive.name} requires service member "
                    f"{MANIFEST_SIGNATURE_MEMBER}, which is missing or unreadable: "
                    f"{_reason(exc)}") from exc
            _verify_manifest_signature(raw, sig_bytes, trusted_signing_pem,
                                       archive_name=archive.name)
    return manifest


def _verify_manifest_signature(
    manifest_bytes: bytes,
    sig_bytes: bytes,
    trusted_signing_pem: bytes,
    *,
    archive_name: str = "",
) -> None:
    """Verify the detached manifest signature against the trusted signing key.

    ``sig_bytes`` is the raw ``.backup/manifest.json.sig`` member content
    (a :class:`backuper.crypto.Signature` JSON); the signature covers EXACT
    ``manifest_bytes``. Delegates to
    :func:`backuper.crypto.verify_bytes` via ``Signature.from_json``;
    every failure (malformed member, foreign key, bad signature) is
    wrapped into :class:`EpochError` -- the chain layer's uniform error
    surface. Messages carry key ids/fingerprints only, never key material.
    """
    subject = f"manifest of {archive_name}" if archive_name else "manifest"
    if _crypto is None:  # pragma: no cover - guarded by the caller
        raise EpochError(
            f"{subject} signature cannot be verified: the crypto layer is unavailable")
    try:
        sig_raw = sig_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EpochError(f"{subject} signature member is not valid UTF-8") from exc
    try:
        sig = _crypto.Signature.from_json(sig_raw)
    except Exception as exc:  # noqa: BLE001 — malformed sig data is an EpochError
        raise EpochError(f"{subject} signature member is unreadable: {_reason(exc)}") from exc
    try:
        _crypto.verify_bytes(trusted_signing_pem, manifest_bytes, sig)
    except _crypto.CryptoError as exc:
        raise EpochError(f"{subject} signature verification failed: {exc}") from exc


def load_snapshot(runner: rar_runner.RarRunner, archive: Path) -> Snapshot:
    """Read and parse ``.backup/files.json`` from the archive."""
    try:
        raw = read_service_member(runner, archive, _SNAPSHOT_MEMBER)
        data = json.loads(raw)
        return Snapshot.from_json(data)
    except Exception as exc:  # noqa: BLE001 — any read/parse failure is an EpochError
        raise EpochError(
            f"snapshot of {archive.name} is unreadable: {_reason(exc)}") from exc


def load_embedded_config(runner: rar_runner.RarRunner, archive: Path) -> bytes:
    """Read the raw bytes of ``.backup/config.yaml`` from the archive."""
    try:
        return read_service_member(runner, archive, _CONFIG_MEMBER)
    except Exception as exc:  # noqa: BLE001 — any read failure is an EpochError
        raise EpochError(
            f"embedded config of {archive.name} is unreadable: {_reason(exc)}") from exc


# ---------------------------------------------------------------------------
# Base-archive validation for diff runs
# ---------------------------------------------------------------------------

@dataclass
class BaseInfo:
    """Everything a diff run needs to know about its base archive."""

    archive: Path          # tip archive path
    manifest: Manifest
    snapshot: Snapshot
    config_bytes: bytes    # embedded config.yaml raw bytes (the operative config for a diff run)


def check_base_archive(
    runner: rar_runner.RarRunner,
    archive: Path,
    *,
    trusted_signing_pem: bytes | None = None,
    require_signature: bool = False,
) -> BaseInfo:
    """Validate that ``archive`` is a usable base for a diff run.

    Checks, in order, every failure raising :class:`EpochError`:

    1. the archive file exists,
    2. its manifest parses (see :func:`load_manifest`: the signature of an
       encrypted manifest is verified when ``trusted_signing_pem`` is
       given, and ``require_signature`` makes a missing trusted key a
       failure),
    3. its files.json parses,
    4. its embedded config is readable,
    5. the manifest's ``previous_filename`` (when not None) names an
       existing ``.rar`` in the same directory (chain sanity for the
       base itself).
    """
    archive = Path(archive)
    if not archive.is_file():
        raise EpochError(f"{archive} is missing")
    manifest = load_manifest(
        runner, archive,
        trusted_signing_pem=trusted_signing_pem, require_signature=require_signature)
    snapshot = load_snapshot(runner, archive)
    config_bytes = load_embedded_config(runner, archive)
    prev = manifest.previous_filename
    if prev is not None:
        prev_path = archive.parent / prev
        if not prev_path.is_file():
            raise EpochError(
                f"previous archive {prev} referenced by {archive.name} is missing")
    return BaseInfo(
        archive=archive, manifest=manifest, snapshot=snapshot, config_bytes=config_bytes)


# ---------------------------------------------------------------------------
# Job config vs embedded config comparison
# ---------------------------------------------------------------------------

# The normalized semantic tuple for a raw embedded config dict. Sentinels
# (None) mark values whose shape is unusable, guaranteeing a mismatch.
_EmbeddedKey = tuple[
    str | None,                       # source
    tuple[str, ...] | None,           # exclude_extensions
    tuple[str, ...] | None,           # exclude_dirs
    tuple[str, ...] | None,           # lock_check_extensions
    int | None,                       # compression
    str | None,                       # recipient key id
    str | None,                       # signing key id
]


def _string_list_key(data: dict, key: str,
                     normalize: callable[[str], str]) -> tuple[str, ...] | None:
    """Normalize one optional string-list config key like load_config does.

    Missing/null -> ``()``; present but not a list of strings -> ``None``
    (sentinel: can never match a validated job config).
    """
    value = data.get(key)
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return None
    return tuple(sorted(normalize(item) for item in value))


def _embedded_key_id(value: object) -> str | None:
    """Key id for one embedded public-key PEM value; unusable shapes -> ``None``.

    Mirrors the id computation of :func:`backuper.config._parse_public_key`
    without its strictness: the embedded config is never re-validated
    here, so a missing value or an unparseable PEM just yields ``None``
    (versus the job config's real id -> a guaranteed mismatch aspect).
    """
    if _crypto is None:
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        public = _crypto.load_public_pem(value.strip().encode("ascii"))
    except (ValueError, TypeError, _crypto.CryptoError):
        return None
    return _crypto.key_id_for_public(public)


def _embedded_semantic_key(data: object, embedded_signing_key_id: str | None = None) -> _EmbeddedKey:
    """Mirror :func:`backuper.config.semantic_key` for a raw YAML dict.

    Applies the same normalization ``load_config`` applies, then sorts
    exactly as ``semantic_key`` does. Missing keys fall back to the same
    defaults as ``load_config`` (no excludes, compression 3, no keys). A
    non-mapping payload yields all-None sentinels (everything differs);
    the two key aspects are the embedded PEMs' key ids (see
    :func:`_embedded_key_id`).
    """
    if not isinstance(data, dict):
        return (None, None, None, None, None, None, None)

    raw_source = data.get("source")
    if isinstance(raw_source, str) and raw_source.strip():
        source_key: str | None = os.path.normcase(str(Path(raw_source)))
    else:
        source_key = None

    exts = _string_list_key(data, "exclude_extensions", normalize_ext)
    dirs = _string_list_key(data, "exclude_dirs", normalize_exclude_dir)
    locks = _string_list_key(data, "lock_check_extensions", normalize_ext)

    raw_compression = data.get("compression", 3)
    if isinstance(raw_compression, bool) or not isinstance(raw_compression, int):
        compression_key: int | None = None
    else:
        compression_key = raw_compression

    recipient_id = _embedded_key_id(data.get("recipient_public_key"))
    # signing key id comes only from the externally supplied value (manifest);
    # config.yaml no longer carries signing_public_key.
    signing_id = embedded_signing_key_id

    return (source_key, exts, dirs, locks, compression_key, recipient_id, signing_id)


def config_mismatch_warning(job_cfg: Config, embedded_bytes: bytes, *,
                            embedded_signing_key_id: str | None = None) -> str | None:
    """Compare the job config against the archive's embedded config.

    Returns ``None`` when the semantics are equal. Raw bytes are never
    compared: the embedded YAML is parsed and normalized exactly like
    :func:`backuper.config.load_config` + :func:`backuper.config.semantic_key`
    would, so BOM/CRLF re-saves or key reordering of an unchanged config
    do not produce spurious warnings.

    Returns a one-line warning listing the differing aspects otherwise.
    An unparsable embedded config yields its own warning (the archive
    config is used as-is by the caller).
    """
    import yaml  # noqa: PLC0415 — lazy import: only this function needs pyyaml

    try:
        data = yaml.safe_load(embedded_bytes)
    except yaml.YAMLError:
        return ("warning: previous archive's embedded config is not valid YAML; "
                "using the archive config as-is")

    job_key = semantic_key(job_cfg)
    embedded_key = _embedded_semantic_key(data, embedded_signing_key_id)
    if embedded_key == job_key:
        return None
    differing = [
        name for name, job_val, emb_val in zip(_ASPECT_NAMES, job_key, embedded_key, strict=True)
        if job_val != emb_val
    ]
    return (f"warning: job config differs from the last archive's config "
            f"({', '.join(differing)}); the archive config is used for this diff")
