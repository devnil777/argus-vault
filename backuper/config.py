"""Job configuration: ``config.yaml`` inside the backup job directory.

Schema::

    source: D:\\Data\\Documents        # exactly one source directory (required)
    exclude_extensions: [".tmp"]     # optional; case-insensitive, dot optional -> normalized ".tmp"
    exclude_dirs: ["node_modules"]   # optional; excludes a matching dir name anywhere
                                     # or a matching absolute Windows directory path
                                     # (quote Windows paths with YAML single quotes)
    lock_check_extensions: [".pst"]  # optional; files with these exts are probed
                                     # for read-locks before archiving
    compression: 3                   # optional int 0..5, default 3 (RAR -m level)

Strictness: unknown keys are rejected (a typo like ``exclude_extention``
must not silently disable exclusions), as are missing/empty/non-absolute
``source``, non-list extension/dir values, empty entries and ``compression``
outside 0..5.

Archive encryption keys (optional, both must be set together)::

    recipient_public_key: |    # PEM of the RSA key whose private half
      -----BEGIN PUBLIC KEY--  # unwraps archive passwords
    # signing public key lives in signing_public.pem next to config.yaml
    # (not in config.yaml) -- PEM of the Ed25519 key whose private half
    # signs manifests (verifier pins trust via that file)

The PUBLIC halves are the only key material in config.yaml (they are
embedded into every archive with it). The PRIVATE halves live as plain
PKCS8 PEM FILES next to config.yaml, with fixed names, never as config
paths and never inside archives:

    recipient_private.pem   # unwraps archive passwords (restore/verify/password)
    signing_private.pem     # signs manifests during full/diff creation

Both keys absent == the legacy unencrypted behaviour. On load each PEM is
parsed, canonicalized (byte-comparable) and hashed to a stable short
``key id`` that participates in :func:`semantic_key`, so a config that
swaps keys is detected by the chain comparison logic.

The exact raw bytes are kept on the loaded config (``raw_bytes``) because
they are embedded into every archive and hashed (``config_sha256``). The
comparison of the job config against the config embedded in the previous
archive uses :func:`semantic_key`, which ignores raw bytes -- so BOM or
CRLF re-saves of an unchanged config do not produce spurious warnings.
"""

from __future__ import annotations

import ntpath
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from backuper.errors import ConfigError

CONFIG_NAME = "config.yaml"

# Private-key file names, FIXED, located next to config.yaml (never stored
# as configurable paths and never embedded into archives).
RECIPIENT_PRIVATE_NAME = "recipient_private.pem"
SIGNING_PRIVATE_NAME = "signing_private.pem"

# Public signing key file (FIXED name), located next to config.yaml. The
# signing PUBLIC key is no longer stored in config.yaml or in manifests;
# it lives only in this file (and is never embedded into archives).
SIGNING_PUBLIC_NAME = "signing_public.pem"

_PRIVATE_KEY_NAMES = {
    "recipient": RECIPIENT_PRIVATE_NAME,
    "signing": SIGNING_PRIVATE_NAME,
}

_KNOWN_KEYS = frozenset({
    "source",
    "exclude_extensions",
    "exclude_dirs",
    "lock_check_extensions",
    "compression",
    "recipient_public_key",
})

# The crypto layer is imported defensively: a backuper installation without
# it still loads/validates legacy (unencrypted) configs normally; only
# key-bearing configs and keygen demand the module.
try:
    from backuper import crypto as _crypto  # noqa: PLC0415
except ImportError:  # pragma: no cover - exercised without the layer
    _crypto = None


def private_key_path(config_path: Path, kind: str) -> Path:
    """Filesystem path of a private key file: next to ``config.yaml``.

    ``kind`` is ``"recipient"`` or ``"signing"`` (ValueError otherwise).
    """
    name = _PRIVATE_KEY_NAMES.get(kind)
    if name is None:
        raise ValueError(f"unknown private key kind {kind!r}")
    return Path(config_path).parent / name


def signing_public_key_path(config_path: Path) -> Path:
    """Filesystem path of the signing PUBLIC key file: next to ``config.yaml``."""
    return Path(config_path).parent / SIGNING_PUBLIC_NAME


def _parse_public_key(path: Path, key: str, value: object) -> tuple[str, str]:
    """Validate one public PEM from the config; return (canonical PEM, key id)."""
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"config file {path}: {key!r} must be a non-empty PEM string")
    if _crypto is None:
        raise ConfigError(
            f"config file {path}: {key!r} requires the backuper.crypto layer, which is unavailable")
    pem = value.strip().encode("ascii", errors="strict")
    try:
        public = _crypto.load_public_pem(pem)
    except (ValueError, _crypto.CryptoError) as exc:  # CryptoError is not a ValueError subclass
        raise ConfigError(f"config file {path}: {key!r} is not a valid PEM public key ({exc})") from exc
    canonical = _crypto.canonical_public_pem(pem).decode("ascii")
    return canonical, _crypto.key_id_for_public(public)


@dataclass
class Config:
    """A loaded job configuration."""

    source: Path
    exclude_extensions: list[str]    # normalized lowercase ".tmp" form
    exclude_dirs: list[str]          # normalized lowercase names/Windows paths, no trailing separators
    lock_check_extensions: list[str]  # normalized lowercase ".pst" form
    compression: int                 # 0..5 (RAR -m level)
    # Encryption keys (None == legacy unencrypted config): canonical PEM
    # text + stable short key ids; public halves only, repr-safe.
    recipient_public_pem: str | None = field(default=None, kw_only=True)
    signing_public_pem: str | None = field(default=None, kw_only=True)
    recipient_key_id: str | None = field(default=None, kw_only=True)
    signing_key_id: str | None = field(default=None, kw_only=True)
    raw_bytes: bytes                 # EXACT bytes as read from disk (embedded + hashed)
    path: Path                       # where it was loaded from

    @property
    def encryption_enabled(self) -> bool:
        """True when the config carries the key pair enabling encryption."""
        return self.recipient_public_pem is not None


def normalize_ext(s: str) -> str:
    """Normalize a file extension to the lowercase ``".tmp"`` form (``""`` -> ``""``)."""
    ext = s.strip().lower()
    if not ext:
        return ""
    return ext if ext.startswith(".") else "." + ext


def normalize_exclude_dir(value: str) -> str:
    """Normalize an excluded directory name or absolute Windows path.

    Bare names retain the historical separator stripping and lowercase
    behavior. Absolute drive and UNC paths use backslashes, lowercase
    spelling, and no trailing separator; extended ``\\?\\`` and
    ``\\?\\UNC\\`` prefixes are removed so prefixed filesystem paths can
    be compared with config entries too.
    """
    value = value.strip()
    windows_path = value.replace("/", "\\")
    lowered = windows_path.lower()
    if lowered.startswith("\\\\?\\unc\\"):
        windows_path = "\\\\" + windows_path[8:]
    elif lowered.startswith("\\\\?\\"):
        windows_path = windows_path[4:]

    is_drive_path = (
        len(windows_path) >= 3
        and windows_path[0].isalpha()
        and windows_path[1:3] == ":\\"
    )
    is_unc_path = windows_path.startswith("\\\\")
    if is_drive_path or is_unc_path:
        # ntpath handles dot segments and repeated separators independently
        # of the host OS, which matters when configs are inspected elsewhere.
        normalized = ntpath.normpath(windows_path).lower()
        # A drive root must retain its separator: without it (``d:``) it is
        # drive-relative, not an absolute path, and the scanner won't match it.
        if len(normalized) == 3 and normalized[1:] == ":\\":
            return normalized
        return normalized.rstrip("\\")

    return value.strip("/\\").lower()


def _string_list(path: Path, data: dict, key: str) -> list[str]:
    """Extract ``key`` as a list of non-empty strings ([] when absent/null)."""
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{path}: {key!r} must be a list of strings, got {value!r}")
    items = [item.strip() for item in value]
    if any(not item for item in items):
        raise ConfigError(f"{path}: {key!r} must not contain empty entries")
    return items


def load_config(path: Path) -> Config:
    """Load and validate ``config.yaml`` (raises :class:`ConfigError` on any problem)."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc

    try:
        # utf-8-sig: tolerate a BOM from editor re-saves; semantic_key makes
        # this invisible for the embedded-config comparison anyway.
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"config file {path} is not valid UTF-8: {exc}") from exc

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file {path} failed to parse as YAML: {exc}") from exc
    return _build_config(data, path, raw)


def config_from_bytes(data: bytes) -> Config:
    """Parse and validate raw ``config.yaml`` bytes into a :class:`Config`.

    The operative-config path of diff runs: the bytes are the embedded
    ``.backup/config.yaml`` read out of an archive. Validation is exactly
    :func:`load_config`'s (same rules, same :class:`ConfigError` messages,
    with the pseudo path ``<embedded config>``); ``raw_bytes`` is the input
    verbatim, so embedding + hashing it again round-trips.
    """
    try:
        # utf-8-sig, same tolerance as load_config for editor re-saves.
        text = bytes(data).decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"config file <embedded config> is not valid UTF-8: {exc}") from exc
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file <embedded config> failed to parse as YAML: {exc}") from exc
    return _build_config(parsed, Path("<embedded config>"), bytes(data))


def _build_config(data: object, path: Path, raw: bytes) -> Config:
    """Validate a parsed YAML payload and build the :class:`Config`.

    Shared by :func:`load_config` and :func:`config_from_bytes`; ``path`` is
    only used in error message texts, ``raw`` becomes ``raw_bytes`` as-is.
    """
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(
            f"config file {path}: top level must be a mapping, got {type(data).__name__}")
    for key in data:
        if not isinstance(key, str):
            raise ConfigError(f"config file {path}: keys must be strings, got {key!r}")
    unknown = sorted(set(data) - _KNOWN_KEYS)
    if unknown:
        raise ConfigError(f"config file {path}: unknown key(s): {', '.join(unknown)}")

    source_value = data.get("source")
    if source_value is None:
        raise ConfigError(f"config file {path}: 'source' is required")
    if not isinstance(source_value, str) or not source_value.strip():
        raise ConfigError(f"config file {path}: 'source' must be a non-empty string, got {source_value!r}")
    source = Path(source_value)
    if not source.is_absolute():
        raise ConfigError(f"config file {path}: 'source' must be an absolute path, got {source_value!r}")

    compression = data.get("compression", 3)
    if isinstance(compression, bool) or not isinstance(compression, int):
        raise ConfigError(f"config file {path}: 'compression' must be an int, got {compression!r}")
    if not 0 <= compression <= 5:
        raise ConfigError(f"config file {path}: 'compression' must be in 0..5, got {compression}")

    exclude_extensions = [normalize_ext(item) for item in _string_list(path, data, "exclude_extensions")]
    lock_check_extensions = [
        normalize_ext(item) for item in _string_list(path, data, "lock_check_extensions")
    ]
    # Directory names match any component; absolute Windows paths identify a
    # specific directory. The shared helper also handles long-path prefixes.
    exclude_dirs = [
        normalize_exclude_dir(item)
        for item in _string_list(path, data, "exclude_dirs")
    ]

    # Optional encryption keys. recipient_public_key lives in config.yaml;
    # the signing PUBLIC key lives in the separate signing_public.pem file
    # next to config.yaml. Both or neither: an encrypted config needs both
    # halves.
    recipient_value = data.get("recipient_public_key")

    recipient_public_pem = recipient_key_id = None
    if recipient_value is not None:
        recipient_public_pem, recipient_key_id = _parse_public_key(
            path, "recipient_public_key", recipient_value)

    # signing public key comes ONLY from the dedicated file
    signing_public_pem = signing_key_id = None
    sp_path = signing_public_key_path(path)
    try:
        if sp_path.is_file():
            signing_source_value = sp_path.read_text(encoding="utf-8")
            if str(signing_source_value).strip():
                signing_public_pem, signing_key_id = _parse_public_key(
                    path, "signing_public_key", signing_source_value)
    except OSError:
        pass

    # both or neither (encrypted behaviour). Embedded configs of the new
    # format carry only recipient_public_key in config.yaml; signing id
    # travels via the manifest, so a missing signing file on the embedded
    # path is not an error.
    embedded = (Path(path).name == "<embedded config>")
    if recipient_value is not None and signing_public_pem is None and not embedded:
        # real job config: signing file must exist
        if not sp_path.is_file():
            raise ConfigError(
                f"config file {path}: 'recipient_public_key' and the signing public "
                f"key file ({SIGNING_PUBLIC_NAME}) must be set together "
                f"(or both absent for unencrypted behaviour)")
    if recipient_value is None and signing_public_pem is not None:
        raise ConfigError(
            f"config file {path}: 'recipient_public_key' and the signing public "
            f"key file ({SIGNING_PUBLIC_NAME}) must be set together "
            f"(or both absent for unencrypted behaviour)")

    return Config(
        source=source,
        exclude_extensions=exclude_extensions,
        exclude_dirs=exclude_dirs,
        lock_check_extensions=lock_check_extensions,
        compression=compression,
        recipient_public_pem=recipient_public_pem,
        signing_public_pem=signing_public_pem,
        recipient_key_id=recipient_key_id,
        signing_key_id=signing_key_id,
        raw_bytes=raw,
        path=path,
    )


def semantic_key(cfg: Config) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...],
                                       int, str | None, str | None]:
    """Hashable value capturing configuration semantics.

    Used to compare the job config against the config embedded in the
    previous archive. Deliberately excludes ``raw_bytes``/``path`` so BOM
    or CRLF re-saves of an unchanged config never produce spurious warnings.

    The two key ids are part of the semantics: swapping either public key
    (a new keygen) changes the tuple, while reformatting/whitespace-only
    differences of the same key do not (ids come from the parsed keys).
    """
    return (
        os.path.normcase(str(cfg.source)),
        tuple(sorted(cfg.exclude_extensions)),
        tuple(sorted(cfg.exclude_dirs)),
        tuple(sorted(cfg.lock_check_extensions)),
        cfg.compression,
        cfg.recipient_key_id,
        cfg.signing_key_id,
    )


class _LiteralStr(str):
    """Marker so public-key PEM blocks dump as YAML literal blocks (``|``).

    A multi-line ``str`` would otherwise be emitted in quoted/flow style
    with ``\\n`` escapes; the literal block is what ``config.yaml``
    documents and what hand editing of the PEM stays easy with.
    """


def _literal_representer(dumper: yaml.SafeDumper, data: _LiteralStr) -> yaml.Node:
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="|")


yaml.SafeDumper.add_representer(_LiteralStr, _literal_representer)


def rewrite_config_with_public_keys(
    path: Path,
    recipient_public_pem: bytes,
    signing_public_pem: bytes,
    *,
    force: bool,
) -> None:
    """Add/set the two public keys in an existing ``config.yaml`` on disk.

    Used by the keygen flow. The file is re-parsed (tolerating a BOM) and
    re-dumped with ``yaml.safe_dump(sort_keys=False)``: other keys keep
    their values and relative order, but comments are NOT preserved. The
    result is UTF-8 without BOM and LF line endings.

    Raises :class:`ConfigError` when the file already holds a DIFFERENT
    public key and ``force`` is not set.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise ConfigError(f"config file {path} is not valid UTF-8: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file {path} failed to parse as YAML: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict) or any(not isinstance(k, str) for k in data):
        raise ConfigError(f"config file {path}: top level must be a string mapping")
    # drop legacy inline signing key before the unknown-key check
    data.pop("signing_public_key", None)
    unknown = sorted(set(data) - _KNOWN_KEYS)
    if unknown:
        raise ConfigError(f"config file {path}: unknown key(s): {', '.join(unknown)}")

    new_recipient = bytes(recipient_public_pem).decode("ascii").strip()
    new_signing = bytes(signing_public_pem).decode("ascii").strip()

    existing = data.get("recipient_public_key")
    if existing is not None and str(existing).strip() != new_recipient and not force:
        raise ConfigError(
            f"config file {path}: 'recipient_public_key' already holds a different "
            f"public key (pass --force to replace it)")
    data["recipient_public_key"] = _LiteralStr(new_recipient)

    # signing public key no longer lives in config.yaml
    data.pop("signing_public_key", None)

    dump = yaml.safe_dump(data, sort_keys=False, allow_unicode=True,
                          default_flow_style=False)
    try:
        path.write_bytes(dump.encode("utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot write config file {path}: {exc}") from exc

    sp_path = signing_public_key_path(path)
    if sp_path.is_file():
        try:
            existing_file = sp_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"cannot read signing public key file {sp_path}: {exc}") from exc
        if existing_file != new_signing and not force:
            raise ConfigError(
                f"signing public key file {sp_path}: already holds a different "
                f"public key (pass --force to replace it)")
    try:
        sp_path.write_text(new_signing + "\n", encoding="utf-8", newline="\n")
    except OSError as exc:
        raise ConfigError(f"cannot write signing public key file {sp_path}: {exc}") from exc

    sp_path = signing_public_key_path(path)
    if sp_path.is_file():
        try:
            existing_file = sp_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"cannot read signing public key file {sp_path}: {exc}") from exc
        if existing_file != new_signing and not force:
            raise ConfigError(
                f"signing public key file {sp_path}: already holds a different "
                f"public key (pass --force to replace it)")
    try:
        sp_path.write_text(new_signing + "\n", encoding="utf-8", newline="\n")
    except OSError as exc:
        raise ConfigError(f"cannot write signing public key file {sp_path}: {exc}") from exc
