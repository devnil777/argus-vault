"""Orchestration of the four backup commands: full / diff / verify / list.

The runner layer wires everything together:

- preflight (Rar.exe location, job/source directory layout),
- the job lock held for the duration of a run,
- scan -> diff -> manifest/spec construction,
- :func:`backuper.archiver.create_archive` for the actual archive work,
- failure bookkeeping (``<ts>_<type>_failed.log`` / ``<ts>_diff_nothing.log``)
  and one-line success summaries.

Exit-code semantics come from :mod:`backuper.errors`; the runner raises,
:mod:`backuper.cli` translates to exit codes.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import subprocess
import sys
import time
import traceback
import uuid
from pathlib import Path

from backuper import __version__, archiver, chain, crypto, diffing
from backuper.archiver import CreateSpec
from backuper.config import (
    CONFIG_NAME,
    RECIPIENT_PRIVATE_NAME,
    SIGNING_PRIVATE_NAME,
    Config,
    config_from_bytes,
    load_config,
    private_key_path,
    rewrite_config_with_public_keys,
    signing_public_key_path,
)
from backuper.errors import (
    ConfigError,
    EpochError,
    NoOpResult,
    PreflightError,
    RarError,
    VerificationError,
)
from backuper.lock import JobLock
from backuper.models import (
    ENCRYPTION_DATA,
    MANIFEST_SIGNATURE_MEMBER,
    Manifest,
    Snapshot,
    ns_to_iso,
)
from backuper.progress import ScanProgress, fmt_duration
from backuper.rar_runner import (
    RarRunner,
    find_rar,
    rar_version,
    read_service_member,
    winapi_path,
)
from backuper.scanner import ScanStats, leaves, scan_source
from backuper.verify import print_reports, verify_archive, verify_chain

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _abs_dir(job_dir: Path) -> Path:
    """Normalize a job dir to an absolute path.

    Archive targets are handed to Rar.exe as literal paths while RAR itself
    runs with cwd=staging/source, so a relative job dir would resolve against
    the wrong cwd (exit 9, "cannot find the path").
    """
    return Path(os.path.abspath(job_dir))


def _resolve_runner(rar_path: str | None) -> tuple[RarRunner, str]:
    """Locate Rar.exe and probe its version (PreflightError on failure)."""
    try:
        path = find_rar(rar_path)
        runner = RarRunner(path)
        version = rar_version(runner)
    except FileNotFoundError as exc:
        raise PreflightError(str(exc)) from exc
    except RuntimeError as exc:
        raise PreflightError(f"RAR version probe failed: {exc}") from exc
    return runner, version


def _preflight_layout(
    job_dir: Path,
    source: Path,
    *,
    create_job_dir: bool,
    need_job_config: bool,
) -> None:
    """Job-directory and source-directory layout checks.

    - ``create_job_dir`` (full runs): create the job dir when missing;
      otherwise it must already exist (diff/verify/list).
    - ``need_job_config`` (full runs): config.yaml must be present.
    - source must exist as a directory, must not nest with the job dir
      (either way, nor be equal) and must not contain a ``.backup`` entry
      at its root.
    """
    job_dir = _abs_dir(job_dir)
    source = Path(source)

    if create_job_dir:
        try:
            job_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise PreflightError(f"cannot create job directory {job_dir}: {exc}") from exc
    elif not job_dir.is_dir():
        raise PreflightError(f"job directory not found: {job_dir}")

    if need_job_config and not (job_dir / CONFIG_NAME).is_file():
        raise ConfigError(f"config file not found: {job_dir / CONFIG_NAME}")

    if not source.is_dir():
        raise PreflightError(f"source directory not found: {source}")

    job_abs = os.path.normcase(os.path.abspath(job_dir))
    src_abs = os.path.normcase(os.path.abspath(source))
    if job_abs == src_abs:
        raise PreflightError(
            f"the job directory and the source directory must differ ({job_dir})")
    if src_abs.startswith(job_abs + os.sep):
        raise PreflightError(
            f"the source directory must not be inside the job directory: {source}")
    if job_abs.startswith(src_abs + os.sep):
        raise PreflightError(
            f"the job directory must not be inside the source directory: {job_dir}")

    if os.path.lexists(winapi_path(source / ".backup")):
        raise ConfigError(
            "refused: source contains a '.backup' directory at its root "
            "(collides with service data)")


def _human_size(num: int) -> str:
    """Binary-unit human size, e.g. ``12.3 MiB``."""
    size = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TiB"  # unreachable


def _local_ts() -> str:
    """Local-time archive name timestamp: ``YYYY-MM-DD_HHMMSS``."""
    return time.strftime("%Y-%m-%d_%H%M%S")


def _bump_ts(ts: str) -> str:
    """Add one second to a ``YYYY-MM-DD_HHMMSS`` name timestamp."""
    dt = datetime.datetime.strptime(ts, "%Y-%m-%d_%H%M%S")
    return (dt + datetime.timedelta(seconds=1)).strftime("%Y-%m-%d_%H%M%S")


def _name_variants(base: str) -> list[str]:
    """Every file name an archive with this base name may have produced."""
    return [
        f"{base}.rar",
        f"{base}.rar.sha256",
        f"{base}.rar.log",
        f"{base}_failed.log",
        f"{base}_nothing.log",
    ]


def _free_archive_ts(epoch_dir: Path, archive_type: str) -> str:
    """Bump the timestamp seconds until the archive base name is unused AND
    sorts strictly after the current tip of the epoch.

    Prevents silent overwrites when a run happens within the same second
    as an existing archive, log or sidecar. Also prevents a chain-order
    bug: within one second "..._diff" sorts BEFORE "..._full" ("d" < "f"),
    so a diff created in the same second as its epoch's full (or tip) would
    name-sort before it and corrupt the filename-ordered chain that tip
    selection, list linkage and verify --chain all rely on.
    """
    archives = sorted(p.stem for p in epoch_dir.glob("*.rar")) \
        if epoch_dir.is_dir() else []
    tip_stem = archives[-1] if archives else ""
    ts = _local_ts()
    for _ in range(600):  # ~10 minutes of collisions is beyond pathological
        if f"{ts}_{archive_type}" > tip_stem and not any(
                (epoch_dir / name).exists()
                for name in _name_variants(f"{ts}_{archive_type}")):
            return ts
        ts = _bump_ts(ts)
    raise EpochError(
        f"could not find a free {archive_type} archive timestamp in "
        f"{epoch_dir} (all seconds taken)")


def _pick_full_epoch(job_dir: Path) -> tuple[str, Path]:
    """Timestamp + epoch dir for a new full run.

    The epoch dir is derived from the local date; an epoch that already
    has a full archive refuses a second one (one full per epoch). Name
    collisions bump the timestamp seconds (possibly rolling into the next
    day, which starts a fresh epoch dir).
    """
    ts = _local_ts()
    for _ in range(600):
        epoch_dir = job_dir / ts[:10]
        if any(epoch_dir.glob("*_full.rar")):
            raise EpochError(
                f"epoch {ts[:10]} already exists — delete it to start a new full epoch")
        if not any(
                (epoch_dir / name).exists()
                for name in _name_variants(f"{ts}_full")):
            return ts, epoch_dir
        ts = _bump_ts(ts)
    raise EpochError("could not find a free full-archive timestamp (all seconds taken)")


def _sweep_tmp_files(*dirs: Path) -> None:
    """Best-effort deletion of stale leftovers (startup sweep).

    Removes unfinished ``*.rar.tmp`` archives, stray RAR repair artifacts
    (``fixed.*.rar`` / ``rebuilt.*.rar`` from an interrupted repair) and
    RAR's archive-modification work files (``__rar_*.rartemp``; ``-w`` pins
    them next to the archive and a killed run leaves one behind). None may
    ever stay in an epoch dir, because they match the ``*.rar`` archive
    listing and a ``rebuilt...`` name would even sort after the real
    archives and become the tip.
    """
    patterns = ("*.rar.tmp", "fixed.*.rar", "rebuilt.*.rar", "__rar_*.rartemp")
    for d in dirs:
        try:
            if not d.is_dir():
                continue
            for pattern in patterns:
                for p in d.glob(pattern):
                    try:
                        p.unlink()
                    except OSError:
                        pass
        except OSError:
            pass


def _config_summary(cfg: Config) -> list[str]:
    """Human-readable config summary for the failed-run log."""
    return [
        "config summary:",
        f"  source                 : {cfg.source}",
        f"  exclude_extensions     : {cfg.exclude_extensions}",
        f"  exclude_dirs           : {cfg.exclude_dirs}",
        f"  lock_check_extensions  : {cfg.lock_check_extensions}",
        f"  compression            : {cfg.compression}",
    ]


def _write_failed_log(
    job_dir: Path,
    epoch_dir: Path | None,
    ts: str,
    archive_type: str,
    stage: str,
    message: str,
    warnings: list[str],
    cfg: Config,
    exc: BaseException | None,
) -> None:
    """Write ``<ts>_<type>_failed.log`` (epoch dir when it exists, else job dir)."""
    target_dir = epoch_dir if epoch_dir is not None and epoch_dir.is_dir() else job_dir
    lines = [
        "backuper run failed",
        "===================",
        f"attempted archive : {ts}_{archive_type}.rar",
        f"started (UTC)     : {ns_to_iso(time.time_ns())}",
        f"stage             : {stage}",
        f"error             : {message}",
        "",
    ]
    lines += _config_summary(cfg)
    lines.append("")
    lines.append("scan warnings:")
    if warnings:
        lines += [f"  {w}" for w in warnings]
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("traceback:")
    if exc is not None:
        formatted = "".join(traceback.format_exception(exc)).rstrip("\n")
        lines += formatted.splitlines()
    else:
        lines.append("  (not an exception path)")
    lines.append("")

    path = target_dir / f"{ts}_{archive_type}_failed.log"
    try:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write("\n".join(lines))
        print(f"failed run log written: {path}", file=sys.stderr)
    except OSError as log_exc:
        print(f"warning: could not write failed-run log {path}: {log_exc}", file=sys.stderr)


def _mismatch_warning_for_full(runner: RarRunner, job_dir: Path, cfg: Config) -> str | None:
    """Best-effort job-config-vs-latest-archive mismatch warning for full runs.

    Any epoch-layer problem (no epochs, unreadable tip) silently skips the
    warning -- it must never block a fresh full run.
    """
    try:
        epoch_dir = chain.latest_epoch(job_dir)
        tip = chain.tip_archive(epoch_dir)
        embedded = chain.load_embedded_config(runner, tip)
        try:
            manifest = chain.load_manifest(runner, tip)
            signing_id = manifest.signing_key_id
        except EpochError:
            signing_id = None
    except EpochError:
        return None
    return chain.config_mismatch_warning(cfg, embedded, embedded_signing_key_id=signing_id)


def _print_warnings(warnings: list[str]) -> None:
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)


def _print_config_encryption_status(cfg: Config) -> None:
    """Report the effective run config's content-encryption setting."""
    if cfg.encryption_enabled:
        print("encryption: ON")


def _warn_private_keys_next_to_config(config_path: Path) -> None:
    """Warn which expected private-key files exist beside a config path.

    This only checks file presence. It does not imply the files are included
    in an archive or protected by archive encryption.
    """
    names = (RECIPIENT_PRIVATE_NAME, SIGNING_PRIVATE_NAME)
    present = [name for name in names if (Path(config_path).parent / name).is_file()]
    if present:
        print("warning: private key file(s) present next to config.yaml: "
              + ", ".join(present), file=sys.stderr)


def _print_manifest_encryption_status(reports: list) -> None:
    """Report encryption only for archives with encrypted manifests."""
    for report in reports:
        manifest = report.manifest
        if manifest is not None and manifest.encryption == ENCRYPTION_DATA:
            print(f"encryption: {report.archive.name}: ON")


def _scan_phase(source: Path, cfg: Config) -> tuple[Snapshot, list[str]]:
    """Scan with live counters and a final stats block.

    The live lines repaint in place on a tty only; the final stats block is
    unconditional (it is what the run logs keep).
    """
    print(f"scanning {source} ...", flush=True)
    stats = ScanStats()
    scan_progress = ScanProgress(stats)
    t0 = time.monotonic()
    try:
        snapshot, scan_warnings = scan_source(
            source, cfg, stats=stats, progress=scan_progress.report)
    finally:
        scan_progress.finish()
    _print_warnings(scan_warnings)

    skipped = sum(1 for e in snapshot.files if e.skipped)
    print(f"scan: {len(snapshot.files) - skipped} files, "
          f"{_human_size(stats.bytes)} in {stats.dirs} dirs "
          f"({stats.empty_dirs} empty) in {fmt_duration(time.monotonic() - t0)}",
          flush=True)
    if stats.files_excluded or stats.dirs_excluded or stats.links_skipped:
        parts = []
        if stats.files_excluded:
            parts.append(f"{stats.files_excluded} files by extension")
        if stats.dirs_excluded:
            parts.append(f"{stats.dirs_excluded} dirs by name")
        if stats.links_skipped:
            parts.append(f"{stats.links_skipped} junctions/symlinks")
        print("  excluded: " + ", ".join(parts))
    if skipped:
        print(f"  skipped: {skipped} locked/unreadable files "
              f"(details in warnings above)")
    return snapshot, scan_warnings


def _print_diff_stats(delta: diffing.DiffResult, snapshot: Snapshot) -> None:
    """One-line summary of what a diff run is about to archive."""
    fmap = snapshot.file_map()
    added_bytes = sum(fmap[fn].sz for fn in delta.added if fn in fmap)
    skipped = sum(1 for e in snapshot.files if e.skipped)
    print(f"diff: +{len(delta.added)} files ({_human_size(added_bytes)}), "
          f"-{len(delta.deleted_files)} deleted files, "
          f"-{len(delta.deleted_dirs)} deleted dirs, "
          f"+{len(delta.added_empty_dirs)} new empty dirs, "
          f"{skipped} skipped", flush=True)


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

_CONFIG_TEMPLATE = """\
# backuper job configuration (created by: backuper init)
#
# Workflow:
#   1. set 'source' below (the directory to back up)
#   2. backuper full <this directory>      -> starts the first epoch
#   3. backuper diff <this directory>      -> incremental run into the newest epoch
#   4. backuper verify <this directory> [--chain]   /  backuper list <this directory>

# Exactly ONE source directory (absolute path, required before the first full).
source: {source}

# File extensions excluded from the backup (case-insensitive, ".tmp" form).
exclude_extensions: [".tmp"]

# Directory names excluded anywhere in the source tree, or absolute Windows
# directory paths to exclude. Quote Windows paths with YAML single quotes so
# backslashes stay literal, e.g. 'C:\\Data\\Cache' or '\\\\server\\share\\cache'.
exclude_dirs: []

# File extensions probed for read-locks before archiving; locked files are
# recorded as "skipped" and retried by the next diff.
lock_check_extensions: []

# RAR compression level, 0 (store) .. 5 (best). Default: 3.
compression: 3
"""


def cmd_init(job_dir: Path, source: str | None, *, generate_keys: bool = False) -> int:
    """Create a job directory with a config.yaml template (no RAR involved).

    With ``--generate-keys`` the keygen flow runs right after the template
    is written (the same shared function as ``backuper keygen``), so the
    directory starts fully encryption-enabled.
    """
    job_dir = _abs_dir(job_dir)
    # Validate the source BEFORE anything is written: a failed init must
    # leave no directory and no config behind.
    if source is not None and not Path(source).is_dir():
        raise PreflightError(f"source directory {source} does not exist")
    if job_dir.exists() and not job_dir.is_dir():
        raise PreflightError(f"job directory path is a file: {job_dir}")
    try:
        os.makedirs(job_dir, exist_ok=True)
    except OSError as exc:
        raise PreflightError(f"cannot create job directory {job_dir}: {exc}") from exc

    config_path = job_dir / CONFIG_NAME
    if config_path.exists():
        raise ConfigError(
            f"already initialized: {config_path} exists (not overwritten)")

    # Absolute path: load_config rejects relative sources, so a relative
    # --source would init fine and then brick the first full run.
    source_value = json.dumps(os.path.abspath(source)) if source is not None else '""'
    config_path.write_text(
        _CONFIG_TEMPLATE.format(source=source_value), encoding="utf-8", newline="\n")

    print(f"created {config_path}")
    if generate_keys:
        generate_job_keys(config_path, force=False)
    if source is None:
        print(f"next: edit 'source' in it, then run: backuper full {job_dir}")
    else:
        print(f"next: run: backuper full {job_dir}")
    return 0


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

_KEYGEN_WARNING = (
    "WARNING: encrypted archives are only restorable while "
    f"'{RECIPIENT_PRIVATE_NAME}' exists next to config.yaml. Keep a backed-up "
    "copy of BOTH private key files (recipient_private.pem, "
    "signing_private.pem) in a safe place OUTSIDE this job directory -- "
    "losing recipient_private.pem means losing access to every archive "
    "encrypted for this job."
)


def _fingerprint(pem: bytes) -> str:
    """Human-comparable fingerprint of a PUBLIC key PEM (its SHA-256 hex)."""
    digest = hashlib.sha256(pem).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _harden_private_key_acls(paths: tuple[Path, ...]) -> None:
    """Windows-only best-effort hardening of private key files.

    For each path runs
    ``icacls <path> /inheritance:r /grant:r "<current user>":F``: ACL
    inheritance is disabled (otherwise anything Inbox-granted to wider
    groups would leak through) and the file is granted FULL control to
    the current user only. ONLY the file path is handed to icacls --
    private key material never appears in any command, output or log.
    Failures (icacls missing, nonzero exit, OSError) print one stderr
    warning naming the file and NEVER abort the keygen.
    """
    if os.name != "nt":
        return
    user = os.environ.get("USERNAME") or os.getlogin()
    for path in paths:
        try:
            proc = subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                capture_output=True, text=True, check=False)
        except OSError as exc:
            print(f"warning: could not restrict permissions on {path.name}: {exc}",
                  file=sys.stderr)
            continue
        if proc.returncode != 0:
            reason = (proc.stderr or proc.stdout or "").strip()
            if not reason:
                reason = f"icacls exit code {proc.returncode}"
            print(f"warning: could not restrict permissions on {path.name}: {reason}",
                  file=sys.stderr)


def generate_job_keys(config_path: Path, *, force: bool = False) -> tuple[str, str]:
    """The shared keygen flow of ``backuper keygen`` and ``init --generate-keys``.

    Generates BOTH keypairs, writes ``recipient_private.pem`` and
    ``signing_private.pem`` next to ``config.yaml`` (refusing to overwrite
    existing files unless ``force``) and rewrites the config adding the two
    public PEMs (also refuses to REPLACE different existing public keys
    without ``force``). Prints key ids + fingerprints to stdout and the
    lose-your-keys warning to stderr.

    On Windows the two private key files also get a best-effort restrictive
    ACL (see :func:`_harden_private_key_acls`): user-only access with ACL
    inheritance disabled; a hardening failure only warns on stderr.

    NEVER prints or logs private key material. Returns the two key ids.
    """
    config_path = Path(config_path)
    if not config_path.is_file():
        raise ConfigError(f"config file not found: {config_path}")

    # RSA-3072 generation dominates; Ed25519 is instant.
    recipient_priv, recipient_pub, recipient_id = crypto.generate_recipient_keypair()
    signing_priv, signing_pub, signing_id = crypto.generate_signing_keypair()

    priv_paths = (
        private_key_path(config_path, "recipient"),
        private_key_path(config_path, "signing"),
    )
    existing = [p for p in priv_paths if p.exists()]
    if existing and not force:
        raise ConfigError(
            "refusing to overwrite existing private key file(s): "
            + ", ".join(p.name for p in existing)
            + " (use --force)")

    rewrite_config_with_public_keys(
        config_path, recipient_pub, signing_pub, force=force)
    for path, pem in zip(priv_paths, (recipient_priv, signing_priv), strict=True):
        try:
            path.write_bytes(pem)
        except OSError as exc:
            raise PreflightError(f"cannot write private key file {path}: {exc}") from exc

    _harden_private_key_acls(priv_paths)

    print(f"recipient key: id {recipient_id}  fingerprint {_fingerprint(recipient_pub)}")
    print(f"signing   key: id {signing_id}  fingerprint {_fingerprint(signing_pub)}")
    print(f"private key files written next to {config_path.parent}: "
          f"{priv_paths[0].name}, {priv_paths[1].name}")
    print(_KEYGEN_WARNING, file=sys.stderr)
    return recipient_id, signing_id


def cmd_keygen(job_dir: Path, *, force: bool = False) -> int:
    """Generate both keypairs for a job dir and install them (config + files)."""
    job_dir = _abs_dir(job_dir)
    generate_job_keys(job_dir / CONFIG_NAME, force=force)
    print(f"next: run: backuper full {job_dir}")
    return 0


# ---------------------------------------------------------------------------
# password
# ---------------------------------------------------------------------------

def _find_job_dir_for_archive(archive_path: Path) -> Path:
    """The job dir holding the config for an archive: config.yaml at the
    archive's directory or any ancestor (archives live in an epoch dir one
    level below the job dir)."""
    probe = Path(os.path.abspath(archive_path)).parent
    while True:
        if (probe / CONFIG_NAME).is_file():
            return probe
        parent = probe.parent
        if parent == probe:
            raise ConfigError(
                f"could not find a config.yaml next to or above {archive_path} "
                f"(pass --keys-dir explicitly)")
        probe = parent


def extract_archive_password(
    archive_path: Path,
    keys_dir: Path | None = None,
    *,
    rar_path: str | None = None,
    recipient_private_key_path: str | None = None,
) -> bytes:
    """Unwrap the archive password of an encrypted archive.

    Reads the UNENCRYPTED ``.backup/manifest.json`` member (plus the
    detached ``.backup/manifest.json.sig``), verifies the manifest
    signature against the signing key pinned in the job config, unwraps
    the DEK with the recipient private key and returns the exact password
    bytes handed to RAR (``password_for_rar(dek)``: 64 lowercase hex
    characters). Errors raise :class:`BackuperError` subclasses; the
    password itself is never part of any message.

    ``keys_dir`` overrides where config.yaml + the private PEMs live;
    default: walk up from the archive's directory until a config.yaml is
    found. Private key files are only read here, never logged.
    """
    archive_path = Path(archive_path)

    # Manifest first: "archive is not encrypted" must be reported regardless
    # of what the job config / key files look like.
    runner, _ = _resolve_runner(rar_path)
    try:
        raw_manifest = read_service_member(runner, archive_path, ".backup/manifest.json")
    except RuntimeError as exc:
        raise RarError(f"cannot read .backup/manifest.json from {archive_path}: {exc}") from exc
    try:
        manifest = Manifest.from_json(json.loads(raw_manifest.decode("utf-8")))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ConfigError(f"manifest of {archive_path} is invalid: {exc}") from exc
    if manifest.encryption is None:
        raise ConfigError(
            f"{archive_path} is not encrypted (manifest carries no encryption envelope)")

    # Where config.yaml + the private PEMs live: explicit dir or walk-up.
    if keys_dir is not None:
        job_dir = Path(keys_dir)
        if not (job_dir / CONFIG_NAME).is_file():
            raise ConfigError(f"config file not found: {job_dir / CONFIG_NAME}")
    else:
        job_dir = _find_job_dir_for_archive(archive_path)

    cfg = load_config(job_dir / CONFIG_NAME)
    if cfg.recipient_public_pem is None or cfg.signing_public_pem is None:
        raise ConfigError(
            f"config file {job_dir / CONFIG_NAME} has no encryption keys configured")

    try:
        raw_sig = read_service_member(runner, archive_path, MANIFEST_SIGNATURE_MEMBER)
    except RuntimeError as exc:
        raise RarError(f"cannot read {MANIFEST_SIGNATURE_MEMBER} from {archive_path}: {exc}") from exc
    try:
        sig = crypto.Signature.from_json(json.loads(raw_sig.decode("utf-8")))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ConfigError(f"manifest signature of {archive_path} is invalid: {exc}") from exc
    try:
        crypto.verify_bytes(cfg.signing_public_pem.encode("utf-8"), raw_manifest, sig)
    except crypto.SignatureError as exc:
        raise VerificationError(f"manifest signature verification failed: {exc}") from exc

    wrapped_json = None
    for item in manifest.wrapped_keys or []:
        if item.get("recipient_key_id") == cfg.recipient_key_id:
            wrapped_json = item
            break
    if wrapped_json is None and manifest.wrapped_keys:
        wrapped_json = manifest.wrapped_keys[0]
    if wrapped_json is None:
        raise ConfigError(f"manifest of {archive_path} has no wrapped keys")
    try:
        wrapped = crypto.WrappedKey.from_json(wrapped_json)
    except crypto.CryptoError as exc:
        raise ConfigError(f"wrapped key of {archive_path} is invalid: {exc}") from exc

    if recipient_private_key_path is not None:
        priv_path = Path(recipient_private_key_path)
    elif keys_dir is None:
        raise ConfigError(
            f"recipient private key is required to decrypt the encrypted archive "
            f"{archive_path} (pass --recipient-private-key)")
    else:
        priv_path = private_key_path(job_dir / CONFIG_NAME, "recipient")
    try:
        priv_pem = priv_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read recipient private key {priv_path}: {exc}") from exc
    try:
        dek = crypto.unwrap_key(priv_pem, wrapped)
        password = crypto.password_for_rar(dek)
    except crypto.CryptoError as exc:
        raise ConfigError(f"cannot decrypt the archive password: {exc}") from exc
    return password


def cmd_password(
    archive: Path,
    *,
    rar_path: str | None = None,
    keys_dir: str | None = None,
    recipient_private_key_path: str | None = None,
) -> int:
    """Print the archive password (64 lowercase hex chars) to stdout.

    stdout carries EXACTLY the password and one newline; every diagnostic
    goes to stderr (via the CLI error translation).
    """
    archive_path = Path(archive)
    if not archive_path.is_file():
        raise PreflightError(f"archive not found: {archive_path}")
    resolved_keys_dir = Path(keys_dir) if keys_dir is not None else None
    password = extract_archive_password(
        archive_path, resolved_keys_dir, rar_path=rar_path,
        recipient_private_key_path=recipient_private_key_path)
    print(password.decode("ascii"))  # exactly one line, nothing else
    return 0


# ---------------------------------------------------------------------------
# full / diff encryption support
# ---------------------------------------------------------------------------

def _read_signing_private_pem(config_path: Path, expected_key_id: str | None,
                              signing_private_key_path: str | None = None) -> bytes:
    """Read the Ed25519 manifest-signing private key next to a job config.

    Called by :func:`cmd_full` / :func:`cmd_diff` only when archive
    encryption is enabled. Raises :class:`ConfigError` (exit 5) when the
    file is missing, unreadable, not an Ed25519 key, or does not match the
    signing public key ``expected_key_id`` configured alongside it -- a
    mismatch here would produce archives whose manifest signature the job
    config can never verify. The key material itself is NEVER part of any
    message or log; only its absence/type mismatch is reported.
    """
    if signing_private_key_path is not None:
        key_path = Path(signing_private_key_path)
    else:
        key_path = private_key_path(config_path, "signing")
    try:
        pem = key_path.read_bytes()
    except FileNotFoundError as exc:
        raise ConfigError(
            f"archive encryption is enabled but the signing private key file "
            f"is missing: {key_path} (restore it from your key backup)") from exc
    except OSError as exc:
        raise ConfigError(
            f"cannot read the signing private key file {key_path}: {exc}") from exc
    try:
        key = crypto.load_private_pem(pem)
    except crypto.CryptoError as exc:
        raise ConfigError(
            f"{key_path} is not a usable Ed25519 signing key ({exc})") from exc
    try:
        key_id = crypto.key_id_for_public(key.public_key())
    except crypto.CryptoError as exc:  # defensive: Ed25519 always exposes it
        raise ConfigError(
            f"{key_path} is not a usable Ed25519 signing key ({exc})") from exc
    if expected_key_id is not None and key_id != expected_key_id:
        raise ConfigError(
            f"{key_path} does not match the signing public key in "
            f"{config_path} (ids {key_id} != {expected_key_id})")
    return pem


# ---------------------------------------------------------------------------
# full
# ---------------------------------------------------------------------------

def cmd_full(job_dir: Path, rar_path: str | None, *, progress: bool = True,
             dry_run: bool = False,
             signing_private_key_path: str | None = None) -> int:
    """Start a new epoch: scan the configured source and store a full archive."""
    job_dir = _abs_dir(job_dir)
    runner, rar_v = _resolve_runner(rar_path)

    if not dry_run:  # a dry run must not leave a job dir behind
        try:
            job_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise PreflightError(
                f"cannot create job directory {job_dir}: {exc}") from exc
    cfg = load_config(job_dir / CONFIG_NAME)
    _print_config_encryption_status(cfg)
    _warn_private_keys_next_to_config(job_dir / CONFIG_NAME)
    _preflight_layout(job_dir, cfg.source, create_job_dir=False, need_job_config=True)

    warning = _mismatch_warning_for_full(runner, job_dir, cfg)
    if warning:
        print(warning, file=sys.stderr)

    if dry_run:
        snapshot, _warnings = _scan_phase(cfg.source, cfg)
        skipped = sum(1 for e in snapshot.files if e.skipped)
        print(f"dry run: would archive {len(snapshot.files) - skipped} files "
              f"into a new full archive; nothing was written")
        return 0

    ts, epoch_dir = _pick_full_epoch(job_dir)

    lock = JobLock(job_dir)
    lock.acquire()  # LockHeldError -> exit 4 (cli)
    try:
        _sweep_tmp_files(job_dir, epoch_dir)
        # re-check under the lock: the pre-lock pick above is advisory only
        ts, epoch_dir = _pick_full_epoch(job_dir)

        stage = "scan"
        warnings: list[str] = []
        try:
            started_utc = ns_to_iso(time.time_ns())
            snapshot, warnings = _scan_phase(cfg.source, cfg)

            stage = "manifest"
            skipped = sum(1 for e in snapshot.files if e.skipped)
            files_to_add = [e.fn for e in snapshot.files if not e.skipped]
            empty_dirs_to_add = leaves(snapshot.empty_dirs)
            manifest = Manifest(
                manifest_id=str(uuid.uuid4()),
                filename=f"{ts}_full.rar",
                archive_type="full",
                created_utc=started_utc,
                config_name=CONFIG_NAME,
                config_sha256=hashlib.sha256(cfg.raw_bytes).hexdigest(),
                script_version=__version__,
                rar_version=rar_v,
                sources=[str(cfg.source)],
                base_full=None,
                previous_manifest_id=None,
                previous_filename=None,
                excludes={
                    "extensions": list(cfg.exclude_extensions),
                    "dirs": list(cfg.exclude_dirs),
                },
                added_empty_dirs=[],
                counters={
                    "files": len(files_to_add),
                    "empty_dirs": len(empty_dirs_to_add),
                    "skipped": skipped,
                    "bytes": sum(e.sz for e in snapshot.files if not e.skipped),
                    "deleted_files": 0,
                    "deleted_dirs": 0,
                    "added_empty_dirs": 0,
                },
            )
            # Per-archive encryption: a fresh random DEK per archive, the
            # signing private key read from disk here (NEVER from the config,
            # never logged); both secret fields are None for a legacy job.
            dek: bytes | None = None
            signing_pem: bytes | None = None
            if cfg.encryption_enabled:
                signing_pem = _read_signing_private_pem(
                    cfg.path, cfg.signing_key_id, signing_private_key_path)
                dek = crypto.generate_archive_password()
            spec = CreateSpec(
                epoch_dir=epoch_dir,
                source=cfg.source,
                archive_type="full",
                name_ts=ts,
                manifest=manifest,
                snapshot=snapshot,
                config_bytes=cfg.raw_bytes,
                compression=cfg.compression,
                files_to_add=files_to_add,
                empty_dirs_to_add=empty_dirs_to_add,
                warnings=warnings,
                config=cfg,
                dek=dek,
                signing_private_pem=signing_pem,
            )

            stage = "archive creation"
            outcome = archiver.create_archive(runner, spec, progress=progress)
        except KeyboardInterrupt:
            _write_failed_log(job_dir, epoch_dir, ts, "full", stage,
                              "interrupted by user", warnings, cfg, None)
            return 2
        except (RarError, VerificationError) as exc:
            _write_failed_log(job_dir, epoch_dir, ts, "full", stage,
                              str(exc), warnings, cfg, exc)
            raise
        except OSError as exc:
            err = RarError(f"{stage} failed: {exc}")
            _write_failed_log(job_dir, epoch_dir, ts, "full", stage,
                              str(err), warnings, cfg, exc)
            raise err from exc
    finally:
        lock.release()

    counters = outcome.counters
    print(f"OK {outcome.archive.name} ({_human_size(outcome.archive.stat().st_size)}): "
          f"{counters.get('files', 0)} files, {counters.get('skipped', 0)} skipped, "
          f"{counters.get('empty_dirs', 0)} empty dirs, {fmt_duration(outcome.duration_s)}")
    return 0


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

def cmd_diff(
    job_dir: Path,
    epoch: str | None,
    rar_path: str | None,
    *,
    progress: bool = True,
    dry_run: bool = False,
    signing_private_key_path: str | None = None,
) -> int:
    """Append a diff archive to the tip of the chosen (or latest) epoch."""
    job_dir = _abs_dir(job_dir)
    runner, rar_v = _resolve_runner(rar_path)

    if not job_dir.is_dir():
        raise PreflightError(f"job directory not found: {job_dir}")
    job_cfg_path = job_dir / CONFIG_NAME
    _warn_private_keys_next_to_config(job_cfg_path)

    # job config is optional for a diff: the archive's embedded config rules
    job_cfg: Config | None = None
    if job_cfg_path.is_file():
        try:
            job_cfg = load_config(job_cfg_path)
        except ConfigError as exc:
            print(f"warning: job config is invalid, ignoring it ({exc}); "
                  f"the archive config is used", file=sys.stderr)

    epoch_dir = chain.resolve_epoch(job_dir, epoch)
    full = chain.epoch_full(epoch_dir)
    tip = chain.tip_archive(epoch_dir)
    # Trust gate: when the job config pins the encryption keys, the tip
    # manifest's signature must verify against the job config's own signing
    # key BEFORE anything is written -- a forged/substituted tip fails here.
    # Legacy (unencrypted) configs keep the lenient path unchanged.
    if job_cfg is not None and job_cfg.encryption_enabled:
        base = chain.check_base_archive(
            runner, tip,
            trusted_signing_pem=job_cfg.signing_public_pem.encode("utf-8"),
            require_signature=True)
    else:
        base = chain.check_base_archive(runner, tip)

    if job_cfg is not None:
        warning = chain.config_mismatch_warning(
            job_cfg, base.config_bytes,
            embedded_signing_key_id=getattr(base.manifest, "signing_key_id", None))
        if warning:
            print(warning, file=sys.stderr)

    try:
        operative = config_from_bytes(base.config_bytes)
    except ConfigError as exc:
        raise EpochError(f"embedded config of {tip.name} is invalid: {exc}") from exc
    # New format: signing key travels via the external file / job config,
    # not config.yaml. Recover it so encrypted diffs can still be signed.
    if operative.signing_public_pem is None:
        if job_cfg is not None and job_cfg.signing_public_pem is not None:
            operative.signing_public_pem = job_cfg.signing_public_pem
            if operative.signing_key_id is None:
                operative.signing_key_id = job_cfg.signing_key_id
        else:
            sp = signing_public_key_path(job_cfg_path)
            if sp.is_file():
                try:
                    operative.signing_public_pem = sp.read_text(encoding="utf-8").strip()
                except OSError:
                    pass
    if operative.signing_key_id is None and getattr(base.manifest, "signing_key_id", None) is not None:
        operative.signing_key_id = getattr(base.manifest, "signing_key_id", None)
    _print_config_encryption_status(operative)

    if not base.manifest.sources:
        raise EpochError(f"manifest of {tip.name} lists no sources")
    source = Path(base.manifest.sources[0])
    _preflight_layout(job_dir, source, create_job_dir=False, need_job_config=False)

    if dry_run:
        snapshot, _warnings = _scan_phase(source, operative)
        delta = diffing.compute_diff(base.snapshot, snapshot)
        if delta.is_no_op:
            print("dry run: no changes detected — no diff archive would be created")
        else:
            _print_diff_stats(delta, snapshot)
            print("dry run: no archive created")
        return 0

    lock = JobLock(job_dir)
    lock.acquire()
    try:
        _sweep_tmp_files(job_dir, epoch_dir)
        ts = _free_archive_ts(epoch_dir, "diff")

        stage = "scan"
        warnings: list[str] = []
        try:
            started_utc = ns_to_iso(time.time_ns())
            snapshot, warnings = _scan_phase(source, operative)

            stage = "diff"
            delta = diffing.compute_diff(base.snapshot, snapshot)
            if delta.is_no_op:
                _write_nothing_log(epoch_dir, ts, rar_v, source, tip, warnings)
                raise NoOpResult(
                    "no changes detected: no new/changed files, no new empty "
                    "dirs, no deletions")
            _print_diff_stats(delta, snapshot)

            stage = "manifest"
            skipped = sum(1 for e in snapshot.files if e.skipped)
            files_to_add = list(delta.added)
            empty_dirs_to_add = leaves(delta.added_empty_dirs)
            fmap = snapshot.file_map()
            manifest = Manifest(
                manifest_id=str(uuid.uuid4()),
                filename=f"{ts}_diff.rar",
                archive_type="diff",
                created_utc=started_utc,
                config_name=CONFIG_NAME,
                config_sha256=hashlib.sha256(base.config_bytes).hexdigest(),
                script_version=__version__,
                rar_version=rar_v,
                sources=[str(source)],
                base_full=full.name,
                previous_manifest_id=base.manifest.manifest_id,
                previous_filename=tip.name,
                excludes={
                    "extensions": list(operative.exclude_extensions),
                    "dirs": list(operative.exclude_dirs),
                },
                added_empty_dirs=list(delta.added_empty_dirs),
                counters={
                    "files": len(files_to_add),
                    "empty_dirs": len(empty_dirs_to_add),
                    "skipped": skipped,
                    "bytes": sum(fmap[fn].sz for fn in files_to_add),
                    "deleted_files": len(delta.deleted_files),
                    "deleted_dirs": len(delta.deleted_dirs),
                    "added_empty_dirs": len(delta.added_empty_dirs),
                },
            )
            # Same per-archive encryption as full, driven by the OPERATIVE
            # (embedded) config. The key files live next to the job config
            # dir (config.py's rule); when the job dir has no config.yaml
            # at all, an encryption-enabled operative cannot be signed and
            # the read helper reports exactly that.
            dek: bytes | None = None
            signing_pem: bytes | None = None
            if operative.encryption_enabled:
                signing_pem = _read_signing_private_pem(
                    job_cfg_path, operative.signing_key_id, signing_private_key_path)
                dek = crypto.generate_archive_password()
            spec = CreateSpec(
                epoch_dir=epoch_dir,
                source=source,
                archive_type="diff",
                name_ts=ts,
                manifest=manifest,
                snapshot=snapshot,
                config_bytes=base.config_bytes,
                compression=operative.compression,
                delete_files=list(delta.deleted_files),
                delete_dirs=list(delta.deleted_dirs),
                added_empty_dirs=list(delta.added_empty_dirs),
                files_to_add=files_to_add,
                empty_dirs_to_add=empty_dirs_to_add,
                warnings=warnings,
                config=operative,
                dek=dek,
                signing_private_pem=signing_pem,
            )

            stage = "archive creation"
            outcome = archiver.create_archive(runner, spec, progress=progress)
        except NoOpResult:
            raise
        except KeyboardInterrupt:
            _write_failed_log(job_dir, epoch_dir, ts, "diff", stage,
                              "interrupted by user", warnings, operative, None)
            return 2
        except (RarError, VerificationError) as exc:
            _write_failed_log(job_dir, epoch_dir, ts, "diff", stage,
                              str(exc), warnings, operative, exc)
            raise
        except OSError as exc:
            err = RarError(f"{stage} failed: {exc}")
            _write_failed_log(job_dir, epoch_dir, ts, "diff", stage,
                              str(err), warnings, operative, exc)
            raise err from exc
    finally:
        lock.release()

    counters = outcome.counters
    print(f"OK {outcome.archive.name} ({_human_size(outcome.archive.stat().st_size)}): "
          f"+{counters.get('files', 0)} files, "
          f"-{counters.get('deleted_files', 0)} files/"
          f"-{counters.get('deleted_dirs', 0)} dirs deleted, "
          f"{counters.get('added_empty_dirs', 0)} new empty dirs, "
          f"{counters.get('skipped', 0)} skipped, {fmt_duration(outcome.duration_s)}")
    return 0


def _write_nothing_log(
    epoch_dir: Path,
    ts: str,
    rar_v: str,
    source: Path,
    tip: Path,
    warnings: list[str],
) -> None:
    """``<ts>_diff_nothing.log``: a diff run happened but had nothing to store."""
    lines = [
        "backuper diff run: nothing to do",
        "================================",
        f"started (UTC)  : {ns_to_iso(time.time_ns())}",
        f"backuper       : {__version__}",
        f"rar version    : {rar_v}",
        f"source         : {source}",
        f"epoch          : {epoch_dir.name}",
        f"base archive   : {tip.name}",
        "",
        "no changes detected: no new/changed files, no new empty dirs, no deletions",
        "",
        "scan warnings:",
    ]
    if warnings:
        lines += [f"  {w}" for w in warnings]
    else:
        lines.append("  (none)")
    lines.append("")
    path = epoch_dir / f"{ts}_diff_nothing.log"
    try:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write("\n".join(lines))
    except OSError as exc:
        print(f"warning: could not write no-op log {path}: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def cmd_verify(
    job_dir: Path,
    epoch: str | None,
    *,
    chain_mode: bool,
    fix: bool,
    rar_path: str | None,
    recipient_private_key_path: str | None = None,
) -> int:
    """Verify the epoch tip (or the whole chain with linkage checks)."""
    job_dir = _abs_dir(job_dir)
    runner, _ = _resolve_runner(rar_path)
    if not job_dir.is_dir():
        raise PreflightError(f"job directory not found: {job_dir}")
    epoch_dir = chain.resolve_epoch(job_dir, epoch)

    # Encrypted-archive wiring (unencrypted jobs verify exactly as before):
    # the trusted signing PUBLIC key comes from the job config and the
    # recipient PRIVATE key is read from recipient_private.pem next to it
    # (its bytes go nowhere except into the in-process unlock call).
    trusted_signing_pem: bytes | None = None
    recipient_private_pem: bytes | None = None
    recipient_key_id: str | None = None
    config_path = job_dir / CONFIG_NAME
    _warn_private_keys_next_to_config(config_path)
    if config_path.is_file():
        try:
            cfg = load_config(config_path)
        except ConfigError as exc:
            print(f"warning: job config is unreadable ({exc}); encrypted "
                  f"archives cannot be unlocked without it", file=sys.stderr)
        else:
            if cfg.encryption_enabled and cfg.signing_public_pem is not None:
                trusted_signing_pem = cfg.signing_public_pem.encode("utf-8")
                recipient_key_id = cfg.recipient_key_id
                if recipient_private_key_path is not None:
                    priv_path = Path(recipient_private_key_path)
                else:
                    raise ConfigError(
                        f"config file {config_path} enables encrypted archives, "
                        f"but no recipient private key was provided "
                        f"(pass --recipient-private-key)")
                try:
                    recipient_private_pem = priv_path.read_bytes()
                except OSError as exc:
                    raise ConfigError(
                        f"config file {config_path} enables encrypted archives, "
                        f"but the recipient private key {priv_path} cannot be "
                        f"read: {exc}") from exc

    lock = JobLock(job_dir)
    lock.acquire()
    try:
        if chain_mode:
            reports = verify_chain(
                runner, epoch_dir, fix=fix,
                recipient_private_pem=recipient_private_pem,
                trusted_signing_pem=trusted_signing_pem,
                recipient_key_id=recipient_key_id)
        else:
            tip = chain.tip_archive(epoch_dir)
            reports = [verify_archive(
                runner, tip, fix=fix,
                recipient_private_pem=recipient_private_pem,
                trusted_signing_pem=trusted_signing_pem,
                recipient_key_id=recipient_key_id)]
    finally:
        lock.release()

    _print_manifest_encryption_status(reports)
    print_reports(reports)
    failed = sum(1 for r in reports if not r.ok)
    if failed:
        print(f"{failed} of {len(reports)} archive(s) failed verification",
              file=sys.stderr)
        return 3
    print(f"{len(reports)} archive(s) verified OK")
    return 0


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

def cmd_list(job_dir: Path, rar_path: str | None = None) -> int:
    """Print the epochs and their chains; never locks, Rar.exe is optional."""
    job_dir = _abs_dir(job_dir)
    if not job_dir.is_dir():
        raise PreflightError(f"job directory not found: {job_dir}")

    runner: RarRunner | None
    try:
        runner = RarRunner(find_rar(rar_path))
    except FileNotFoundError:
        runner = None

    epochs = chain.list_epochs(job_dir)
    if not epochs:
        print(f"no epochs found in {job_dir}")
        print("hint: run 'backuper init <dir>' to create a job dir with a "
              "config.yaml, then 'backuper full <dir>' to start a new epoch")
        return 0

    print(f"job: {job_dir}")
    for epoch_dir in epochs:
        archives = chain.epoch_archives(epoch_dir)
        try:
            full = chain.epoch_full(epoch_dir)
            full_note = f"full: {full.name}"
        except EpochError:
            full_note = "full: MISSING"
        print(f"{epoch_dir.name}  ({full_note})")
        if not archives:
            print("  (no archives)")
            continue

        prev_name: str | None = None
        prev_manifest: Manifest | None = None
        for archive in archives:
            try:
                size = _human_size(archive.stat().st_size)
            except OSError:
                size = "?"
            manifest: Manifest | None
            try:
                manifest = chain.load_manifest(runner, archive)
            except EpochError as exc:
                if runner is None:
                    print(f"  {archive.name}  {size}  UNREADABLE "
                          f"(manifest unreadable (rar not found))")
                else:
                    print(f"  {archive.name}  {size}  UNREADABLE ({exc})")
                prev_name, prev_manifest = archive.name, None
                continue

            counters = manifest.counters
            if manifest.archive_type == "full":
                marker = "first"
            elif (prev_manifest is not None
                    and manifest.previous_filename == prev_name
                    and manifest.previous_manifest_id == prev_manifest.manifest_id):
                marker = "\u2713 linked"          # ✓
            else:
                marker = "\u2717 broken"          # ✗
            created = manifest.created_utc[:19] + "Z"
            print(f"  {archive.name}  {manifest.archive_type:<5} {size:>10}  "
                  f"created {created}  "
                  f"files={counters.get('files', 0)} skipped={counters.get('skipped', 0)} "
                  f"empty_dirs={counters.get('empty_dirs', 0)} "
                  f"deleted_files={counters.get('deleted_files', 0)} "
                  f"deleted_dirs={counters.get('deleted_dirs', 0)}  {marker}")
            prev_name, prev_manifest = archive.name, manifest
    return 0
