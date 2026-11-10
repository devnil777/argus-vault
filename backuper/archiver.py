"""Archive creation: staging of the .backup/ service data, the two-step
``rar a`` run into a ``.tmp`` target, the post-archive cross-check and the
success log / sha256 sidecar bookkeeping.

Flow of :func:`create_archive` (every failure mode per task.md):

1. stage the service members in a fresh %TEMP% dir (the runner's startup
   sweep has already removed leftovers such as RAR's ``__rar_*.rartemp``
   from the epoch dir — a killed run can leave one behind),
2. ``rar a`` step 1 adds them into ``<target>.rar.tmp`` (from the staging
   dir), step 2 adds the user files (cwd = source root) and finishes the
   archive with ``-qo+ -rr5``; both steps pass ``-w<epoch dir>`` so RAR's
   archive-modification temp stays in the epoch dir, never on the source,
3. cross-check the tmp against the snapshot BEFORE renaming (path + size
   for every file, exact size for service members, strict folder check --
   this is what catches RAR's silent ``dir\\`` form loss; the listing call
   carries the archive password when the archive is encrypted),
4. only on success: rename to ``<target>.rar``, write the ``.sha256``
   sidecar (failure to write it is a warning, the archive stays valid)
   and the ``<archive>.log`` success log.

Encryption (``CreateSpec.dek`` set): the readable ``.backup/`` metadata
stays OPEN (step 1 is never password-protected); the user-file content
step runs with the RAR password derived from the DEK; the manifest gains
the ``encryption``/``wrapped_keys``/``signing_key_id`` envelope
envelope and is signed over its EXACT staged bytes, with the detached
``.backup/manifest.json.sig`` member staged alongside it. The password
never travels in argv (bare ``-p`` + stdin) and never appears in logs
(``rar_runner.redact`` scrubs anything that echoes a cmd list).

The tmp file is deleted on any failure/KeyboardInterrupt, so a failed run
never leaves a half-written archive behind.
"""

from __future__ import annotations

import hashlib
import itertools
import os
import re
import shutil
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from backuper import crypto, rar_runner
from backuper.config import Config
from backuper.errors import EpochError, RarError, VerificationError
from backuper.models import (
    ENCRYPTION_DATA,
    MANIFEST_SIGNATURE_MEMBER,
    Manifest,
    Snapshot,
    json_bytes,
    json_bytes_compact,
)
from backuper.progress import ArchiveProgress, ByteProgress, fmt_duration
from backuper.rar_runner import RarResult, RarRunner, winapi_path
from backuper.scanner import leaves

# Service members stored inside every archive (forward-slash spelling).


def space_problem(*, free: int, needed: int) -> str | None:
    """Low-disk-space warning text, or None when space looks sufficient.

    ``needed`` is the uncompressed size of what is about to be archived; the
    archive is created directly in the job's epoch dir (no cross-volume move
    ever happens), so this is purely an upper-bound advisory: +5% for the
    recovery record. Compression may still fit when the bound does not.
    """
    if needed <= 0:
        return None
    bound = int(needed * 1.05) + 1_000_000  # rr5 overhead + sidecars margin
    if free >= bound:
        return None
    return (f"job disk may run out of space: up to ~{_fmt_bytes(bound)} needed "
            f"(uncompressed estimate +5% recovery record), only {_fmt_bytes(free)} free")


def _fmt_bytes(num: int) -> str:
    size = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0 or unit == "TiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TiB"  # unreachable


SERVICE_MEMBERS_FULL = [
    ".backup/manifest.json",
    ".backup/files.json",
    ".backup/config.yaml",
]
SERVICE_MEMBERS_DIFF = SERVICE_MEMBERS_FULL + [
    ".backup/delete_files.txt",
    ".backup/delete_dirs.txt",
]

_SHA256_CHUNK = 1 << 20  # streaming hash chunk: 1 MiB


# ---------------------------------------------------------------------------
# Create spec / outcome
# ---------------------------------------------------------------------------

@dataclass
class CreateSpec:
    """Everything one archive creation needs; built by the runner layer."""

    epoch_dir: Path
    source: Path
    archive_type: str          # "full" | "diff"
    name_ts: str               # "2026-11-02_030000" (local time)
    manifest: Manifest         # fully built; filename must be f"{name_ts}_{type}.rar"
    snapshot: Snapshot         # CURRENT snapshot (embedded as files.json)
    config_bytes: bytes        # raw config.yaml bytes embedded verbatim
    compression: int           # RAR -m level (from the operative config)
    delete_files: list[str] = field(default_factory=list)   # diff only; ignored for full
    delete_dirs: list[str] = field(default_factory=list)    # diff only; ignored for full
    added_empty_dirs: list[str] = field(default_factory=list)  # diff only
    files_to_add: list[str] = field(default_factory=list)   # non-skipped fn list (forward slashes)
    empty_dirs_to_add: list[str] = field(default_factory=list)  # LEAF empty dirs to store
    warnings: list[str] = field(default_factory=list)       # scan warnings to record in the log
    # --- encryption envelope; dek + signing_private_pem are BOTH set or
    # BOTH None (None/None == the legacy unencrypted behaviour) --------------
    config: Config | None = None   # operative config; source of the PUBLIC keys in the envelope
    dek: bytes | None = field(default=None, repr=False)     # raw 32-byte per-archive DEK (secret)
    signing_private_pem: bytes | None = field(default=None, repr=False)  # Ed25519 PEM (secret)


@dataclass
class CreateOutcome:
    """Result of a successful :func:`create_archive`."""

    archive: Path
    sidecar_written: bool
    duration_s: float
    counters: dict
    notes: list[str]
    committed: bool = True


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def sha256_file(path: Path, *,
                progress: Callable[[int], None] | None = None) -> str:
    """Streaming sha256 hex digest of a file (1 MiB chunks, long-path safe).

    ``progress`` (optional) receives the running byte count after every
    non-empty chunk, so a caller can drive a live progress line.
    """
    digest = hashlib.sha256()
    done = 0
    with open(winapi_path(path), "rb") as fh:
        while True:
            chunk = fh.read(_SHA256_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            done += len(chunk)
            if progress is not None:
                progress(done)
    return digest.hexdigest()


def hash_file_with_progress(archive: Path, purpose: str, *,
                            label: str = "sha256") -> str:
    """sha256_file with a start line, live byte progress and a summary line."""
    try:
        size = archive.stat().st_size
    except OSError:
        size = 0
    print(f"hashing {archive.name} ({_fmt_bytes(size)}) for {purpose} ...", flush=True)
    bar = ByteProgress(label, size)
    try:
        return sha256_file(archive, progress=bar.report)
    finally:
        bar.finish()


def write_sidecar(archive: Path, *, digest: str | None = None,
                  backup_existing: bool = False) -> tuple[bool, str]:
    """Write ``<archive>.sha256`` (certutil/sha256sum format) + fsync.

    ``digest`` lets the caller reuse a hash it already computed (no re-read).
    ``backup_existing`` copies a pre-existing sidecar to
    ``<sidecar>.bak-<UTC timestamp>`` before replacing it.
    The write is atomic: data goes to ``<sidecar>.tmp``, is fsynced, then
    renamed over the sidecar via ``os.replace``. Returns ``(written, digest)``.
    A write failure is reported, never raised: per spec the archive stays
    valid without the sidecar.
    """
    if digest is None:
        digest = sha256_file(archive)
    sidecar = Path(str(archive) + ".sha256")
    tmp = Path(str(sidecar) + ".tmp")
    try:
        if backup_existing and os.path.lexists(winapi_path(sidecar)):
            timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            backup = Path(str(sidecar) + f".bak-{timestamp}")
            shutil.copyfile(winapi_path(sidecar), winapi_path(backup))
        with open(winapi_path(tmp), "w", encoding="utf-8", newline="") as fh:
            fh.write(f"{digest} *{archive.name}\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(winapi_path(tmp), winapi_path(sidecar))
    except OSError:
        try:
            if os.path.lexists(winapi_path(tmp)):
                os.remove(winapi_path(tmp))
        except OSError:
            pass
        return False, digest
    return True, digest


def write_sidecar_with_progress(archive: Path, *, digest: str | None = None,
                                backup_existing: bool = False) -> tuple[bool, str]:
    """Hash with console progress, then write <archive>.sha256 (no re-read)."""
    if digest is None:
        digest = hash_file_with_progress(archive, "the sha256 sidecar", label="sha256 sidecar")
    return write_sidecar(archive, digest=digest, backup_existing=backup_existing)


def read_sidecar_hash(archive: Path) -> str | None:
    """Parse the expected hash out of ``<archive>.sha256`` (None if absent/malformed)."""
    sidecar = Path(str(archive) + ".sha256")
    try:
        text = sidecar.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # "<64 hex> *<filename>" (binary marker) or "<64 hex>  <filename>" (text mode)
        head = line.split(maxsplit=1)[0].lower()
        if len(head) == 64 and re.fullmatch(r"[0-9a-f]{64}", head):
            return head
        return None
    return None


def _delete_list_bytes(paths: list[str]) -> bytes:
    """delete_files.txt / delete_dirs.txt payload: UTF-8 no BOM, LF, one
    forward-slash path per line; empty file for an empty list."""
    if not paths:
        return b""
    return ("\n".join(p.replace("\\", "/") for p in paths) + "\n").encode("utf-8")


def _rar_failure(stage: str, target: Path, res: RarResult,
                 password: bytes | None = None) -> RarError:
    """Build the RarError for a failed create step: exit code + last ~40 lines.

    ``password`` (the archive DEK password when the step was encrypted) is
    redacted out of the embedded output defensively, so the secret can
    never surface in an error message even if RAR output or arg handling
    changes later.
    """
    text = res.stdout() + "\n" + res.stderr()
    lines = [ln for ln in text.splitlines() if ln.strip()]
    tail = "\n".join(rar_runner.redact(lines[-40:], password))
    return RarError(
        f"rar add ({stage}) failed for {target.name}: exit {res.exit_code} "
        f"({res.exit_description})\noutput tail:\n{tail}")


# ---------------------------------------------------------------------------
# Archive listing cross-check
# ---------------------------------------------------------------------------

def split_entries(entries: list[dict]) -> tuple[dict[str, int], set[str], list[str]]:
    """Split ``rar lt`` entries into files/folders plus duplicate problems.

    Returns ``(files, folders, problems)`` where ``files`` maps the stored
    name (forward slashes, no trailing separator) to its UNPACKED size and
    ``folders`` is the set of stored directory names. Non-file/folder
    entries (service records) are ignored. Duplicate names are a problem:
    they would make the archive content ambiguous.
    """
    files: dict[str, int] = {}
    folders: set[str] = set()
    problems: list[str] = []
    seen: dict[str, str] = {}
    for entry in entries:
        name = str(entry.get("Name", "")).replace("\\", "/").rstrip("/")
        if not name:
            continue
        etype = str(entry.get("Type", "")).strip().lower()
        if name in seen:
            problems.append(
                f"duplicate archive entry {name!r} (first seen as {seen[name]!r})")
            continue
        seen[name] = etype or "unknown"
        if etype == "file":
            try:
                files[name] = int(entry.get("Size", "-1"))
            except (TypeError, ValueError):
                problems.append(
                    f"archive entry {name!r} has a non-numeric size {entry.get('Size')!r}")
        elif etype in ("folder", "directory"):
            folders.add(name)
        # other types (service records) are not user-visible content
    return files, folders, problems


def cross_check_entries(
    files: dict[str, int],
    folders: set[str],
    expected_files: dict[str, int],
    svc_bytes: dict[str, bytes],
    expected_folders: list[str],
    *,
    exact_files: bool = True,
) -> list[str]:
    """Pure cross-check of a parsed archive listing against expectations.

    ``files``/``folders`` come from :func:`split_entries`;
    ``expected_files`` maps user-file names to their expected UNPACKED
    size; ``svc_bytes`` maps the expected service members to the exact
    bytes that were written (checked by name + size); ``expected_folders``
    are the folder names that MUST be stored (strict: catches the silent
    ``dir\\`` loss), while EXTRA folders are tolerated (RAR may store
    parent dirs).

    ``exact_files=False`` drops the missing/unexpected user-file checks for
    callers that cannot derive the expected list (single-archive verify of
    a diff); service members and folders are still checked strictly.

    Returns human-readable problems; empty means the archive matches.
    """
    problems: list[str] = []

    for member, data in svc_bytes.items():
        if member not in files:
            problems.append(f"service member {member} is missing from the archive")
        elif files[member] != len(data):
            problems.append(
                f"service member {member} size mismatch: archive has "
                f"{files[member]} B, expected {len(data)} B")

    if exact_files:
        for name, size in sorted(expected_files.items()):
            if name not in files:
                problems.append(f"file {name} is missing from the archive")
            elif files[name] != size:
                problems.append(
                    f"file {name} size mismatch: archive has {files[name]} B, "
                    f"snapshot says {size} B")
        svc_names = set(svc_bytes)
        unexpected = sorted(set(files) - set(expected_files) - svc_names)
        for name in unexpected:
            problems.append(f"unexpected file in the archive: {name}")

    for name in expected_folders:
        if name not in folders:
            problems.append(f"empty directory {name} is missing from the archive")

    return problems


def cross_check(
    runner: RarRunner,
    archive_path: Path,
    spec: CreateSpec,
    svc_bytes: dict[str, bytes],
) -> list[str]:
    """Cross-check a freshly created archive against its CreateSpec.

    Lists the archive and verifies: every non-skipped snapshot entry that
    was requested is stored with the expected size, every service member
    is stored with the exact staged size, the leaf empty dirs are stored
    as folders, and there are no stray files. Empty result = pass.
    """
    t_start = time.monotonic()
    print(f"listing {archive_path.name} ...", flush=True)
    # Encrypted archives: the data is password-protected but the HEADERS
    # stay open, so plain `rar lt` would list them fine without a password;
    # feeding the password anyway is harmless and required for
    # encrypted-header archives (see rar_runner.list_entries).
    password = (crypto.password_for_rar(spec.dek)
                if spec.dek is not None else None)
    try:
        t_list_start = time.monotonic()
        entries = rar_runner.list_entries(runner, archive_path, password=password)
    except RuntimeError as exc:
        return [f"archive listing failed: {exc}"]
    t_list = time.monotonic() - t_list_start

    files, folders, problems = split_entries(entries)

    fmap = spec.snapshot.file_map()
    expected_files: dict[str, int] = {}
    for fn in spec.files_to_add:
        entry = fmap.get(fn)
        if entry is None:
            problems.append(f"listfile entry {fn} is not present in the snapshot")
            continue
        expected_files[fn] = entry.sz

    members = SERVICE_MEMBERS_DIFF if spec.archive_type == "diff" else SERVICE_MEMBERS_FULL
    if spec.dek is not None:
        # encrypted archives stage the detached manifest signature too
        members = members + [MANIFEST_SIGNATURE_MEMBER]
    svc: dict[str, bytes] = {}
    for member in members:
        if member not in svc_bytes:
            problems.append(f"service member {member} was never staged")
        else:
            svc[member] = svc_bytes[member]

    if spec.archive_type == "diff":
        expected_folders = leaves(spec.added_empty_dirs)
    else:
        expected_folders = leaves(spec.snapshot.empty_dirs)

    problems += cross_check_entries(
        files, folders, expected_files, svc, expected_folders, exact_files=True)
    total = time.monotonic() - t_start
    print(f"  listed + verified {len(entries)} entries in {fmt_duration(total)} "
          f"(listing {fmt_duration(t_list)})", flush=True)
    return problems


# ---------------------------------------------------------------------------
# Archive creation
# ---------------------------------------------------------------------------

def create_archive(runner: RarRunner, spec: CreateSpec, *, progress: bool) -> CreateOutcome:
    """Create one archive of the epoch chain; raises on any failure.

    See the module docstring for the flow. On any RAR failure, failed
    cross-check or KeyboardInterrupt the ``.tmp`` target is removed and the
    original exception (RarError / VerificationError) propagates; the
    caller writes the ``<ts>_<type>_failed.log``.
    """
    started_monotonic = time.monotonic()
    started_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    expected_name = f"{spec.name_ts}_{spec.archive_type}.rar"
    if spec.manifest.filename != expected_name:
        raise ValueError(
            f"manifest.filename {spec.manifest.filename!r} does not match "
            f"the create spec ({expected_name!r})")
    if spec.archive_type not in ("full", "diff"):
        raise ValueError(f"invalid archive_type {spec.archive_type!r}")

    # Encryption invariant: either both secrets are set or none is.
    # Encrypted == readable metadata stays open, user data gets the RAR
    # password derived from the DEK, and the manifest is signed.
    dek = spec.dek
    encrypted = dek is not None
    if encrypted != (spec.signing_private_pem is not None):
        raise ValueError(
            "invalid CreateSpec: dek and signing_private_pem must be set "
            "together, or both None")
    password: bytes | None = None
    if encrypted:
        if (spec.config is None
                or not spec.config.recipient_public_pem
                or not spec.config.signing_public_pem):
            raise ValueError(
                "invalid CreateSpec: an encrypted archive requires the "
                "config's public encryption keys")
        password = crypto.password_for_rar(dek)   # 64-char hex ASCII, once

    os.makedirs(spec.epoch_dir, exist_ok=True)
    # Absolute: RAR receives the target as a literal path while running with
    # cwd=staging/source — a relative target would resolve against those cwds.
    target = Path(os.path.abspath(spec.epoch_dir / expected_name))
    tmp = Path(str(target) + ".tmp")  # RAR keeps this name as-is (no .rar appended)
    notes: list[str] = []
    step_results: list[RarResult] = []

    fmap = spec.snapshot.file_map()
    content_bytes = sum(fmap[fn].sz for fn in spec.files_to_add if fn in fmap)
    content_names = list(spec.files_to_add) + list(spec.empty_dirs_to_add)
    print(f"archiving {len(content_names)} entries ({_fmt_bytes(content_bytes)}) "
          f"into {target.name} ...", flush=True)

    problem = space_problem(
        free=shutil.disk_usage(spec.epoch_dir).free, needed=content_bytes)
    if problem:
        # Advisory only: compression may still fit, and a real out-of-space
        # surfaces as a rar write error -> failed run (policy handles it).
        print(f"warning: {problem}", file=sys.stderr, flush=True)

    # Hardening (stage 1.4): never silently overwrite an existing target.
    if os.path.lexists(winapi_path(target)):
        raise EpochError(f"target archive already exists: {target}")

    staging = Path(tempfile.mkdtemp(prefix="backuper_svc_"))
    try:
        # --- stage the service members ------------------------------------
        print(f"staging service data ({len(spec.snapshot.files)} entries) ...",
              flush=True)
        t_stage = time.monotonic()
        # The manifest bytes are FINAL before signing: the detached
        # signature covers EXACTLY these staged bytes (no re-serialization).
        manifest_json = json_bytes(spec.manifest.to_json())
        if encrypted:
            # Readable envelope in the OPEN manifest; the DEK itself only
            # travels wrapped (never the bare password, never the bytes).
            spec.manifest.encryption = ENCRYPTION_DATA
            wrapped = crypto.wrap_key(
                spec.config.recipient_public_pem.encode("ascii"), dek)
            spec.manifest.wrapped_keys = [wrapped.to_json()]
            spec.manifest.signing_key_id = spec.config.signing_key_id
            manifest_json = json_bytes(spec.manifest.to_json())
            sig = crypto.sign_bytes(spec.signing_private_pem, manifest_json)
        svc_bytes: dict[str, bytes] = {
            ".backup/manifest.json": manifest_json,
            # compact: the pretty encoder is pure Python and stalls for minutes
            # on 198k-entry snapshots; readers are format-agnostic (json.loads)
            ".backup/files.json": json_bytes_compact(spec.snapshot.to_json()),
            ".backup/config.yaml": spec.config_bytes,
        }
        members = list(SERVICE_MEMBERS_FULL)
        if spec.archive_type == "diff":
            members = list(SERVICE_MEMBERS_DIFF)
            svc_bytes[".backup/delete_files.txt"] = _delete_list_bytes(spec.delete_files)
            svc_bytes[".backup/delete_dirs.txt"] = _delete_list_bytes(spec.delete_dirs)
        # SERVICE_MEMBERS_* stay untouched (other code imports them); the
        # signature piggybacks as an extra staged service member.
        if encrypted:
            svc_bytes[MANIFEST_SIGNATURE_MEMBER] = json_bytes(sig.to_json())
            members.append(MANIFEST_SIGNATURE_MEMBER)
        backup_dir = staging / ".backup"
        backup_dir.mkdir()
        for member, data in svc_bytes.items():
            (staging / member).write_bytes(data)
        staged_elapsed = time.monotonic() - t_stage
        print(f"  staged {len(svc_bytes)} service members "
              f"({_fmt_bytes(sum(len(b) for b in svc_bytes.values()))}) "
              f"in {fmt_duration(staged_elapsed)}", flush=True)

        # --- pre-existing tmp: defensive cleanup ---------------------------
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass

        reporter = None
        if progress:
            file_sizes = [fmap[fn].sz if fn in fmap else 0 for fn in spec.files_to_add]
            cum_bytes = list(itertools.accumulate(
                file_sizes + [0] * len(spec.empty_dirs_to_add), initial=0))
            reporter = ArchiveProgress(len(content_names), cum_bytes=cum_bytes,
                                       total_bytes=cum_bytes[-1])
        try:
            # --- step 1: service members (final=True when nothing else follows,
            # so a deletes-only diff still gets its -qo+ quick-open and -rr5
            # recovery record — task.md: "при создании full/diff всегда -rr5").
            # NEVER password-protected: the metadata must stay readable.
            res1 = rar_runner.create_step(
                runner, tmp, staging, members,
                final=not content_names, compression=spec.compression)
            step_results.append(res1)
            if not res1.ok:
                raise _rar_failure("service step", tmp, res1, password=password)

            # --- step 2: user files + empty dirs, finishing the archive
            if content_names:
                t_content = time.monotonic()
                try:
                    res2 = rar_runner.create_step(
                        runner, tmp, spec.source, content_names,
                        final=True, compression=spec.compression,
                        progress_callback=reporter, password=password)
                finally:
                    if reporter is not None:
                        reporter.finish()
                content_elapsed = time.monotonic() - t_content
                step_results.append(res2)
                if not res2.ok:
                    raise _rar_failure("content step", tmp, res2, password=password)
                rate = ""
                if content_elapsed > 0:
                    rate = f" ({_fmt_bytes(int(content_bytes / content_elapsed))}/s)"
                print(f"  archived {len(content_names)} entries "
                      f"in {fmt_duration(content_elapsed)}{rate}", flush=True)

            # --- cross-check the tmp BEFORE renaming ------------------------
            print(f"verifying archive contents ({tmp.name}) ...", flush=True)
            problems = cross_check(runner, tmp, spec, svc_bytes)
            if problems:
                raise VerificationError(
                    "post-archive cross-check failed:\n"
                    + "\n".join(f"  - {p}" for p in problems))

            if os.path.lexists(winapi_path(target)):
                raise EpochError(f"target archive already exists: {target}")
            os.replace(tmp, target)
        except BaseException:
            # failure or interrupt: never leave a half-written archive behind
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            raise
    finally:
        shutil.rmtree(winapi_path(staging), ignore_errors=True)

    # --- committed boundary: the archive is valid from here on --------------
    committed = True

    # --- sidecar (best-effort: failure never invalidates the archive) ------
    sidecar_written = False
    digest: str | None = None
    try:
        sidecar_written, digest = write_sidecar_with_progress(target)
        if not sidecar_written:
            note = f"sha256 sidecar could not be written: {target.name}.sha256"
            notes.append(note)
            print(f"warning: {note}", file=sys.stderr)
    except (OSError, KeyboardInterrupt) as exc:
        note = f"post-commit: sidecar not written ({exc})"
        notes.append(note)
        print(f"warning: {note}", file=sys.stderr)

    duration_s = time.monotonic() - started_monotonic
    finished_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    try:
        _write_success_log(
            target=target,
            spec=spec,
            step_results=step_results,
            content_skipped=not content_names,
            started_utc=started_utc,
            finished_utc=finished_utc,
            duration_s=duration_s,
            digest=digest,
            notes=notes,
            password=password,
        )
    except (OSError, KeyboardInterrupt) as exc:
        note = f"post-commit: success log not written ({exc})"
        notes.append(note)
        print(f"warning: {note}", file=sys.stderr)

    return CreateOutcome(
        archive=target,
        sidecar_written=sidecar_written,
        duration_s=duration_s,
        counters=dict(spec.manifest.counters),
        notes=notes,
        committed=committed,
    )


# ---------------------------------------------------------------------------
# Success log
# ---------------------------------------------------------------------------

def _write_success_log(
    *,
    target: Path,
    spec: CreateSpec,
    step_results: list[RarResult],
    content_skipped: bool,
    started_utc: str,
    finished_utc: str,
    duration_s: float,
    digest: str | None,
    notes: list[str],
    password: bytes | None = None,
) -> None:
    """Write ``<archive>.log`` next to the archive (best effort).

    ``password`` (the archive DEK password when the create was encrypted)
    is redacted from every echoed RAR command line before it lands in the
    log, so the secret can never appear there even if the args change.
    """
    from backuper import __version__  # noqa: PLC0415 — avoid import cycles at module load

    manifest = spec.manifest
    counters = manifest.counters
    lines: list[str] = [
        "backuper archive creation log",
        "=============================",
        f"backuper version : {__version__}",
        f"rar version      : {manifest.rar_version}",
        f"started (UTC)    : {started_utc}",
        f"finished (UTC)   : {finished_utc}",
        f"duration         : {duration_s:.2f} s",
        "",
        f"source           : {spec.source}",
        f"epoch            : {spec.epoch_dir.name}",
        f"archive          : {target.name}",
        f"type             : {spec.archive_type}",
    ]
    if spec.archive_type == "diff":
        lines += [
            f"base_full        : {manifest.base_full}",
            f"previous archive : {manifest.previous_filename}",
            f"previous manifest: {manifest.previous_manifest_id}",
        ]
    if spec.dek is not None:
        lines.append("encryption       : data (per-archive DEK wrapped to the "
                     "recipient key; manifest signed)")
    lines += [
        "",
        "counters         : "
        + ", ".join(f"{k}={v}" for k, v in sorted(counters.items())),
        f"sha256           : {digest if digest is not None else '(not computed)'}",
    ]
    lines.append("")
    lines.append("rar commands:")
    if not step_results:
        lines.append("  (none recorded)")
    for res in step_results:
        lines.append("  " + " ".join(rar_runner.redact(res.cmd, password)))
    if content_skipped:
        lines.append("  (content step skipped: deletes-only diff)")
    lines.append("")
    lines.append("scan warnings:")
    if spec.warnings:
        lines += [f"  {w}" for w in spec.warnings]
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("notes:")
    if notes:
        lines += [f"  {n}" for n in notes]
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("result: OK")

    log_path = Path(str(target) + ".log")
    try:
        with open(log_path, "w", encoding="utf-8", newline="") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as exc:
        print(f"warning: could not write log {log_path.name}: {exc}", file=sys.stderr)
