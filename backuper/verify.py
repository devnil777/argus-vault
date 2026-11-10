"""Archive and chain verification, including the recovery-record repair flow.

Order of checks per archive (:func:`verify_archive`):

1. the archive file exists,
2. the ``.sha256`` sidecar (missing -> note; mismatch -> deferred decision),
3. ``rar t`` integrity test (0 ok / 3 damaged -> optional repair flow /
   other nonzero -> problem),
4. structural: manifest + files.json parse, every service member is
   readable, and the archive listing matches the expectations (reusing
   :func:`backuper.archiver.cross_check_entries`),
5. self-heal: a missing sidecar is regenerated after successful
   verification.

For ENCRYPTED archives (``manifest.encryption == ENCRYPTION_DATA``) two
gates run before any slow or RAR-level step (no partial results): first
the detached manifest signature is verified against the config-pinned
trusted signing public key, then the DEK is unwrapped with the recipient
private key to derive the RAR password -- which is carried only through
the bare ``-p`` + stdin forms of ``rar t``/``rar r``. All ``.backup/``
service-member reads stay passwordless (they are stored unencrypted) and
the trusted signing key comes from the external file:
verification pins the key from the job config.

The repair flow (:func:`repair_flow`) only REPLACES the archive after the
repaired copy passes the integrity test, parses and cross-checks -- per
spec "замена только после успешной сверки".

Diff archives store only the delta, so their user-file expectations are
not derivable from the archive alone. :func:`verify_archive` therefore
checks diffs non-exactly (service members + folders + counters), while
:func:`verify_chain` derives the exact expected file list from the
previous archive's snapshot (``compute_diff``) and passes it in.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from backuper import chain, crypto, diffing, rar_runner
from backuper.archiver import (
    SERVICE_MEMBERS_DIFF,
    SERVICE_MEMBERS_FULL,
    cross_check_entries,
    hash_file_with_progress,
    read_sidecar_hash,
    split_entries,
    write_sidecar_with_progress,
)
from backuper.errors import EpochError, VerificationError
from backuper.models import (
    ENCRYPTION_DATA,
    MANIFEST_SIGNATURE_MEMBER,
    Manifest,
    Snapshot,
)
from backuper.progress import PercentProgress, fmt_duration
from backuper.rar_runner import RarRunner, read_service_member, winapi_path
from backuper.scanner import leaves

# The manifest member whose detached signature is checked for encrypted
# manifests (same string as chain._MANIFEST_MEMBER; service members are
# OPEN and are always read WITHOUT a password).
_MANIFEST_MEMBER = ".backup/manifest.json"


@dataclass
class VerifyReport:
    """Outcome of verifying one archive."""

    archive: Path
    ok: bool
    repaired: bool = False
    notes: list[str] = field(default_factory=list)     # informational
    problems: list[str] = field(default_factory=list)  # reasons for failure
    # Loaded metadata (None when unreadable); used by verify_chain for the
    # linkage and diff-expectation checks without re-reading the archive.
    manifest: Manifest | None = None
    snapshot: Snapshot | None = None


# ---------------------------------------------------------------------------
# Encrypted-archive unlock (signature verification + DEK unwrap)
# ---------------------------------------------------------------------------

class ArchiveUnlockError(VerificationError):
    """An encrypted archive's password could not be derived from its manifest.

    Raised by :func:`resolve_archive_password` when the manifest carries
    no usable wrapped key or the DEK cannot be unwrapped with the provided
    recipient private key (CLI exit code 3, verification failure).
    """


def verify_manifest_signature(
    manifest_bytes: bytes, sig_bytes: bytes, trusted_signing_pem: bytes,
) -> None:
    """Verify the detached manifest signature over exact member bytes.

    ``sig_bytes`` is the raw ``.backup/manifest.json.sig`` member content
    (a :class:`backuper.crypto.Signature` JSON serialized by the create
    flow); the signature covers EXACT ``manifest_bytes`` -- the
    ``.backup/manifest.json`` member bytes. ``trusted_signing_pem`` is the
    Ed25519 public PEM pinned by the external signing_public.pem file.

    Raises :class:`backuper.crypto.SignatureError` for every failure
    (malformed member, unsupported shape, foreign signing key, tampered
    manifest); messages carry key ids only, never key material.
    """
    try:
        sig_raw = sig_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise crypto.SignatureError(
            "manifest signature member is not valid UTF-8") from exc
    try:
        sig = crypto.Signature.from_json(sig_raw)
    except crypto.CryptoError as exc:
        raise crypto.SignatureError(f"manifest signature member is invalid: {exc}") from exc
    crypto.verify_bytes(trusted_signing_pem, manifest_bytes, sig)


def resolve_archive_password(
    manifest: Manifest,
    recipient_private_pem: bytes,
    recipient_key_id: str | None = None,
) -> bytes:
    """Unwrap the manifest's DEK and derive the RAR password (64-char hex).

    Prefers the wrapped key whose ``recipient_key_id`` equals
    ``recipient_key_id`` (the job config's id); falls back to the first
    wrapped key when there is no match (single-recipient archives made
    before the pinning field, or a key rotation with a kept legacy entry).

    Raises :class:`ArchiveUnlockError` when the manifest carries no
    wrapped keys, the wrapped-key data is malformed, or decryption with
    the provided private key fails (wrong/foreign key, corrupted
    payload). The underlying crypto errors never contain key material.
    """
    wrapped_entries = manifest.wrapped_keys or []
    if not wrapped_entries:
        raise ArchiveUnlockError("manifest has no wrapped_keys; the archive "
                                 "password cannot be derived")
    chosen = None
    if recipient_key_id is not None:
        chosen = next(
            (item for item in wrapped_entries
             if item.get("recipient_key_id") == recipient_key_id),
            None)
    if chosen is None:
        chosen = wrapped_entries[0]
    try:
        wrapped = crypto.WrappedKey.from_json(chosen)
    except crypto.CryptoError as exc:
        raise ArchiveUnlockError(f"wrapped key data is invalid: {exc}") from exc
    try:
        dek = crypto.unwrap_key(recipient_private_pem, wrapped)
        return crypto.password_for_rar(dek)
    except crypto.CryptoError as exc:
        raise ArchiveUnlockError(
            "cannot unwrap the archive password with the provided recipient "
            f"private key: {exc}") from exc


# ---------------------------------------------------------------------------
# Per-archive verification
# ---------------------------------------------------------------------------

def _tail(text: str, lines: int = 10) -> str:
    """Last non-empty lines of a command output, for error messages."""
    parts = [ln for ln in text.splitlines() if ln.strip()]
    return " | ".join(parts[-lines:]) if parts else "(no output)"


def verify_archive(
    runner: RarRunner,
    archive: Path,
    *,
    fix: bool,
    accept_new_hash: bool = False,
    expected_files: dict[str, int] | None = None,
    recipient_private_pem: bytes | None = None,
    trusted_signing_pem: bytes | None = None,
    recipient_key_id: str | None = None,
) -> VerifyReport:
    """Verify one archive; ``fix=True`` enables repair/sidecar self-healing.

    ``expected_files`` (name -> expected unpacked size) overrides the
    user-file expectations for DIFF archives in chain mode; for full
    archives the expectation is always derived from the archive's own
    files.json. ``None`` verifies a diff non-exactly (service members +
    folders + counters only).

    Encrypted-archive kwargs (used only when the manifest carries
    ``encryption == ENCRYPTION_DATA``; legacy archives behave exactly as
    before and a stray ``.sig`` member on them is ignored):
    ``trusted_signing_pem`` -- the job config's Ed25519 PUBLIC signing
    PEM (its absence fails the archive outright: no trusted key, no
    verification); ``recipient_private_pem`` -- the RSA private PEM read
    from the operator's ``recipient_private.pem`` (absence fails too);
    ``recipient_key_id`` -- the job config's recipient key id, preferred
    when picking the manifest entry to unwrap. A bad signature or a
    failed unlock fails the whole archive BEFORE the sha256/listing/
    ``rar t`` steps -- no partial results.
    """
    report = VerifyReport(archive=Path(archive), ok=True)

    # 1. exists -----------------------------------------------------------
    if not report.archive.is_file():
        report.problems.append("archive file is missing")
        report.ok = False
        return report

    # 2. metadata (fast; also feeds the rar t indicator) ----------------------
    print(f"reading archive metadata ({report.archive.name}) ...", flush=True)
    try:
        manifest = chain.load_manifest(runner, report.archive)
        snapshot = chain.load_snapshot(runner, report.archive)
    except EpochError as exc:
        report.problems.append(f"manifest/files.json unreadable: {exc}")
        report.ok = False
        return report
    report.manifest = manifest
    report.snapshot = snapshot

    # 2b. encrypted-manifest gates: signature first, then the DEK password ---
    #     both BEFORE any slow RAR-level step; failures here fail the whole
    #     archive (no partial results). Service members stay OPEN: the
    #     reads below never carry a password.
    rar_password: bytes | None = None
    if manifest.encryption == ENCRYPTION_DATA:
        rar_password, unlock_problem = _unlock_encrypted_manifest(
            runner, report.archive, manifest,
            trusted_signing_pem=trusted_signing_pem,
            recipient_private_pem=recipient_private_pem,
            recipient_key_id=recipient_key_id)
        if unlock_problem is not None:
            report.problems.append(unlock_problem)
            report.ok = False
            return report

    # 3. sidecar ------------------------------------------------------------
    sidecar = Path(str(report.archive) + ".sha256")
    sidecar_missing = not sidecar.is_file()
    sha_mismatch = False
    actual_digest: str | None = None
    if sidecar_missing:
        report.notes.append("sha256 sidecar is missing (archive can still be valid)")
    else:
        expected_hash = read_sidecar_hash(report.archive)
        if expected_hash is None:
            report.notes.append("sha256 sidecar is malformed")
            sha_mismatch = True
            actual_digest = hash_file_with_progress(
                report.archive, "the sha256 check", label="sha256 check")
        else:
            actual = hash_file_with_progress(
                report.archive, "the sha256 check", label="sha256 check")
            if actual != expected_hash:
                sha_mismatch = True
                actual_digest = actual

    # 4. listing (once; feeds both the rar t indicator and the check) --------
    entries = _list_archive(runner, report.archive)
    if entries is None:      # problem already recorded; rar t may still run
        report.ok = False
        return report

    skip_structure = False
    # 5. rar t --------------------------------------------------------------
    total_files, cum_bytes, total_bytes = _test_totals(entries)
    print(f"testing {report.archive.name} ...", flush=True)
    tester = PercentProgress("rar t", total_files, cum_bytes=cum_bytes,
                             total_bytes=total_bytes)
    try:
        t_exit = rar_runner.test_archive(
            runner, report.archive, progress_callback=tester, password=rar_password)
    finally:
        tester.finish()
    if t_exit == 3:
        if not fix:
            report.problems.append(
                "archive is damaged (rar t exit 3) — recovery record may allow "
                "repair, rerun with --fix")
            report.ok = False
            return report
        ok, repaired, notes, problems = repair_flow(
            runner, report.archive, password=rar_password,
            trusted_signing_pem=trusted_signing_pem,
            require_signature=(manifest.encryption == ENCRYPTION_DATA),
            recipient_private_pem=recipient_private_pem,
            recipient_key_id=recipient_key_id,
            expected_files=expected_files)
        report.repaired = repaired
        report.notes.extend(notes)
        if not ok:
            report.problems.extend(problems)
            report.ok = False
            return report
        # successful repair rewrote archive + sidecar: re-read metadata,
        # listing and re-run structural checks on the replaced archive so
        # the report never reflects stale pre-repair data.
        post_ok = True
        post_problems: list[str] = []
        require_sig = (manifest.encryption == ENCRYPTION_DATA)
        new_manifest: Manifest | None = None
        new_snapshot: Snapshot | None = None
        try:
            new_manifest = chain.load_manifest(
                runner, report.archive,
                trusted_signing_pem=trusted_signing_pem,
                require_signature=require_sig)
            new_snapshot = chain.load_snapshot(runner, report.archive)
        except EpochError as exc:
            post_ok = False
            post_problems.append(
                f"repaired archive metadata unreadable: {exc}")
        if (post_ok and new_manifest is not None and new_snapshot is not None
                and new_manifest.encryption == ENCRYPTION_DATA):
            _, unlock_problem = _unlock_encrypted_manifest(
                runner, report.archive, new_manifest,
                trusted_signing_pem=trusted_signing_pem,
                recipient_private_pem=recipient_private_pem,
                recipient_key_id=recipient_key_id)
            if unlock_problem is not None:
                post_ok = False
                post_problems.append(unlock_problem)
        new_entries = None
        if post_ok:
            new_entries = _list_archive(runner, report.archive)
            if new_entries is None:
                post_ok = False
                post_problems.append("listing of the repaired archive failed")
        if post_ok and new_manifest is not None and new_snapshot is not None and new_entries is not None:
            if new_manifest.archive_type == "full":
                post_expectation: dict[str, int] | None = {
                    e.fn: e.sz for e in new_snapshot.files if not e.skipped}
            else:
                post_expectation = expected_files
            post_problems += _structural_check(
                runner, report.archive, new_manifest, new_snapshot,
                post_expectation, new_entries)
            if post_problems:
                post_ok = False
        if post_ok and new_manifest is not None and new_snapshot is not None and new_entries is not None:
            manifest = new_manifest
            snapshot = new_snapshot
            entries = new_entries
            report.manifest = manifest
            report.snapshot = snapshot
            sha_mismatch = False
            sidecar_missing = False
            skip_structure = True
        else:
            report.problems.extend(post_problems)
            report.problems.append(
                "repaired archive failed post-repair verification")
            report.notes.append(
                "repaired archive failed post-repair verification")
            report.ok = False
            return report
    elif t_exit != 0:
        output = ""
        try:
            res = runner.run(["t", str(report.archive)])
            output = _tail(res.stdout() + "\n" + res.stderr())
        except Exception as exc:  # noqa: BLE001 — reporting only
            output = f"(could not re-run rar t for details: {exc})"
        report.problems.append(f"rar t exited {t_exit}: {output}")
        report.ok = False
        return report
    elif sha_mismatch:
        report.problems.append(
            "sha256 mismatch: archive content differs from its sidecar")
        report.ok = False
        # the archive passed rar t, so also show the structural result

    # 6. structure ----------------------------------------------------------
    if not skip_structure:
        if manifest.archive_type == "full":
            expectation: dict[str, int] | None = {
                e.fn: e.sz for e in snapshot.files if not e.skipped}
        else:
            expectation = expected_files
        problems = _structural_check(
            runner, report.archive, manifest, snapshot, expectation, entries)
        if problems:
            report.problems.extend(problems)
            report.ok = False
            return report

    # 7. self-heal a missing sidecar ------------------------------------------
    if sidecar_missing:
        written, _ = write_sidecar_with_progress(report.archive)
        if not written:
            report.problems.append(
                "sha256 sidecar could not be written after successful "
                "verification")
            report.ok = False
            return report
        report.notes.append(
            "sha256 sidecar was missing and has been regenerated after "
            "successful verification")

    # 8. regenerate a mismatched sidecar only when explicitly accepted -------
    if sha_mismatch:
        if accept_new_hash:
            written, _ = write_sidecar_with_progress(
                report.archive, digest=actual_digest, backup_existing=True)
            if not written:
                report.problems.append(
                    "sha256 sidecar could not be regenerated after successful "
                    "verification")
                report.ok = False
                return report
            report.notes.append(
                "sha256 sidecar regenerated (archive passed structural checks; "
                "new hash accepted)")
            # resolve the deferred mismatch problem recorded earlier
            report.problems = [
                p for p in report.problems
                if "sha256 mismatch: archive content differs from its sidecar"
                not in p]
            report.ok = True
        else:
            if not any("sha256 mismatch" in p for p in report.problems):
                report.problems.append(
                    "sha256 mismatch: archive content differs from its sidecar")
            report.ok = False
            return report
    return report


def _unlock_encrypted_manifest(
    runner: RarRunner,
    archive: Path,
    manifest: Manifest,
    *,
    trusted_signing_pem: bytes | None,
    recipient_private_pem: bytes | None,
    recipient_key_id: str | None,
) -> tuple[bytes | None, str | None]:
    """Signature + DEK gates for one encrypted archive's manifest.

    Returns ``(password, problem)``: on success problem is None and
    password is the derived RAR password; on any failure password is None
    and problem is the (already provenance-of-failure descriptive) report
    text. The signature is checked FIRST (provenance before effort);
    missing/invalid key placeholders list exactly which pieces of access
    are missing. Raises nothing.
    """
    if trusted_signing_pem is None:
        return None, (
            "manifest is encrypted but no trusted signing key was provided "
            "(the external signing_public.pem); the archive origin "
            "cannot be verified")
    try:
        raw_manifest = read_service_member(runner, archive, _MANIFEST_MEMBER)
    except Exception as exc:  # noqa: BLE001 — any read failure is a problem
        return None, f"manifest member is unreadable: {exc}"
    try:
        sig_bytes = read_service_member(
            runner, archive, MANIFEST_SIGNATURE_MEMBER)
    except Exception as exc:  # noqa: BLE001
        return None, (
            f"encrypted manifest requires signature member "
            f"{MANIFEST_SIGNATURE_MEMBER}, which is missing or unreadable: {exc}")
    try:
        verify_manifest_signature(raw_manifest, sig_bytes, trusted_signing_pem)
    except crypto.SignatureError as exc:
        return None, f"manifest signature verification failed: {exc}"

    if recipient_private_pem is None:
        return None, (
            "manifest is encrypted but no recipient private key was provided "
            "(the job's recipient_private.pem); the archive password cannot "
            "be derived")
    try:
        return resolve_archive_password(
            manifest, recipient_private_pem, recipient_key_id), None
    except ArchiveUnlockError as exc:
        return None, str(exc)


def _list_archive(runner: RarRunner, archive: Path) -> list[dict] | None:
    """List ``archive`` once with timing prints; None + logged problem on failure.

    The entry dicts are shared by the ``rar t`` indicator (totals) and the
    structural cross-check, so the (slow on huge archives) listing runs once.
    """
    print(f"listing {archive.name} ...", flush=True)
    t_list = time.monotonic()
    try:
        entries = rar_runner.list_entries(runner, archive)
    except RuntimeError as exc:
        print(f"  listing failed: {exc}", flush=True)
        return None
    print(f"  listed {len(entries)} entries in {fmt_duration(time.monotonic() - t_list)}",
          flush=True)
    return entries


def _test_totals(entries: list[dict]) -> tuple[int, list[int] | None, int]:
    """Totals for the ``rar t`` indicator from a parsed listing.

    Returns ``(entry count, cumulative unpacked sizes in listing order,
    total bytes)``; ``(0, None, 0)`` when nothing is known, in which case
    the indicator degrades to a plain counter.
    """
    if not entries:
        return 0, None, 0
    cum: list[int] = [0]
    total = 0
    for entry in entries:
        size = 0
        if str(entry.get("Type", "")).strip().lower() == "file":
            try:
                size = int(entry.get("Size", 0))
            except (TypeError, ValueError):
                size = 0
        total += size
        cum.append(total)
    return len(entries), cum, total


def _structural_check(
    runner: RarRunner,
    archive: Path,
    manifest: Manifest,
    snapshot: Snapshot,
    expected_files: dict[str, int] | None,
    entries: list[dict],
) -> list[str]:
    """Service members + listing cross-check; ``expected_files=None`` skips
    the exact user-file check (diff archives without chain context).

    ``entries`` is the shared listing (see :func:`_list_archive`); no second
    listing happens here.
    """
    members = SERVICE_MEMBERS_FULL if manifest.archive_type == "full" else SERVICE_MEMBERS_DIFF
    # The detached manifest signature member belongs with the service
    # members of an ENCRYPTED manifest (checked exact-size + readable like
    # the rest); legacy members lists may already carry it.
    if manifest.encryption == ENCRYPTION_DATA and not any(
            m == MANIFEST_SIGNATURE_MEMBER for m in members):
        # SERVICE_MEMBERS_* is a shared constant; never mutate it.
        members = list(members) + [MANIFEST_SIGNATURE_MEMBER]
    svc_bytes: dict[str, bytes] = {}
    problems: list[str] = []
    for member in members:
        try:
            svc_bytes[member] = read_service_member(runner, archive, member)
        except Exception as exc:  # noqa: BLE001 — any read failure is a problem
            problems.append(f"service member {member} is unreadable: {exc}")
    if problems:
        return problems

    expected_config_sha = manifest.config_sha256
    actual_config_sha = hashlib.sha256(
        svc_bytes[".backup/config.yaml"]).hexdigest()
    if expected_config_sha != actual_config_sha:
        problems.append(
            f"manifest config_sha256={expected_config_sha} does not match "
            f"the embedded .backup/config.yaml (actual {actual_config_sha})")

    files, folders, split_problems = split_entries(entries)
    problems.extend(split_problems)

    if manifest.archive_type == "full":
        expected_folders = leaves(snapshot.empty_dirs)
    else:
        expected_folders = leaves(manifest.added_empty_dirs)

    problems += cross_check_entries(
        files, folders,
        expected_files or {},
        svc_bytes,
        expected_folders,
        exact_files=expected_files is not None,
    )

    # counters.files must describe exactly the stored user files
    stored_user_files = len(files) - sum(1 for m in members if m in files)
    claimed = manifest.counters.get("files")
    if isinstance(claimed, int) and claimed != stored_user_files:
        problems.append(
            f"manifest counters.files={claimed} but the archive stores "
            f"{stored_user_files} user files")
    return problems


# ---------------------------------------------------------------------------
# Repair flow
# ---------------------------------------------------------------------------

def _repair_leftovers(archive: Path, keep: Path | None = None) -> None:
    """Delete RAR repair artifacts we did not accept.

    ``rar r`` writes ``fixed.<name>`` (recovery-record path) or, when the
    damage is beyond the record, ``rebuilt.<name>`` (salvage by
    reconstruction). Both land next to the archive and both match the
    epoch's ``*.rar`` glob -- a leftover would corrupt the archive listing
    and even become the tip (``rebuilt...`` sorts after ``2026-...``), so
    they are removed eagerly on every repair path.
    """
    for name in (f"fixed.{archive.name}", f"fixed.{archive.name}.rar",
                 f"rebuilt.{archive.name}"):
        candidate = archive.parent / name
        if keep is not None and candidate == keep:
            continue
        try:
            if candidate.exists():
                candidate.unlink()
        except OSError:
            pass


def repair_flow(
    runner: RarRunner,
    archive: Path,
    *,
    password: bytes | None = None,
    trusted_signing_pem: bytes | None = None,
    require_signature: bool = False,
    recipient_private_pem: bytes | None = None,
    recipient_key_id: str | None = None,
    expected_files: dict[str, int] | None = None,
) -> tuple[bool, bool, list[str], list[str]]:
    """Repair ``archive`` via its recovery record.

    Returns ``(ok, repaired, notes, problems)``. The repaired copy is only
    substituted after it passes the integrity test, parses and cross-checks
    (svc members + folders; full archives also against their own snapshot);
    on any failure the fixed file is deleted and the original is left
    untouched.

    ``password`` (optional) travels via the bare ``-p`` + stdin forms to
    ``rar t``/``rar r`` run against an encrypted archive (the recovery -
    record repair itself does not need it, but the integrity test of the
    encrypted content does).
    """
    notes: list[str] = []
    problems: list[str] = []
    archive = Path(archive)

    # free space for the fixed copy next to the archive
    try:
        size = archive.stat().st_size
        free = shutil.disk_usage(archive.parent).free
    except OSError as exc:
        return False, False, notes, [f"cannot assess free space for the repair: {exc}"]
    if free < size + size // 10:  # size * 1.1, integer math
        return False, False, notes, [
            "not enough free space next to the archive for the repaired copy"]

    print(f"repairing {archive.name} via the recovery record ...", flush=True)
    try:
        fixed = rar_runner.repair(runner, archive, password=password)
    except RuntimeError as exc:
        _repair_leftovers(archive)
        return False, False, notes, [f"repair failed: {exc}"]

    ok = True
    # one listing of the fixed copy: feeds both the test indicator and the
    # structural cross-check below
    fixed_entries = _list_archive(runner, fixed)
    if fixed_entries is None:
        problems.append("listing of the repaired copy failed")
        ok = False
    total_files, cum_bytes, total_bytes = _test_totals(fixed_entries or [])
    print(f"testing repaired copy {fixed.name} ...", flush=True)
    tester = PercentProgress("rar t (repaired)", total_files,
                             cum_bytes=cum_bytes, total_bytes=total_bytes)
    try:
        fixed_exit = rar_runner.test_archive(
            runner, fixed, progress_callback=tester, password=password)
    finally:
        tester.finish()
    if fixed_exit != 0:
        problems.append(f"repaired copy {fixed.name} failed the integrity test")
        ok = False
    manifest: Manifest | None = None
    snapshot: Snapshot | None = None
    try:
        manifest = chain.load_manifest(
            runner, fixed,
            trusted_signing_pem=trusted_signing_pem,
            require_signature=require_signature)
        snapshot = chain.load_snapshot(runner, fixed)
    except EpochError as exc:
        problems.append(f"repaired copy metadata unreadable: {exc}")
        ok = False
    if ok and fixed_entries is not None and manifest is not None and snapshot is not None:
        # Encrypted manifests: verify signature (already done by
        # load_manifest above) and unlock the DEK on the repaired copy
        # before any structural check.
        if manifest.encryption == ENCRYPTION_DATA:
            _, unlock_problem = _unlock_encrypted_manifest(
                runner, fixed, manifest,
                trusted_signing_pem=trusted_signing_pem,
                recipient_private_pem=recipient_private_pem,
                recipient_key_id=recipient_key_id)
            if unlock_problem is not None:
                problems.append(unlock_problem)
                ok = False
        if ok:
            expectation = None
            if manifest.archive_type == "full":
                expectation = {e.fn: e.sz for e in snapshot.files if not e.skipped}
            elif expected_files is not None:
                expectation = expected_files
            problems += _structural_check(
                runner, fixed, manifest, snapshot, expectation, fixed_entries)
            if problems:
                ok = False

    if not ok:
        try:
            fixed.unlink()
        except OSError:
            pass
        _repair_leftovers(archive)
        return False, False, notes, problems

    os.replace(winapi_path(fixed), winapi_path(archive))
    _repair_leftovers(archive)  # e.g. a rebuilt.<name> from an earlier salvage
    written, _ = write_sidecar_with_progress(archive, backup_existing=True)
    if written:
        notes.append("repaired via recovery record; sidecar updated")
    else:
        notes.append("repaired via recovery record; sidecar write failed")
    return True, True, notes, problems


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

def verify_chain(
    runner: RarRunner,
    epoch_dir: Path,
    *,
    fix: bool,
    accept_new_hash: bool = False,
    recipient_private_pem: bytes | None = None,
    trusted_signing_pem: bytes | None = None,
    recipient_key_id: str | None = None,
) -> list[VerifyReport]:
    """Verify every archive of the epoch (full first, then diffs by name)
    and check the chain linkage of each diff onto its previous archive.

    The two encrypted-archive kwargs (see :func:`verify_archive`) are
    threaded through to every per-archive verification; metadata
    pre-loading stays lenient (a manifest that fails the signature check
    is reported by its own archive's verification, not by the
    pre-loading pass). When the chain's archives are encrypted but the
    caller provided no keys, the affected archives fail with problem
    texts naming exactly which pieces of access are missing.
    """
    archives = chain.epoch_archives(epoch_dir)
    if not archives:
        raise EpochError(f"epoch {Path(epoch_dir).name} contains no archives")

    print(f"preparing chain verification ({len(archives)} archives) ...", flush=True)
    t_meta = time.monotonic()
    # Pre-load manifests/snapshots to derive the exact per-diff expectations
    # (what the diff SHOULD contain = compute_diff of the two embedded
    # snapshots) and to have the previous archive's data for the linkage.
    manifests: dict[str, Manifest] = {}
    snapshots: dict[str, Snapshot] = {}
    for archive in archives:
        try:
            manifests[archive.name] = chain.load_manifest(runner, archive)
        except EpochError:
            continue
        try:
            snapshots[archive.name] = chain.load_snapshot(runner, archive)
        except EpochError:
            pass
    print(f"  metadata loaded in {fmt_duration(time.monotonic() - t_meta)}", flush=True)

    expectations: dict[str, dict[str, int]] = {}
    for archive in archives:
        manifest = manifests.get(archive.name)
        if manifest is None or manifest.archive_type != "diff":
            continue
        prev_name = manifest.previous_filename or ""
        prev_manifest = manifests.get(prev_name)
        prev_snapshot = snapshots.get(prev_name)
        snapshot = snapshots.get(archive.name)
        if (prev_manifest is None or prev_snapshot is None or snapshot is None
                or manifest.previous_manifest_id != prev_manifest.manifest_id):
            continue  # linkage problems are reported separately
        added = diffing.compute_diff(prev_snapshot, snapshot).added
        fmap = snapshot.file_map()
        expectations[archive.name] = {
            fn: fmap[fn].sz for fn in added if fn in fmap}

    try:
        full_name = chain.epoch_full(epoch_dir).name
    except EpochError as exc:
        full_name = None
        full_problem = str(exc)
    else:
        full_problem = ""

    reports: list[VerifyReport] = []
    for archive in archives:
        report = verify_archive(
            runner, archive, fix=fix, accept_new_hash=accept_new_hash,
            expected_files=expectations.get(archive.name),
            recipient_private_pem=recipient_private_pem,
            trusted_signing_pem=trusted_signing_pem,
            recipient_key_id=recipient_key_id)
        manifest = report.manifest
        if manifest is not None and manifest.archive_type == "diff":
            if full_name is None:
                report.problems.append(f"epoch has no resolvable full archive: {full_problem}")
            elif manifest.base_full != full_name:
                report.problems.append(
                    f"manifest.base_full={manifest.base_full!r} does not match "
                    f"the epoch full archive {full_name!r}")
            prev_name = manifest.previous_filename
            prev = next((r for r in reports if r.archive.name == prev_name), None)
            if prev_name is None:
                report.problems.append("diff manifest has no previous_filename")
            elif prev is None or prev.manifest is None:
                report.problems.append(
                    f"previous archive {prev_name!r} is missing or unreadable")
            else:
                if manifest.previous_filename != prev.manifest.filename:
                    report.problems.append(
                        f"manifest.previous_filename={manifest.previous_filename!r} "
                        f"does not match the actual previous archive name "
                        f"{prev.manifest.filename!r}")
                if manifest.previous_manifest_id != prev.manifest.manifest_id:
                    report.problems.append(
                        f"manifest.previous_manifest_id={manifest.previous_manifest_id!r} "
                        f"does not match {prev.manifest.filename!r} id "
                        f"{prev.manifest.manifest_id!r}")
        report.ok = not report.problems
        reports.append(report)
    return reports


def _print_report(report: VerifyReport) -> None:
    """Human-readable one-archive output used by cmd_verify."""
    status = "OK" if report.ok else "FAILED"
    print(f"{status} {report.archive.name}")
    stream = sys.stdout
    for note in report.notes:
        print(f"note: {note}", file=stream)
    if not report.ok:
        stream = sys.stderr
    for problem in report.problems:
        print(f"error: {problem}", file=stream)


def print_reports(reports: list[VerifyReport]) -> None:
    """Print a list of verify reports (public helper for the runner)."""
    for report in reports:
        _print_report(report)
