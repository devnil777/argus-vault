"""Verification tests: intact, sidecar healing, real damage + repair, chain."""

import hashlib
import os
import re
import shutil
import time
import uuid

import conftest
import pytest
from conftest import member_text, run_cli, stored_files

from backuper import crypto, rar_runner
from backuper.archiver import sha256_file
from backuper.models import (
    ENCRYPTION_DATA,
    MANIFEST_SIGNATURE_MEMBER,
    FileEntry,
    Snapshot,
    json_bytes,
    json_bytes_compact,
)
from backuper.verify import verify_archive, verify_chain

pytestmark = pytest.mark.skipif(conftest.RAR_PATH is None, reason="Rar.exe not found")

# Real keypairs, generated once per module (RSA-3072 keygen is slowish).
_RECIPIENT = None   # (private_pem, public_pem, key_id)
_SIGNER = None


def _recipient():
    global _RECIPIENT
    if _RECIPIENT is None:
        _RECIPIENT = crypto.generate_recipient_keypair()
    return _RECIPIENT


def _signer():
    global _SIGNER
    if _SIGNER is None:
        _SIGNER = crypto.generate_signing_keypair()
    return _SIGNER


def _make_full_and_diff(job):
    """full with blob1, diff adding blob2 (both ~4 MiB so the diff archive
    has a recovery record big enough to absorb the 64 KiB test damage)."""
    job.make_source(**{"blob1.bin": os.urandom(4 * 1024 * 1024)})
    assert run_cli(["full", job.dir]) == 0
    full = job.full_archive()
    job.make_source(**{"blob2.bin": os.urandom(4 * 1024 * 1024)})
    assert run_cli(["diff", job.dir]) == 0
    diff = job.tip()
    assert diff != full
    return full, diff


def test_verify_intact_single_and_chain(job, capsys):
    _make_full_and_diff(job)
    assert run_cli(["verify", job.dir]) == 0
    out = capsys.readouterr().out
    assert "sha256 check:" in out
    assert "rar t:" in out
    assert "listed" in out
    assert "reading archive metadata" in out
    assert "listing " in out
    assert run_cli(["verify", job.dir, "--chain"]) == 0
    chain_out = capsys.readouterr().out
    assert "preparing chain verification (" in chain_out
    assert "metadata loaded in" in chain_out


def test_verify_regenerates_missing_sidecar(job, capsys):
    job.make_source(a="x")
    assert run_cli(["full", job.dir]) == 0
    full = job.full_archive()
    sidecar = full.with_name(full.name + ".sha256")
    sidecar.unlink()

    assert run_cli(["verify", job.dir]) == 0
    assert sidecar.is_file()
    out = capsys.readouterr().out
    assert "regenerated" in out
    m = re.fullmatch(rf"([0-9a-f]{{64}}) \*{re.escape(full.name)}\n",
                     sidecar.read_text(encoding="utf-8"))
    assert m and m.group(1) == sha256_file(full)


def test_verify_tampered_sidecar_fails_then_fix_regenerates(job, capsys):
    job.make_source(a="x")
    assert run_cli(["full", job.dir]) == 0
    full = job.full_archive()
    sidecar = full.with_name(full.name + ".sha256")

    # 1) mismatch + --fix: still fails, sidecar unchanged, no backup
    sidecar.write_text("0" * 64 + " *" + full.name + "\n", encoding="utf-8")
    assert run_cli(["verify", job.dir, "--fix"]) == 3
    captured = capsys.readouterr()
    assert "sha256 mismatch" in captured.err + captured.out
    assert sidecar.read_text(encoding="utf-8") == "0" * 64 + " *" + full.name + "\n"
    assert list(full.parent.glob(full.name + ".sha256.bak-*")) == []

    # 2) mismatch + --accept-new-hash: succeeds, sidecar updated, backup kept
    assert run_cli(["verify", job.dir, "--accept-new-hash"]) == 0
    m = re.fullmatch(r"([0-9a-f]{64}) \*" + re.escape(full.name) + r"\n",
                      sidecar.read_text(encoding="utf-8"))
    assert m and m.group(1) == sha256_file(full)
    baks = list(full.parent.glob(full.name + ".sha256.bak-*"))
    assert baks
    assert baks[0].read_text(encoding="utf-8").split()[0] == "0" * 64

    # 3) mismatch + --accept-new-hash + structural failure: fails, no regen
    for b in full.parent.glob(full.name + ".sha256.bak-*"):
        b.unlink()
    sidecar.write_text("0" * 64 + " *" + full.name + "\n", encoding="utf-8")
    import subprocess
    subprocess.run([str(conftest.RAR_PATH), "d", "-inul", str(full), "a"],
                   check=True)
    assert run_cli(["verify", job.dir, "--accept-new-hash"]) == 3
    captured = capsys.readouterr()
    assert "sha256 mismatch" in captured.err + captured.out
    assert sidecar.read_text(encoding="utf-8") == "0" * 64 + " *" + full.name + "\n"
    assert list(full.parent.glob(full.name + ".sha256.bak-*")) == []

def test_verify_real_damage_fails_then_fix_repairs(job, tmp_path, capsys):
    _full, diff = _make_full_and_diff(job)
    pristine = tmp_path / "pristine.rar"
    shutil.copy2(diff, pristine)

    # 64 KiB continuous damage at ~40% of the diff archive
    raw = bytearray(pristine.read_bytes())
    pos = int(len(raw) * 0.4)
    raw[pos:pos + 65536] = os.urandom(65536)
    diff.write_bytes(bytes(raw))

    try:
        assert run_cli(["verify", job.dir]) == 3
        assert "damaged" in capsys.readouterr().err

        assert run_cli(["verify", job.dir, "--fix"]) == 0
        assert run_cli(["verify", job.dir, "--chain"]) == 0

        # the repaired archive must not have left repair artifacts behind
        assert list(diff.parent.glob("fixed.*")) == []
        assert list(diff.parent.glob("rebuilt.*")) == []
    except BaseException:
        shutil.copy2(pristine, diff)   # leave the job consistent on failure
        raise


def test_chain_verify_reports_broken_link_when_full_missing(job, capsys):
    job.make_source(a="x")
    assert run_cli(["full", job.dir]) == 0
    job.make_source(b="y")
    assert run_cli(["diff", job.dir]) == 0

    job.full_archive().unlink()        # full gone, diff still there

    rc = run_cli(["verify", job.dir, "--chain"])
    assert rc == 3
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert "FAILED" in captured.out + captured.err


def test_verify_chain_checks_linkage_metadata(job):
    # A healthy chain must pass --chain verification with exact per-diff
    # expectations derived from the previous archive's snapshot.
    job.make_source(**{"a.txt": "1", "sub/old.txt": "o"})
    assert run_cli(["full", job.dir]) == 0
    (job.src / "a.txt").write_bytes(b"2")
    (job.src / "sub" / "old.txt").unlink()
    assert run_cli(["diff", job.dir]) == 0

    assert run_cli(["verify", job.dir, "--chain"]) == 0
    diff = job.tip()
    files, _ = stored_files(job, diff)
    assert "a.txt" in files and "sub/old.txt" not in files
    assert member_text(job, diff, ".backup/delete_files.txt").splitlines() == \
        ["sub/old.txt"]


# ---------------------------------------------------------------------------
# Encrypted archives: signature gate + DEK unlock + password-bearing rar t
# (real archives built from the production create_step primitives: step 1
# stores the OPEN service members, step 2 adds the encrypted user files)
# ---------------------------------------------------------------------------

_VALID_CONFIG = b"source: C:/nonexistent-source\n"

_ENCRYPTED_MANIFEST_KEYS = {
    "schema_version": 1,
    "created_utc": "2026-01-01T00:00:00Z",
    "config_name": "config.yaml",
    "script_version": "0.2.0",
    "rar_version": "7.22",
}


def _craft_encrypted_full(rar, tmp_path, *, target, dek, recipient, signer,
                          content=None, sign_bad=False, skip_sig=False,
                          tampers_manifest=False):
    """Create a real encrypted FULL archive via the two-step production flow.

    Step 1 stores the OPEN ``.backup/`` members (manifest wrapping ``dek``
    for ``recipient`` + the detached signature by ``signer``), step 2 adds
    the user file encrypted with ``password_for_rar(dek)``. Returns the
    archive path (the password is derivable by the caller via
    ``crypto.password_for_rar(dek)``).
    """
    content = b"payload-" * 8 if content is None else content
    private_recipient_pem, public_pem, rid = recipient
    sign_priv, sign_pub, sign_rid = signer
    wrapped = crypto.wrap_key(public_pem, dek)
    manifest_data = {
        **_ENCRYPTED_MANIFEST_KEYS,
        "manifest_id": str(uuid.uuid4()),
        "filename": target.name,
        "archive_type": "full",
        "config_sha256": hashlib.sha256(_VALID_CONFIG).hexdigest(),
        "sources": ["C:/nonexistent-source"],
        "base_full": target.name,
        "previous_manifest_id": None,
        "previous_filename": None,
        "excludes": {"extensions": [], "dirs": []},
        "added_empty_dirs": [],
        "counters": {"files": 1, "empty_dirs": 0, "skipped": 0, "bytes": len(content),
                     "deleted_files": 0, "deleted_dirs": 0, "added_empty_dirs": 0},
        "encryption": ENCRYPTION_DATA,
        "wrapped_keys": [wrapped.to_json()],
        "signing_key_id": sign_rid,
    }
    raw_manifest = json_bytes(manifest_data)
    sig = crypto.sign_bytes(sign_priv, b"tampered bytes" if sign_bad else raw_manifest)
    if tampers_manifest:
        # Mutate a counter value so the manifest bytes no longer match the
        # signature (computed over the original bytes), while staying valid
        # JSON so signature verification is the failing step.
        assert b'"files": 1' in raw_manifest
        raw_manifest = raw_manifest.replace(b'"files": 1', b'"files": 2', 1)
    snapshot = Snapshot(
        files=[FileEntry(fn="data.bin", sz=len(content), mt_ns=time.time_ns())],
        empty_dirs=[])
    members = {
        ".backup/manifest.json": raw_manifest,
        ".backup/files.json": json_bytes_compact(snapshot.to_json()),
        ".backup/config.yaml": _VALID_CONFIG,
    }
    if not skip_sig:
        members[MANIFEST_SIGNATURE_MEMBER] = json_bytes(sig.to_json())

    staging = tmp_path / "stage_encrypted"
    src = tmp_path / "src_encrypted"
    src.mkdir(parents=True, exist_ok=True)
    (src / "data.bin").write_bytes(content)
    for rel, data in members.items():
        p = staging / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    svc_names = [rel.replace("/", "\\") for rel in members]
    res = rar_runner.create_step(rar, target, staging, svc_names,
                                 final=False, compression=0)
    assert res.ok, res.stdout() + res.stderr()
    password = crypto.password_for_rar(dek)
    res = rar_runner.create_step(
        rar, target, src, ["data.bin"], final=True, compression=0, password=password)
    assert res.ok, res.stdout() + res.stderr()
    return target


def test_verify_encrypted_archive_ok(rar, tmp_path):
    dek = crypto.generate_archive_password()
    target = tmp_path / "2026-01-01_000000_full.rar"
    _craft_encrypted_full(rar, tmp_path, target=target, dek=dek,
                          recipient=_recipient(), signer=_signer())
    # sanity: the sealed content is NOT testable with a wrong password
    assert rar_runner.test_archive(rar, target, password=b"0" * 64) == 11

    report = verify_archive(
        rar, target, fix=False,
        trusted_signing_pem=_signer()[1],
        recipient_private_pem=_recipient()[0],
        recipient_key_id=_recipient()[2])
    assert report.ok, report.problems
    assert report.manifest.encryption == ENCRYPTION_DATA


def test_verify_encrypted_bad_signature_fails_before_rar(rar, tmp_path, capsys):
    dek = crypto.generate_archive_password()
    target = tmp_path / "2026-01-01_000001_full.rar"
    _craft_encrypted_full(rar, tmp_path, target=target, dek=dek,
                          recipient=_recipient(), signer=_signer(), sign_bad=True)
    report = verify_archive(
        rar, target, fix=False,
        trusted_signing_pem=_signer()[1],
        recipient_private_pem=_recipient()[0],
        recipient_key_id=_recipient()[2])
    assert not report.ok
    assert any("manifest signature verification failed" in p for p in report.problems)
    out = capsys.readouterr().out
    assert "listing " not in out     # no listing, no sha256 work, no rar t
    assert "testing " not in out


def test_verify_encrypted_tampered_manifest_rejected(rar, tmp_path):
    dek = crypto.generate_archive_password()
    target = tmp_path / "2026-01-01_000002_full.rar"
    _craft_encrypted_full(rar, tmp_path, target=target, dek=dek,
                          recipient=_recipient(), signer=_signer(),
                          tampers_manifest=True)
    report = verify_archive(
        rar, target, fix=False,
        trusted_signing_pem=_signer()[1],
        recipient_private_pem=_recipient()[0])
    assert not report.ok
    assert any("manifest signature verification failed" in p for p in report.problems)


def test_verify_encrypted_missing_sig_member_rejected(rar, tmp_path):
    dek = crypto.generate_archive_password()
    target = tmp_path / "2026-01-01_000003_full.rar"
    _craft_encrypted_full(rar, tmp_path, target=target, dek=dek,
                          recipient=_recipient(), signer=_signer(), skip_sig=True)
    report = verify_archive(
        rar, target, fix=False,
        trusted_signing_pem=_signer()[1],
        recipient_private_pem=_recipient()[0])
    assert not report.ok
    problem = "\n".join(report.problems)
    assert MANIFEST_SIGNATURE_MEMBER in problem
    assert "missing or unreadable" in problem


def test_verify_encrypted_missing_keys_fail_with_clear_list(rar, tmp_path, capsys):
    dek = crypto.generate_archive_password()
    target = tmp_path / "2026-01-01_000004_full.rar"
    _craft_encrypted_full(rar, tmp_path, target=target, dek=dek,
                          recipient=_recipient(), signer=_signer())

    report = verify_archive(rar, target, fix=False)   # no keys at all
    assert not report.ok
    problem = "\n".join(report.problems)
    assert "no trusted signing key was provided" in problem
    assert "no recipient private key was provided" not in problem  # sig gate first
    assert "testing " not in capsys.readouterr().out

    report = verify_archive(
        rar, target, fix=False, trusted_signing_pem=_signer()[1])  # no private key
    assert not report.ok
    assert "no recipient private key was provided" in "\n".join(report.problems)


def test_verify_encrypted_wrong_recipient_key_fails_gracefully(rar, tmp_path):
    dek = crypto.generate_archive_password()
    target = tmp_path / "2026-01-01_000005_full.rar"
    _craft_encrypted_full(rar, tmp_path, target=target, dek=dek,
                          recipient=_recipient(), signer=_signer())
    other = crypto.generate_recipient_keypair()    # foreign private key
    report = verify_archive(
        rar, target, fix=False,
        trusted_signing_pem=_signer()[1],
        recipient_private_pem=other[0],
        recipient_key_id=None)
    assert not report.ok
    problem = "\n".join(report.problems)
    assert "cannot unwrap the archive password" in problem
    # the key id may appear (a fingerprint); the DEK/password never does
    assert dek.hex() not in problem


def test_verify_chain_encrypted_threads_keys(rar, tmp_path):
    """verify_chain passes the unlock kwargs to every archive's check."""
    epoch = tmp_path / "2026-01-01"
    epoch.mkdir()
    dek = crypto.generate_archive_password()
    target = epoch / "2026-01-01_000000_full.rar"
    _craft_encrypted_full(rar, tmp_path, target=target, dek=dek,
                          recipient=_recipient(), signer=_signer())

    bad = verify_chain(rar, epoch, fix=False)      # no keys -> clear failure
    assert len(bad) == 1 and not bad[0].ok
    assert "no trusted signing key was provided" in "\n".join(bad[0].problems)

    good = verify_chain(
        rar, epoch, fix=False,
        recipient_private_pem=_recipient()[0],
        trusted_signing_pem=_signer()[1],
        recipient_key_id=_recipient()[2])
    assert len(good) == 1 and good[0].ok, good[0].problems

