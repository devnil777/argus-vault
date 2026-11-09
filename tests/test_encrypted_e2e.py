"""End-to-end tests for per-archive encryption (real Rar.exe, full flow).

Covers the create-side integration inside ``create_archive``:
ciphered user content (content step), OPEN ``.backup/`` metadata, the
manifest encryption envelope + detached signature member, the password
transport through ``password_for_rar`` + ``extract_archive_password``,
and the byte-identical legacy behaviour when the job config carries no
keys. Secrets are asserted absent from everything the runs print.
"""

from __future__ import annotations

import json
import re

import conftest
import pytest
from conftest import stored_files

from backuper import crypto, rar_runner, runner
from backuper.errors import ConfigError, EpochError
from backuper.models import ENCRYPTION_DATA, MANIFEST_SIGNATURE_MEMBER

pytestmark = pytest.mark.skipif(conftest.RAR_PATH is None, reason="Rar.exe not found")

try:
    _ = crypto.CryptoError                # noqa: B018 — probe the import
    _HAS_CRYPTO = True
except (ImportError, AttributeError):     # pragma: no cover
    _HAS_CRYPTO = False

_needs_crypto = pytest.mark.skipif(not _HAS_CRYPTO,
                                   reason="backuper.crypto not importable")


# ---------------------------------------------------------------------------
# helpers (session-cached keypairs: RSA-3072 generation is CPU-heavy)
# ---------------------------------------------------------------------------

_KEYS_CACHE: dict = {}


def gen_keypairs():
    """Generate both keypairs once per session."""
    if "keys" not in _KEYS_CACHE:
        rec_priv, rec_pub, rec_id = crypto.generate_recipient_keypair()
        sig_priv, sig_pub, sig_id = crypto.generate_signing_keypair()
        _KEYS_CACHE["keys"] = (rec_priv, rec_pub, rec_id,
                               sig_priv, sig_pub, sig_id)
    return _KEYS_CACHE["keys"]


def _pem_block(pem: bytes) -> str:
    """A PEM as a YAML literal block, indented for config.yaml."""
    return "\n".join("  " + line for line in pem.decode("ascii").strip().splitlines())


def make_encrypted_job(job: conftest.Job) -> tuple:
    """Rewrite the job's config with the public keys + write both PRIVATE PEMs.

    Returns ``(rec_priv, rec_pub, rec_id, sig_priv, sig_pub, sig_id)``.
    The private files live next to config.yaml exactly as the keygen flow
    would place them; the recipient private file is only needed to exercise
    the ``password``/extract path.
    """
    rec_priv, rec_pub, rec_id, sig_priv, sig_pub, sig_id = gen_keypairs()
    job.write_config(
        f"source: {job.src.as_posix()}\n"
        "exclude_extensions: ['.tmp']\n"
        f"recipient_public_key: |\n{_pem_block(rec_pub)}\n"
)
    (job.dir / "recipient_private.pem").write_bytes(rec_priv)
    (job.dir / "signing_private.pem").write_bytes(sig_priv)
    (job.dir / "signing_public.pem").write_bytes(sig_pub)
    return rec_priv, rec_pub, rec_id, sig_priv, sig_pub, sig_id


def _sig_of(job: conftest.Job, archive, sig_pub: bytes) -> crypto.Signature:
    raw = rar_runner.read_service_member(job.rar, archive, MANIFEST_SIGNATURE_MEMBER)
    return crypto.Signature.from_json(json.loads(raw.decode("utf-8")))


def _assert_open_metadata(job: conftest.Job, archive, *, rec_id: str, sig_id: str) -> bytes:
    """All service members must read WITHOUT a password; envelope checked."""
    raw_manifest = rar_runner.read_service_member(
        job.rar, archive, ".backup/manifest.json")
    data = json.loads(raw_manifest.decode("utf-8"))
    assert data["encryption"] == ENCRYPTION_DATA
    assert data["wrapped_keys"], "wrapped_keys must be present"
    assert data["wrapped_keys"][0]["recipient_key_id"] == rec_id
    assert data["wrapped_keys"][0]["algorithm"] == "RSA-OAEP-SHA256"
    assert data["signing_key_id"] == sig_id
    # the other service members stay open as well
    rar_runner.read_service_member(job.rar, archive, ".backup/files.json")
    rar_runner.read_service_member(job.rar, archive, ".backup/config.yaml")
    return raw_manifest


# ---------------------------------------------------------------------------
# happy path: encrypted full + content diff
# ---------------------------------------------------------------------------

@_needs_crypto
def test_encrypted_full_and_diff_e2e(job, capsys):
    rec_priv, rec_pub, rec_id, sig_priv, sig_pub, sig_id = make_encrypted_job(job)
    job.make_source(readme="hello world", **{"sub/data.bin": bytes(range(256))})

    assert runner.cmd_full(job.dir, None, progress=False) == 0
    full = job.full_archive()

    # readable metadata + envelope
    raw_manifest = _assert_open_metadata(job, full, rec_id=rec_id, sig_id=sig_id)
    # detached signature over the EXACT manifest bytes, verified with the
    # PUBLIC signing key straight from the config text
    sig = _sig_of(job, full, sig_pub)
    crypto.verify_bytes(sig_pub, raw_manifest, sig)

    # the sig member is staged like any other service member
    files, _folders = stored_files(job, full)
    assert MANIFEST_SIGNATURE_MEMBER in files
    assert "readme" in files and "sub/data.bin" in files

    # wrapped key round-trip: unwrap with the recipient private key and get
    # byte-identical RAR password out of the wave-1 extractor helper
    dek = crypto.unwrap_key(
        rec_priv, crypto.WrappedKey.from_json(json.loads(raw_manifest.decode(
            "utf-8"))["wrapped_keys"][0]))
    password = runner.extract_archive_password(
        full, recipient_private_key_path=str(job.dir / "recipient_private.pem"))
    assert password == crypto.password_for_rar(dek)
    assert re.fullmatch(rb"[0-9a-f]{64}", password)   # 64 lowercase hex chars

    # `rar t` passes WITH the password, FAILS without it
    assert rar_runner.test_archive(job.rar, full, password=password) == 0
    without = rar_runner.test_archive(job.rar, full, password=None)
    assert without != 0   # wrong-password path, never a hang

    # --- content diff keeps the scheme alive ---------------------------------
    (job.src / "readme").write_bytes(b"changed with a different size")
    (job.src / "new.bin").write_bytes(b"added later")
    assert runner.cmd_diff(job.dir, None, None, progress=False) == 0
    diff = job.tip()
    raw_diff_manifest = _assert_open_metadata(
        job, diff, rec_id=rec_id, sig_id=sig_id)
    crypto.verify_bytes(sig_pub, raw_diff_manifest, _sig_of(job, diff, sig_pub))
    diff_password = runner.extract_archive_password(
        diff, recipient_private_key_path=str(job.dir / "recipient_private.pem"))
    assert rar_runner.test_archive(job.rar, diff, password=diff_password) == 0

    # no password / private key material leaked into ANY captured output
    captured = capsys.readouterr()
    everything = captured.out + captured.err
    assert password.decode("ascii") not in everything
    assert diff_password.decode("ascii") not in everything
    assert sig_priv.decode("ascii").strip() not in everything
    assert rec_priv.decode("ascii").strip() not in everything
    assert "PRIVATE KEY" not in everything

    # the creation log keeps the public scheme description, never secrets
    log_text = (job.full_archive().with_name(full.name + ".log")).read_text(
        encoding="utf-8")
    assert password.decode("ascii") not in log_text
    assert "encryption" in log_text


# ---------------------------------------------------------------------------
# deletes-only diff: metadata-only archive still carries a valid signature
# ---------------------------------------------------------------------------

@_needs_crypto
def test_encrypted_deletes_only_diff_e2e(job):
    _rec_priv, rec_pub, rec_id, _sig_priv, sig_pub, sig_id = make_encrypted_job(job)
    job.make_source(**{"a.txt": "one", "b.txt": "two"})

    assert runner.cmd_full(job.dir, None, progress=False) == 0
    (job.src / "a.txt").unlink()
    assert runner.cmd_diff(job.dir, None, None, progress=False) == 0
    diff = job.tip()

    files, _folders = stored_files(job, diff)
    # zero user files, only the (open) service members + the sig member
    assert set(files) == {
        ".backup/manifest.json", ".backup/files.json", ".backup/config.yaml",
        ".backup/delete_files.txt", ".backup/delete_dirs.txt",
        MANIFEST_SIGNATURE_MEMBER,
    }
    assert member_delete_lists(job, diff) == ["a.txt"]

    raw_manifest = _assert_open_metadata(job, diff, rec_id=rec_id, sig_id=sig_id)
    crypto.verify_bytes(sig_pub, raw_manifest, _sig_of(job, diff, sig_pub))

    password = runner.extract_archive_password(
        diff, recipient_private_key_path=str(job.dir / "recipient_private.pem"))
    assert rar_runner.test_archive(job.rar, diff, password=password) == 0
    # BY DESIGN the deletes-only archive stores NO encrypted member (no
    # content step): testing without a password therefore succeeds too --
    # the manifest still carries the envelope + valid signature.
    assert rar_runner.test_archive(job.rar, diff, password=None) == 0


def member_delete_lists(job: conftest.Job, archive) -> list[str]:
    raw = rar_runner.read_service_member(
        job.rar, archive, ".backup/delete_files.txt")
    return [line for line in raw.decode("utf-8").splitlines() if line]


# ---------------------------------------------------------------------------
# missing / mismatched signing key: clear ConfigError, no archive produced
# ---------------------------------------------------------------------------

@_needs_crypto
def test_encrypted_missing_signing_key_fails_full(job):
    rec_priv, rec_pub, _rec_id, sig_priv, sig_pub, _sig_id = gen_keypairs()
    job.write_config(
        f"source: {job.src.as_posix()}\n"
        "exclude_extensions: ['.tmp']\n"
        f"recipient_public_key: |\n{_pem_block(rec_pub)}\n"
)
    (job.dir / "recipient_private.pem").write_bytes(rec_priv)   # but NOT signing
    (job.dir / "signing_public.pem").write_bytes(sig_pub)
    job.make_source(some_file="content")

    with pytest.raises(ConfigError) as ei:
        runner.cmd_full(job.dir, None, progress=False)
    assert "signing private key" in str(ei.value)
    assert "signing_private.pem" in str(ei.value)
    assert ei.value.exit_code == 5
    # no half-written archive, no failed-run log claiming a RAR problem
    assert list(job.dir.glob("**/*.rar")) == []
    assert list(job.dir.glob("**/*.rar.tmp")) == []


@_needs_crypto
def test_encrypted_mismatched_signing_key_fails_full(job):
    _rec_priv, rec_pub, _r, sig_priv, sig_pub, _s = gen_keypairs()
    # a fresh, DIFFERENT Ed25519 private key (the cached pair matches config)
    _o1, _o2, _o3 = crypto.generate_signing_keypair()
    other_sig_priv, _o5, _o6 = crypto.generate_signing_keypair()
    job.write_config(
        f"source: {job.src.as_posix()}\n"
        "exclude_extensions: ['.tmp']\n"
        f"recipient_public_key: |\n{_pem_block(rec_pub)}\n"
)
    (job.dir / "signing_private.pem").write_bytes(other_sig_priv)
    (job.dir / "signing_public.pem").write_bytes(sig_pub)
    job.make_source(some_file="content")

    with pytest.raises(ConfigError) as ei:
        runner.cmd_full(job.dir, None, progress=False)
    assert "does not match" in str(ei.value)
    assert ei.value.exit_code == 5
    assert list(job.dir.glob("**/*.rar")) == []


# ---------------------------------------------------------------------------
# legacy behaviour byte-for-byte: no keys -> no envelope, no sig, no -p
# ---------------------------------------------------------------------------

@_needs_crypto
def test_legacy_job_without_keys_stays_unencrypted(job):
    job.make_source(plain="simple text")

    assert runner.cmd_full(job.dir, None, progress=False) == 0
    full = job.full_archive()

    man = job.manifest_of(full)
    assert man.encryption is None
    assert man.wrapped_keys is None
    assert man.signing_key_id is None

    files, _folders = stored_files(job, full)
    assert MANIFEST_SIGNATURE_MEMBER not in files
    assert "plain" in files

    # unencrypted content tests fine WITHOUT any password
    assert rar_runner.test_archive(job.rar, full, password=None) == 0

    # the wave-1 extractor refuses an unencrypted archive
    with pytest.raises(ConfigError) as ei:
        runner.extract_archive_password(full)
    assert "not encrypted" in str(ei.value)


# ---------------------------------------------------------------------------
# diff trust gate: a forged/substituted tip manifest fails the diff BEFORE
# any new archive is written (signature verified against the job config's
# trusted signing key, not the manifest's own informational key field)
# ---------------------------------------------------------------------------

@_needs_crypto
def test_encrypted_diff_forged_tip_fails_before_writing(job, tmp_path):
    rec_priv, _rec_pub, _rec_id, _sig_priv, _sig_pub, _sig_id = make_encrypted_job(job)
    job.make_source(readme="hello world", **{"sub/data.bin": bytes(range(256))})

    assert runner.cmd_full(job.dir, None, progress=False) == 0
    tip = job.tip()
    epoch_dir = tip.parent
    before = sorted(p.name for p in epoch_dir.iterdir())

    # Forge the tip: the exact original OPEN members, but the detached
    # signature is produced by a FOREIGN signing key. The encrypted content
    # step is rebuilt with the SAME DEK so the forgery is otherwise sound.
    f_priv, _f_pub, _f_id = crypto.generate_signing_keypair()
    raw_manifest = rar_runner.read_service_member(job.rar, tip, ".backup/manifest.json")
    manifest_json = json.loads(raw_manifest.decode("utf-8"))
    dek = crypto.unwrap_key(
        rec_priv, crypto.WrappedKey.from_json(manifest_json["wrapped_keys"][0]))
    password = crypto.password_for_rar(dek)

    svc_stage = tmp_path / "forge_svc"
    svc = {
        ".backup/manifest.json": raw_manifest,
        ".backup/files.json": rar_runner.read_service_member(
            job.rar, tip, ".backup/files.json"),
        ".backup/config.yaml": rar_runner.read_service_member(
            job.rar, tip, ".backup/config.yaml"),
        MANIFEST_SIGNATURE_MEMBER: json.dumps(
            crypto.sign_bytes(f_priv, raw_manifest).to_json()).encode("ascii"),
    }
    for rel, data in svc.items():
        p = svc_stage / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    res = rar_runner.create_step(job.rar, tip, svc_stage, list(svc),
                                 final=False, compression=0)
    assert res.ok, res.stdout() + res.stderr()

    src_stage = tmp_path / "forge_src"
    src_stage.mkdir()
    (src_stage / "readme").write_bytes(b"hello world")
    (src_stage / "sub").mkdir()
    (src_stage / "sub" / "data.bin").write_bytes(bytes(range(256)))
    res = rar_runner.create_step(job.rar, tip, src_stage, ["readme", "sub\\data.bin"],
                                 final=True, compression=0, password=password)
    assert res.ok, res.stdout() + res.stderr()

    with pytest.raises(EpochError, match="signature verification failed"):
        runner.cmd_diff(job.dir, None, None, progress=False)
    # the trust gate fired before anything was written: no diff archive,
    # no failed/nothing log, no temp artifacts
    assert sorted(p.name for p in epoch_dir.iterdir()) == before
