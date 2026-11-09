"""Epoch/chain layer tests: resolution, tip selection, base validation."""

import os
import uuid

import conftest
import pytest
import yaml
from conftest import run_cli, stored_files

from backuper import chain, crypto, rar_runner
from backuper.config import config_from_bytes, load_config
from backuper.errors import EpochError
from backuper.models import ENCRYPTION_DATA, MANIFEST_SIGNATURE_MEMBER, json_bytes

pytestmark = pytest.mark.skipif(conftest.RAR_PATH is None, reason="Rar.exe not found")

# Real keypairs, generated once per module (RSA-3072 keygen is slowish).
_RECIPIENT = None   # (private_pem, public_pem, key_id)
_SIGNER = None
_OTHER_SIGNER = None


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


def _other_signer():
    global _OTHER_SIGNER
    if _OTHER_SIGNER is None:
        _OTHER_SIGNER = crypto.generate_signing_keypair()
    return _OTHER_SIGNER


def config_text_with_keys(src, *,
                          recipient_pem: bytes | str | None,
                          signing_pem: bytes | str | None = None) -> str:
    """The default job config plus (optionally) the two public PEM blocks."""
    text = conftest.default_config_text(src)

    def block(name: str, pem: bytes | str) -> str:
        lines = (pem.decode("ascii") if isinstance(pem, bytes) else pem).strip("\n").splitlines()
        return f"{name}: |\n" + "\n".join("  " + ln for ln in lines) + "\n"

    if recipient_pem is not None:
        text += block("recipient_public_key", recipient_pem)
    return text


# ---------------------------------------------------------------------------
# resolve_epoch / epoch_full rejections (CLI level -> exit 5)
# ---------------------------------------------------------------------------

def test_diff_rejects_bad_epoch_names(job):
    job.make_source(a="x")
    assert run_cli(["full", job.dir]) == 0
    assert run_cli(["diff", job.dir, "--epoch", "nope"]) == 5
    assert run_cli(["diff", job.dir, "--epoch", "..\\evil"]) == 5
    assert run_cli(["diff", job.dir, "--epoch", "2026/01/01"]) == 5
    assert run_cli(["diff", job.dir, "--epoch", "2099-01-01"]) == 5  # missing


def test_diff_without_any_epoch_is_exit5(job):
    assert run_cli(["diff", job.dir]) == 5


def test_diff_into_empty_epoch_dir_is_exit5(job):
    (job.dir / "2026-01-01").mkdir()      # valid name, but no archives at all
    assert run_cli(["diff", job.dir]) == 5


def test_diff_with_broken_latest_epoch_is_exit5(job):
    # spec: "если в ней битые архивы -- сбой запуска" (a broken epoch = failure)
    job.make_source(a="x")
    assert run_cli(["full", job.dir]) == 0
    job.full_archive().unlink()           # full is gone -> epoch is broken
    assert run_cli(["diff", job.dir]) == 5


def test_tip_selection_with_multiple_diffs(job):
    job.make_source(**{"a.txt": "1"})
    assert run_cli(["full", job.dir]) == 0
    (job.src / "a.txt").write_bytes(b"2")
    assert run_cli(["diff", job.dir]) == 0
    (job.src / "b.txt").write_bytes(b"3")
    assert run_cli(["diff", job.dir]) == 0

    archives = job.archives()
    assert [p.name for p in archives] == sorted(p.name for p in archives)
    assert len(archives) == 3
    assert archives[0].name.endswith("_full.rar")
    assert all(p.name.endswith("_diff.rar") for p in archives[1:])
    tip = job.tip()
    assert tip == archives[-1]
    man = job.manifest_of(tip)
    assert man.previous_filename == archives[1].name
    assert man.previous_manifest_id == job.manifest_of(archives[1]).manifest_id
    assert man.base_full == archives[0].name
    assert run_cli(["verify", job.dir, "--chain"]) == 0


# ---------------------------------------------------------------------------
# check_base_archive: each "previous archive unavailable" condition alone
# ---------------------------------------------------------------------------

def manifest_bytes(**overrides) -> bytes:
    data = {
        "schema_version": 1,
        "manifest_id": str(uuid.uuid4()),
        "filename": "2026-01-01_000000_diff.rar",
        "archive_type": "diff",
        "created_utc": "2026-01-01T00:00:00Z",
        "config_name": "config.yaml",
        "config_sha256": "0" * 64,
        "script_version": "0.2.0",
        "rar_version": "7.22",
        "sources": ["C:/nonexistent-source"],
        "base_full": "2026-01-01_000000_full.rar",
        "previous_manifest_id": str(uuid.uuid4()),
        "previous_filename": None,
        "excludes": {"extensions": [], "dirs": []},
        "added_empty_dirs": [],
        "counters": {"files": 0, "empty_dirs": 0, "skipped": 0, "bytes": 0,
                     "deleted_files": 0, "deleted_dirs": 0, "added_empty_dirs": 0},
    }
    data.update(overrides)
    return json_bytes(data)


VALID_FILES_JSON = json_bytes({"schema_version": 1, "files": [], "empty_dirs": []})
VALID_CONFIG = b"source: C:/nonexistent-source\n"


def craft_archive(runner, target, staging, members: dict[str, bytes]) -> None:
    """Build a real (service-members-only) archive via the production step."""
    for rel, data in members.items():
        p = staging / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    names = [rel.replace("/", "\\") for rel in members]
    res = rar_runner.create_step(runner, target, staging, names,
                                 final=True, compression=0)
    assert res.ok, res.stdout() + res.stderr()


def test_check_base_archive_missing_file(rar, tmp_path):
    with pytest.raises(EpochError):
        chain.check_base_archive(rar, tmp_path / "absent.rar")


def test_check_base_archive_manifest_corrupt(rar, tmp_path):
    staging = tmp_path / "stage1"
    target = tmp_path / "bad_manifest.rar"
    craft_archive(rar, target, staging, {
        ".backup/manifest.json": b"{this is not json",
        ".backup/files.json": VALID_FILES_JSON,
        ".backup/config.yaml": VALID_CONFIG,
    })
    with pytest.raises(EpochError):
        chain.check_base_archive(rar, target)


def test_check_base_archive_files_json_unreadable(rar, tmp_path):
    staging = tmp_path / "stage2"
    target = tmp_path / "bad_files_json.rar"
    craft_archive(rar, target, staging, {
        ".backup/manifest.json": manifest_bytes(),
        ".backup/files.json": b"not json at all",
        ".backup/config.yaml": VALID_CONFIG,
    })
    with pytest.raises(EpochError):
        chain.check_base_archive(rar, target)


def test_check_base_archive_config_missing(rar, tmp_path):
    staging = tmp_path / "stage3"
    target = tmp_path / "no_config.rar"
    craft_archive(rar, target, staging, {
        ".backup/manifest.json": manifest_bytes(),
        ".backup/files.json": VALID_FILES_JSON,
    })
    with pytest.raises(EpochError):
        chain.check_base_archive(rar, target)


def test_check_base_archive_previous_file_renamed_away(rar, tmp_path):
    staging = tmp_path / "stage4"
    target = tmp_path / "dangling_prev.rar"
    craft_archive(rar, target, staging, {
        ".backup/manifest.json": manifest_bytes(previous_filename="ghost.rar"),
        ".backup/files.json": VALID_FILES_JSON,
        ".backup/config.yaml": VALID_CONFIG,
    })
    with pytest.raises(EpochError) as ei:
        chain.check_base_archive(rar, target)
    assert "ghost.rar" in str(ei.value)


def test_check_base_archive_valid_base_passes(rar, tmp_path):
    staging = tmp_path / "stage5"
    target = tmp_path / "good.rar"
    craft_archive(rar, target, staging, {
        ".backup/manifest.json": manifest_bytes(previous_filename=None),
        ".backup/files.json": VALID_FILES_JSON,
        ".backup/config.yaml": VALID_CONFIG,
    })
    info = chain.check_base_archive(rar, target)
    assert info.manifest.manifest_id
    assert info.snapshot.files == []
    assert info.config_bytes == VALID_CONFIG


# ---------------------------------------------------------------------------
# Other epoch refusals
# ---------------------------------------------------------------------------

def test_duplicate_full_same_day_is_exit5(job):
    job.make_source(a="x")
    assert run_cli(["full", job.dir]) == 0
    assert run_cli(["full", job.dir]) == 5
    assert len(job.archives()) == 1


def test_full_refuses_source_with_root_backup_dir(job):
    job.make_source(**{".backup/keep.txt": "x"})
    assert run_cli(["full", job.dir]) == 5


def test_config_mismatch_warning_on_diff_but_archive_config_operative(job, capsys):
    job.make_source(a="x")
    assert run_cli(["full", job.dir]) == 0

    # edit the JOB config after the full: the diff must warn but keep using
    # the ARCHIVE (embedded) config.
    job.write_config(conftest.default_config_text(job.src) +
                     "exclude_extensions: ['.tmp', '.zaps']\n")
    job.make_source(**{"skipme.zaps": "should be archived anyway"})

    assert run_cli(["diff", job.dir]) == 0
    err = capsys.readouterr().err
    assert "warning: job config differs" in err
    assert "exclude_extensions" in err

    diff = job.tip()
    man = job.manifest_of(diff)
    assert man.excludes["extensions"] == [".tmp"]      # archive config, not job
    files, _folders = stored_files(job, diff)
    assert "skipme.zaps" in files                      # operative config excluded nothing


# ---------------------------------------------------------------------------
# config_mismatch_warning with the encryption-key aspects (7-tuple)
# ---------------------------------------------------------------------------

def test_embedded_semantic_key_is_a_7_tuple_matching_semantic_key(job, tmp_path):
    """_embedded_semantic_key mirrors config.semantic_key incl. both key ids."""
    config_path = tmp_path / "config.yaml"
    text = config_text_with_keys(
        job.src,
        recipient_pem=_recipient()[1])
    config_path.write_text(text, encoding="utf-8", newline="")
    (tmp_path / "signing_public.pem").write_text(
        _signer()[1].decode("ascii"), encoding="utf-8")
    cfg = load_config(config_path)

    embedded_bytes = config_path.read_bytes()
    assert cfg.raw_bytes == embedded_bytes
    assert chain.config_mismatch_warning(
        cfg, embedded_bytes, embedded_signing_key_id=cfg.signing_key_id) is None

    data = yaml.safe_load(embedded_bytes)
    assert chain._embedded_semantic_key(data, cfg.signing_key_id) == (
        os.path.normcase(str(cfg.source)),
        tuple(sorted(cfg.exclude_extensions)),
        tuple(sorted(cfg.exclude_dirs)),
        tuple(sorted(cfg.lock_check_extensions)),
        cfg.compression,
        cfg.recipient_key_id,
        cfg.signing_key_id,
    )
    assert tuple(chain._ASPECT_NAMES) == (
        "source", "exclude_extensions", "exclude_dirs", "lock_check_extensions",
        "compression", "recipient_public_key", "signing_public_key")


def test_embedded_semantic_key_normalizes_absolute_exclude_dirs():
    job_cfg = config_from_bytes(
        b"source: 'C:/Data'\nexclude_dirs: ['C:/Data/Cache/']\n")
    embedded = (
        b"source: 'C:/Data'\n"
        b"exclude_dirs: ['\\\\?\\C:\\data\\cache']\n"
    )
    assert chain.config_mismatch_warning(job_cfg, embedded) is None


def test_config_mismatch_key_reformat_is_not_a_mismatch(job, tmp_path):
    """Same keys, different whitespace in the embedded YAML -> no warning."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        config_text_with_keys(job.src,
                              recipient_pem=_recipient()[1]),
        encoding="utf-8", newline="")
    (tmp_path / "signing_public.pem").write_text(
        _signer()[1].decode("ascii"), encoding="utf-8")
    cfg = load_config(config_path)

    # the embedded copy re-indents the PEM blocks (contents identical)
    reformatted = conftest.default_config_text(job.src)
    name, pem = "recipient_public_key", _recipient()[1]
    lines = pem.decode("ascii").strip("\n").splitlines()
    reformatted += f"{name}: |2\n" + "\n".join("    " + ln for ln in lines) + "\n"
    assert chain.config_mismatch_warning(
        cfg, reformatted.encode("ascii"),
        embedded_signing_key_id=cfg.signing_key_id) is None


def test_config_mismatch_lists_swapped_signing_key_aspect(job, tmp_path):
    """Swapping the signing key warns on its aspect only (not on others)."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        config_text_with_keys(job.src,
                              recipient_pem=_recipient()[1]),
        encoding="utf-8", newline="")
    (tmp_path / "signing_public.pem").write_text(
        _signer()[1].decode("ascii"), encoding="utf-8")
    cfg = load_config(config_path)

    embedded = config_text_with_keys(job.src,
                                     recipient_pem=_recipient()[1])
    warning = chain.config_mismatch_warning(
        cfg, embedded.encode("ascii"),
        embedded_signing_key_id=_other_signer()[2])
    assert warning is not None
    assert "signing_public_key" in warning
    for absent in ("source", "exclude_extensions", "recipient_public_key"):
        assert absent not in warning


def test_config_mismatch_lists_swapped_recipient_key_and_all_key_aspects_with_legacy(
        job, tmp_path):
    """A legacy embedded config (no keys) mismatches BOTH new aspects."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        config_text_with_keys(job.src,
                              recipient_pem=_recipient()[1]),
        encoding="utf-8", newline="")
    (tmp_path / "signing_public.pem").write_text(
        _signer()[1].decode("ascii"), encoding="utf-8")
    cfg = load_config(config_path)

    warning = chain.config_mismatch_warning(
        cfg, conftest.default_config_text(job.src).encode("utf-8"))
    assert warning is not None
    for present in ("recipient_public_key", "signing_public_key"):
        assert present in warning
    for absent in ("source", "exclude_extensions", "lock_check_extensions"):
        assert absent not in warning


def test_config_mismatch_unparsable_embedded_key_is_a_mismatch(job, tmp_path):
    """A garbage PEM in the embedded config cannot match the job key id."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        config_text_with_keys(job.src,
                              recipient_pem=_recipient()[1]),
        encoding="utf-8", newline="")
    (tmp_path / "signing_public.pem").write_text(
        _signer()[1].decode("ascii"), encoding="utf-8")
    cfg = load_config(config_path)

    warning = chain.config_mismatch_warning(
        cfg, conftest.default_config_text(job.src).encode("ascii") +
        b"signing_public_key: 'not a pem'\n")
    assert warning is not None
    assert "signing_public_key" in warning


# ---------------------------------------------------------------------------
# Manifest signature verification on load (encrypted manifests)
# ---------------------------------------------------------------------------

def _signed_members(*, sign_bad=False, sign_other=False):
    """Fresh signed encrypted-manifest member set for craft_archive.

    Returns ``(members: dict[str, bytes], signer_public_pem: bytes)``. The
    manifest carries a wrapped DEK for a fresh keypair and is signed by
    the module signer (or, when ``sign_other``, by a different signer).
    ``sign_bad`` signs bytes that are NOT the stored manifest.
    """
    private_pem, public_pem, rid = _recipient()
    dek = crypto.generate_archive_password()
    rid_wrapped = [crypto.wrap_key(public_pem, dek).to_json()]
    raw_manifest = manifest_bytes(
        encryption=ENCRYPTION_DATA,
        wrapped_keys=rid_wrapped,
        signing_key_id=_signer()[2],
    )
    signing_pem = _other_signer()[0] if sign_other else _signer()[0]
    over = b"tampered: not the manifest bytes" if sign_bad else raw_manifest
    sig = crypto.sign_bytes(signing_pem, over)
    members = {
        ".backup/manifest.json": raw_manifest,
        ".backup/files.json": VALID_FILES_JSON,
        ".backup/config.yaml": VALID_CONFIG,
        MANIFEST_SIGNATURE_MEMBER: json_bytes(sig.to_json()),
    }
    return members, _signer()[1]


def test_load_manifest_encrypted_signature_verified_ok(rar, tmp_path):
    staging = tmp_path / "stage_ok"
    target = tmp_path / "signed_ok.rar"
    members, signer_public = _signed_members()
    craft_archive(rar, target, staging, members)
    manifest = chain.load_manifest(rar, target, trusted_signing_pem=signer_public)
    assert manifest.encryption == ENCRYPTION_DATA
    assert manifest.wrapped_keys


def test_load_manifest_encrypted_bad_signature_rejected(rar, tmp_path):
    staging = tmp_path / "stage_bad"
    target = tmp_path / "signed_bad.rar"
    members, signer_public = _signed_members(sign_bad=True)
    craft_archive(rar, target, staging, members)
    with pytest.raises(EpochError, match="signature"):
        chain.load_manifest(rar, target, trusted_signing_pem=signer_public)


def test_load_manifest_encrypted_wrong_trusted_key_rejected(rar, tmp_path):
    staging = tmp_path / "stage_slope"
    target = tmp_path / "signed_wrong_key.rar"
    members, _ = _signed_members(sign_other=True)
    craft_archive(rar, target, staging, members)
    with pytest.raises(EpochError, match="signature verification failed"):
        chain.load_manifest(
            rar, target,
            trusted_signing_pem=b"-----BEGIN PUBLIC KEY-----\nbogus")


def test_load_manifest_encrypted_tampered_member_rejected(rar, tmp_path):
    """The stored manifest differs by 64 bytes from the signed bytes."""
    members, signer_public = _signed_members()
    raw = members[".backup/manifest.json"]
    assert raw.count(b"0" * 64) == 1        # config_sha256 sentinel
    members[".backup/manifest.json"] = raw.replace(b"0" * 64, b"1" * 64, 1)
    staging = tmp_path / "stage_flip"
    target = tmp_path / "signed_tampered.rar"
    craft_archive(rar, target, staging, members)
    with pytest.raises(EpochError, match="signature verification failed"):
        chain.load_manifest(rar, target, trusted_signing_pem=signer_public)


def test_load_manifest_encrypted_missing_sig_member_rejected(rar, tmp_path):
    staging = tmp_path / "stage_nosig"
    target = tmp_path / "missing_sig.rar"
    members, signer_public = _signed_members()
    del members[MANIFEST_SIGNATURE_MEMBER]
    craft_archive(rar, target, staging, members)
    with pytest.raises(EpochError) as ei:
        chain.load_manifest(rar, target, trusted_signing_pem=signer_public)
    assert MANIFEST_SIGNATURE_MEMBER in str(ei.value)


def test_load_manifest_encrypted_no_trusted_key_is_lenient(rar, tmp_path):
    staging = tmp_path / "stage_tenant"
    target = tmp_path / "lenient.rar"
    members, _ = _signed_members()
    craft_archive(rar, target, staging, members)
    manifest = chain.load_manifest(rar, target)   # no key, no require_signature
    assert manifest.encryption == ENCRYPTION_DATA


def test_load_manifest_encrypted_require_signature_without_key_fails(rar, tmp_path):
    staging = tmp_path / "stage_require"
    target = tmp_path / "require.rar"
    members, _ = _signed_members()
    craft_archive(rar, target, staging, members)
    with pytest.raises(EpochError, match="no trusted signing key"):
        chain.load_manifest(rar, target, require_signature=True)


def test_load_manifest_legacy_with_stray_sig_member_and_key_loads(rar, tmp_path):
    """A legacy manifest is never signature-checked; a stray .sig member is
    tolerated (ignored) even when a trusted key is supplied."""
    signing_priv, _signing_pub, sign_key_id = _signer()
    raw_manifest = manifest_bytes()          # legacy: no encryption envelope
    stray_sig = json_bytes({"algorithm": "Ed25519", "signing_key_id": "zz",
                            "signature": ""})
    staging = tmp_path / "stage_twin"
    target = tmp_path / "legacy_stray_sig.rar"
    craft_archive(rar, target, staging, {
        ".backup/manifest.json": raw_manifest,
        ".backup/files.json": VALID_FILES_JSON,
        ".backup/config.yaml": VALID_CONFIG,
        MANIFEST_SIGNATURE_MEMBER: stray_sig,
    })
    manifest = chain.load_manifest(rar, target, trusted_signing_pem=_signer()[1])
    assert manifest.encryption is None


def test_check_base_archive_threads_signature_kwargs(rar, tmp_path):
    staging = tmp_path / "stage_base"
    target = tmp_path / "base.rar"
    members, signer_public = _signed_members()
    craft_archive(rar, target, staging, members)

    info = chain.check_base_archive(rar, target, trusted_signing_pem=signer_public)
    assert info.manifest.encryption == ENCRYPTION_DATA

    members_bad, signer_public = _signed_members(sign_bad=True)
    staging_bad = tmp_path / "stage_base_bad"
    target_bad = tmp_path / "base_bad.rar"
    craft_archive(rar, target_bad, staging_bad, members_bad)
    with pytest.raises(EpochError, match="signature"):
        chain.check_base_archive(rar, target_bad, trusted_signing_pem=signer_public)


