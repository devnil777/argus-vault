"""Config/model/CLI support for archive encryption keys.

Covers the config keys (recipient_public_key / signing_public_key), the
additive Manifest encryption envelope, the ``keygen``/``init
--generate-keys`` flow and the ``password`` command. RAR itself is never
invoked: the archive-member reader is stubbed out, so these tests run
even without Rar.exe. The crypto-dependent parts skip (not fail) when
``backuper.crypto`` cannot be imported.
"""

from __future__ import annotations

import json

import conftest
import pytest
import yaml

from backuper import runner
from backuper.config import (
    CONFIG_NAME,
    RECIPIENT_PRIVATE_NAME,
    SIGNING_PRIVATE_NAME,
    config_from_bytes,
    load_config,
    private_key_path,
    semantic_key,
)
from backuper.errors import ConfigError
from backuper.models import (
    ENCRYPTION_DATA,
    MANIFEST_SIGNATURE_MEMBER,
    SCHEMA_VERSION,
    Manifest,
    json_bytes,
)

try:
    from backuper import crypto
    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover — only when the crypto layer is absent
    crypto = None
    _HAS_CRYPTO = False

needs_crypto = pytest.mark.skipif(not _HAS_CRYPTO, reason="backuper.crypto not importable")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_KEYS_CACHE: dict = {}


def gen_keypairs():
    """Generate both keypairs once per session (RSA-3072 gen is CPU-heavy)."""
    if "keys" not in _KEYS_CACHE:
        rec_priv, rec_pub, rec_id = crypto.generate_recipient_keypair()
        sig_priv, sig_pub, sig_id = crypto.generate_signing_keypair()
        _KEYS_CACHE["keys"] = (rec_priv, rec_pub, rec_id, sig_priv, sig_pub, sig_id)
    return _KEYS_CACHE["keys"]


def config_text_with_keys(*, rec_pub: bytes = None, sig_pub: bytes = None,
                          indent: int = 2) -> str:
    """A valid config.yaml text carrying both public keys as literal blocks."""
    def block(pem: bytes) -> str:
        pad = " " * indent
        return "\n".join(pad + line for line in pem.decode("ascii").strip().splitlines())
    text = "source: C:/Data\nexclude_extensions: ['.tmp']\ncompression: 3\n"
    if rec_pub is not None:
        text += f"recipient_public_key: |\n{block(rec_pub)}\n"
    return text


def write_config(dir_path, text) -> object:
    p = dir_path / CONFIG_NAME
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text.encode("utf-8"))
    return p


def manifest_dict(**extra) -> dict:
    """A minimal valid legacy manifest payload (no envelope)."""
    d = {
        "schema_version": SCHEMA_VERSION,
        "manifest_id": "11112222-3333-4444-5555-666677778888",
        "filename": "2026-11-07_010000_full.rar",
        "archive_type": "full",
        "created_utc": "2026-11-07T01:00:00.0000000Z",
        "config_name": "config.yaml",
        "config_sha256": "0" * 64,
        "script_version": "test",
        "rar_version": "test",
        "sources": ["C:/Data"],
        "base_full": None,
        "previous_manifest_id": None,
        "previous_filename": None,
        "excludes": {"extensions": [], "dirs": []},
        "added_empty_dirs": [],
        "counters": {"files": 0, "empty_dirs": 0, "skipped": 0, "bytes": 0,
                     "deleted_files": 0, "deleted_dirs": 0, "added_empty_dirs": 0},
    }
    d.update(extra)
    return d


def _pem_block(pem: bytes) -> str:
    return "\n".join("  " + line for line in pem.decode("ascii").strip().splitlines())


def write_encrypted_job(tmp_path, *, tamper: bool = False) -> tuple[bytes, bytes, bytes]:
    """Deploy a full encryption setup in ``tmp_path`` (job dir = config + keys).

    Returns (manifest_json_bytes, sig_json_bytes, dek); the manifest is
    signed over the EXACT manifest bytes, optionally corrupted afterwards
    (``tamper``) so signature verification fails.
    """
    rec_priv, rec_pub, rec_id, sig_priv, sig_pub, sig_id = gen_keypairs()
    text = ("source: C:/Data\n"
            "recipient_public_key: |\n" + _pem_block(rec_pub) + "\n")
    write_config(tmp_path, text)
    (tmp_path / RECIPIENT_PRIVATE_NAME).write_bytes(rec_priv)
    (tmp_path / SIGNING_PRIVATE_NAME).write_bytes(sig_priv)
    (tmp_path / "signing_public.pem").write_bytes(sig_pub)

    dek = crypto.generate_archive_password()
    wrapped = crypto.wrap_key(rec_pub, dek)
    m = Manifest.from_json({
        **manifest_dict(),
        "encryption": ENCRYPTION_DATA,
        "wrapped_keys": [wrapped.to_json()],
        "signing_key_id": sig_id,
    })
    manifest_json = json_bytes(m.to_json())
    sig = crypto.sign_bytes(sig_priv, manifest_json)
    if tamper:
        manifest_json = manifest_json.replace(b"010000", b"019999")
    return manifest_json, json_bytes(sig.to_json()), dek


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def test_private_key_constants_and_paths():
    assert RECIPIENT_PRIVATE_NAME == "recipient_private.pem"
    assert SIGNING_PRIVATE_NAME == "signing_private.pem"
    cfg_path = "D:/jobs/job1/" + CONFIG_NAME
    assert private_key_path(cfg_path, "recipient").name == "recipient_private.pem"
    assert private_key_path(cfg_path, "signing").name == "signing_private.pem"
    assert private_key_path(cfg_path, "recipient").parent.as_posix() == "D:/jobs/job1"
    with pytest.raises(ValueError):
        private_key_path(cfg_path, "bogus")


@needs_crypto
def test_config_accepts_both_keys(tmp_path):
    _, rec_pub, rec_id, _, sig_pub, sig_id = gen_keypairs()
    p = write_config(tmp_path, config_text_with_keys(rec_pub=rec_pub, sig_pub=sig_pub))
    (tmp_path / "signing_public.pem").write_bytes(sig_pub)
    cfg = load_config(p)
    assert cfg.encryption_enabled is True
    assert cfg.recipient_key_id == rec_id
    assert cfg.signing_key_id == sig_id
    # canonical PEM: byte-equal to crypto's canonical form
    assert cfg.recipient_public_pem == crypto.canonical_public_pem(rec_pub).decode()
    assert cfg.signing_public_pem == crypto.canonical_public_pem(sig_pub).decode()
    # embedded config no longer carries the signing key (it lives in the file)
    emb = config_from_bytes(p.read_bytes())
    assert emb.recipient_key_id == rec_id
    assert emb.signing_key_id is None


@needs_crypto
def test_config_rejects_one_key_without_the_other(tmp_path):
    _, rec_pub, _, _, _, _ = gen_keypairs()
    text = "source: C:/Data\nrecipient_public_key: |\n" + _pem_block(rec_pub) + "\n"
    with pytest.raises(ConfigError) as ei:
        load_config(write_config(tmp_path, text))
    assert "must be set together" in str(ei.value)

    _, _, _, _, sig_pub, _ = gen_keypairs()
    with pytest.raises(ConfigError):
        load_config(write_config(
            tmp_path, "source: C:/Data\nsigning_public_key: |\n" + _pem_block(sig_pub) + "\n"))


@needs_crypto
def test_config_rejects_bad_public_keys(tmp_path):
    _, _, _, _, sig_pub, _ = gen_keypairs()
    # valid signing key but garbage recipient key
    text = ("source: C:/Data\n"
            "recipient_public_key: not-a-pem\n")
    (tmp_path / "signing_public.pem").write_bytes(sig_pub)
    with pytest.raises(ConfigError) as ei:
        load_config(write_config(tmp_path, text))
    assert "valid PEM" in str(ei.value)
    # non-string values rejected
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, "source: C:/Data\nrecipient_public_key: 42\n"
                                         "signing_public_key: 42\n"))
    # empty strings rejected
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, "source: C:/Data\nrecipient_public_key: ''\n"
                                         "signing_public_key: ''\n"))


@needs_crypto
def test_unknown_keys_still_rejected_with_keys_present(tmp_path):
    _, rec_pub, _, _, sig_pub, _ = gen_keypairs()
    text = config_text_with_keys(rec_pub=rec_pub, sig_pub=sig_pub) \
        .replace("compression: 3", "compression: 3\nexclude_extention: ['.tmp']")
    with pytest.raises(ConfigError) as ei:
        load_config(write_config(tmp_path, text))
    assert "unknown key" in str(ei.value)


@needs_crypto
def test_semantic_key_swaps_with_keys(tmp_path):
    _, rec_pub, rec_id, _, sig_pub, sig_id = gen_keypairs()
    a = config_from_bytes(
        config_text_with_keys(rec_pub=rec_pub, sig_pub=sig_pub).encode("utf-8"))
    # signing key no longer travels in config.yaml; only recipient id is here
    assert semantic_key(a)[-2] == rec_id
    assert semantic_key(a)[-1] is None
    # same keys, different formatting (deeper indentation): ids unchanged
    b = config_from_bytes(
        config_text_with_keys(rec_pub=rec_pub, sig_pub=sig_pub, indent=4).encode("utf-8"))
    assert semantic_key(b) == semantic_key(a)
    # a swapped recipient key changes the semantics
    rec_priv2, rec_pub2, rec_id2 = crypto.generate_recipient_keypair()
    assert rec_id2 != rec_id
    c = config_from_bytes(
        config_text_with_keys(rec_pub=rec_pub2, sig_pub=sig_pub).encode("utf-8"))
    assert semantic_key(c) != semantic_key(a)
    # encryption off vs on differs
    legacy = config_from_bytes(b"source: C:/Data\n")
    assert semantic_key(legacy) != semantic_key(a)


def test_legacy_config_summary_fields_unchanged():
    cfg = config_from_bytes(b"source: C:/Data\ncompression: 2\n")
    assert cfg.encryption_enabled is False
    assert cfg.recipient_public_pem is None and cfg.recipient_key_id is None
    assert cfg.compression == 2


def test_rewrite_config_helper_refuses_other_keys_and_preserves_fields(tmp_path):
    """rewrite_config_with_public_keys keeps other keys, needs --force on change."""
    _, rec_pub, rec_id, _, sig_pub, sig_id = gen_keypairs()
    p = write_config(tmp_path, "source: C:/Data\ncompression: 2\n")
    from backuper.config import rewrite_config_with_public_keys
    rewrite_config_with_public_keys(p, rec_pub, sig_pub, force=False)
    cfg = load_config(p)
    assert cfg.compression == 2 and cfg.recipient_key_id == rec_id
    assert cfg.signing_key_id == sig_id
    raw = p.read_bytes()
    assert b"recipient_private.pem" not in raw and b"signing_private.pem" not in raw
    # different keys without --force -> ConfigError
    rec_priv2, rec_pub2, _ = crypto.generate_recipient_keypair()
    with pytest.raises(ConfigError) as ei:
        rewrite_config_with_public_keys(p, rec_pub2, sig_pub, force=False)
    assert "--force" in str(ei.value)
    # with --force it replaces
    rewrite_config_with_public_keys(p, rec_pub2, sig_pub, force=True)
    assert load_config(p).recipient_key_id != rec_id


# ---------------------------------------------------------------------------
# models: Manifest additive envelope
# ---------------------------------------------------------------------------

def test_old_manifest_without_envelope_loads():
    m = Manifest.from_json(manifest_dict())
    assert m.encryption is None and m.wrapped_keys is None
    assert m.signing_key_id is None
    # legacy manifests serialize WITHOUT the new keys
    out = json.loads(json_bytes(m.to_json()))
    assert "encryption" not in out and "wrapped_keys" not in out
    assert "signing_key_id" not in out


@needs_crypto
def test_manifest_envelope_roundtrip():
    _, _, rec_id, _, _, sig_id = gen_keypairs()
    wrapped = {"algorithm": "RSA-OAEP-SHA256", "recipient_key_id": rec_id, "wrapped": "AAA="}
    src = manifest_dict(encryption=ENCRYPTION_DATA, wrapped_keys=[wrapped],
                        signing_key_id=sig_id)
    m = Manifest.from_json(src)
    assert m.encryption == ENCRYPTION_DATA
    assert m.wrapped_keys == [wrapped]
    assert m.signing_key_id == sig_id
    # round-trip through to_json -> from_json
    m2 = Manifest.from_json(json.loads(json_bytes(m.to_json())))
    assert m2.to_json() == m.to_json()
    out = json.loads(json_bytes(m.to_json()))
    assert out["encryption"] == ENCRYPTION_DATA and out["wrapped_keys"] == [wrapped]


def test_manifest_envelope_bad_types_rejected():
    with pytest.raises(ValueError):
        Manifest.from_json(manifest_dict(encryption=7))
    with pytest.raises(ValueError):
        Manifest.from_json(manifest_dict(encryption=""))
    with pytest.raises(ValueError):
        Manifest.from_json(manifest_dict(wrapped_keys=[42]))
    with pytest.raises(ValueError):
        Manifest.from_json(manifest_dict(wrapped_keys="x"))
    with pytest.raises(ValueError):
        Manifest.from_json(manifest_dict(signing_key_id=0))


def test_schema_version_stays_1():
    assert SCHEMA_VERSION == 1
    assert Manifest.from_json(manifest_dict()).schema_version == 1
    m = Manifest.from_json(manifest_dict(encryption=ENCRYPTION_DATA))
    assert m.to_json()["schema_version"] == 1


# ---------------------------------------------------------------------------
# keygen flow
# ---------------------------------------------------------------------------

@needs_crypto
def test_generate_job_keys_creates_files_and_config(tmp_path, capsys):
    write_config(tmp_path, "source: C:/Data\ncompression: 1\n")

    runner.generate_job_keys(tmp_path / CONFIG_NAME)

    priv = tmp_path / RECIPIENT_PRIVATE_NAME
    sigp = tmp_path / SIGNING_PRIVATE_NAME
    priv_pem, sig_pem = priv.read_bytes(), sigp.read_bytes()
    assert b"PRIVATE KEY" in priv_pem and b"PRIVATE KEY" in sig_pem
    cfg = load_config(tmp_path / CONFIG_NAME)
    assert cfg.compression == 1 and cfg.encryption_enabled is True
    # config keys match the written private keys (same keypair, round-trip)
    rec_id = crypto.key_id_for_public(crypto.load_public_pem(cfg.recipient_public_pem.encode()))
    sig_id = crypto.key_id_for_public(crypto.load_public_pem(cfg.signing_public_pem.encode()))
    assert cfg.recipient_key_id == rec_id and cfg.signing_key_id == sig_id
    dek = crypto.generate_archive_password()
    dek_out = crypto.unwrap_key(
        priv_pem, crypto.wrap_key(cfg.recipient_public_pem.encode(), dek))
    assert dek_out == dek
    # the config never references the private key files
    raw = (tmp_path / CONFIG_NAME).read_bytes()
    assert b"recipient_private.pem" not in raw and b"signing_private.pem" not in raw
    # stdout: ids + fingerprints; the PRIVATE pem text never appears anywhere
    captured = capsys.readouterr()
    assert rec_id in captured.out and sig_id in captured.out
    assert priv_pem.decode("ascii").strip() not in captured.out
    assert sig_pem.decode("ascii").strip() not in captured.out
    assert "WARNING" in captured.err


@needs_crypto
def test_generate_job_keys_refuses_overwrite_without_force(tmp_path):
    write_config(tmp_path, "source: C:/Data\n")
    runner.generate_job_keys(tmp_path / CONFIG_NAME)
    orig_cfg = load_config(tmp_path / CONFIG_NAME)
    priv_before = (tmp_path / RECIPIENT_PRIVATE_NAME).read_bytes()
    sig_before = (tmp_path / SIGNING_PRIVATE_NAME).read_bytes()
    cfg_before = (tmp_path / CONFIG_NAME).read_bytes()

    with pytest.raises(ConfigError) as ei:
        runner.generate_job_keys(tmp_path / CONFIG_NAME)
    assert "--force" in str(ei.value)
    assert (tmp_path / RECIPIENT_PRIVATE_NAME).read_bytes() == priv_before
    assert (tmp_path / SIGNING_PRIVATE_NAME).read_bytes() == sig_before
    assert (tmp_path / CONFIG_NAME).read_bytes() == cfg_before

    # --force regenerates everything (fresh random keys -> ids change)
    runner.generate_job_keys(tmp_path / CONFIG_NAME, force=True)
    assert (tmp_path / CONFIG_NAME).read_bytes() != cfg_before
    new_cfg = load_config(tmp_path / CONFIG_NAME)
    assert new_cfg.encryption_enabled is True
    assert new_cfg.recipient_key_id != orig_cfg.recipient_key_id
    # old private files were REPLACED (force), old archives lose access
    assert (tmp_path / RECIPIENT_PRIVATE_NAME).read_bytes() != priv_before
    assert (tmp_path / SIGNING_PRIVATE_NAME).read_bytes() != sig_before


@needs_crypto
def test_keygen_cli_exit_codes(tmp_path, capsys):
    # no config.yaml -> exit 5
    empty = tmp_path / "empty"
    empty.mkdir()
    assert conftest.run_cli(["keygen", str(empty)]) == 5
    assert "config" in capsys.readouterr().err.lower()

    # happy path via the CLI
    job = tmp_path / "job"
    job.mkdir()
    (job / CONFIG_NAME).write_bytes(b"source: C:/Data\n")
    assert conftest.run_cli(["keygen", str(job)]) == 0
    assert (job / RECIPIENT_PRIVATE_NAME).is_file()
    assert (job / SIGNING_PRIVATE_NAME).is_file()
    assert load_config(job / CONFIG_NAME).encryption_enabled is True

    # refusing overwrite (no --force) -> exit 5
    assert conftest.run_cli(["keygen", str(job)]) == 5
    # --force on the CLI succeeds
    assert conftest.run_cli(["keygen", str(job), "--force"]) == 0


@needs_crypto
def test_init_generate_keys(tmp_path, capsys):
    job = tmp_path / "job"
    src = tmp_path / "src"
    src.mkdir()
    assert conftest.run_cli(["init", str(job), "--source", str(src), "--generate-keys"]) == 0
    assert (job / RECIPIENT_PRIVATE_NAME).is_file()
    assert (job / SIGNING_PRIVATE_NAME).is_file()
    cfg = load_config(job / CONFIG_NAME)
    assert cfg.encryption_enabled is True
    assert cfg.recipient_key_id and cfg.signing_key_id
    assert "created" in capsys.readouterr().out
    raw = (job / CONFIG_NAME).read_bytes()
    assert b"recipient_private.pem" not in raw and b"signing_private.pem" not in raw

@needs_crypto
def test_init_plain_has_no_key_files(tmp_path):
    job = tmp_path / "job"
    assert conftest.run_cli(["init", str(job)]) == 0
    assert not (job / RECIPIENT_PRIVATE_NAME).exists()
    assert not (job / SIGNING_PRIVATE_NAME).exists()
    # init does not run keygen -> the template carries no key config
    data = yaml.safe_load((job / CONFIG_NAME).read_text(encoding="utf-8"))
    assert "recipient_public_key" not in data and "signing_public_key" not in data


def test_cli_parser_smoke():
    from backuper.cli import build_parser
    parser = build_parser()
    a = parser.parse_args(["keygen", "somewhere", "--force"])
    assert a.command == "keygen" and a.dir == "somewhere" and a.force is True
    b = parser.parse_args(["init", "j", "--generate-keys"])
    assert b.command == "init" and b.generate_keys is True and not hasattr(b, "force")
    c = parser.parse_args(["password", "a.rar", "--keys-dir", "kd", "--rar", "r.exe"])
    assert c.command == "password" and c.archive == "a.rar" and c.keys_dir == "kd"
    assert c.rar == "r.exe"
    with pytest.raises(SystemExit) as ei:
        parser.parse_args(["keygen", "--nope"])
    assert ei.value.code == 2


def test_cli_help_smoke():
    with pytest.raises(SystemExit) as ei:
        conftest.run_cli(["keygen", "--help"])
    assert ei.value.code == 0
    with pytest.raises(SystemExit) as ei:
        conftest.run_cli(["password", "--help"])
    assert ei.value.code == 0


# ---------------------------------------------------------------------------
# password command (archive member reader stubbed)
# ---------------------------------------------------------------------------

class _FauxRunner:
    """Stand-in for RarRunner; the stubbed reader never uses it."""


@pytest.fixture()
def stubbed_member_reader(monkeypatch):
    """Replace rar member reads with an in-memory dict keyed by member name."""
    store: dict[str, bytes] = {}

    def fake_read_service_member(runner_obj, archive, member):
        if member not in store:
            raise RuntimeError(f"member {member!r} not in archive")
        return store[member]

    monkeypatch.setattr(runner, "read_service_member", fake_read_service_member)
    monkeypatch.setattr(runner, "_resolve_runner", lambda rar: (_FauxRunner(), "test"))
    return store


@needs_crypto
def test_password_command_prints_only_hex_password(
        tmp_path, stubbed_member_reader, capsys):
    manifest_json, sig_json, dek = write_encrypted_job(tmp_path)
    stubbed_member_reader[".backup/manifest.json"] = manifest_json
    stubbed_member_reader[MANIFEST_SIGNATURE_MEMBER] = sig_json
    archive = tmp_path / "epoch1" / "2026-11-07_010000_full.rar"
    archive.parent.mkdir()
    archive.write_bytes(b"RARC\xff")  # only needs to exist as a file

    assert conftest.run_cli(["password", str(archive),
                             "--recipient-private-key",
                             str(tmp_path / RECIPIENT_PRIVATE_NAME)]) == 0
    captured = capsys.readouterr()
    current_out = crypto.password_for_rar(dek).decode("ascii") + "\n"
    assert captured.out == current_out
    assert captured.err == ""


@needs_crypto
def test_extract_password_walks_up_to_job_dir(
        tmp_path, stubbed_member_reader, capsys):
    manifest_json, sig_json, dek = write_encrypted_job(tmp_path)
    stubbed_member_reader[".backup/manifest.json"] = manifest_json
    stubbed_member_reader[MANIFEST_SIGNATURE_MEMBER] = sig_json
    # deep nesting below the epoch dir; tmp_path itself holds config.yaml
    deep = tmp_path / "epoch1" / "sub"
    deep.mkdir(parents=True)
    archive = deep / "b.rar"
    archive.write_bytes(b"x")

    assert runner.extract_archive_password(
        archive,
        recipient_private_key_path=str(tmp_path / RECIPIENT_PRIVATE_NAME),
    ) == crypto.password_for_rar(dek)
    assert capsys.readouterr().out == ""


@needs_crypto
def test_password_command_bad_signature_exit3(
        tmp_path, stubbed_member_reader, capsys):
    manifest_json, sig_json, _ = write_encrypted_job(tmp_path, tamper=True)
    stubbed_member_reader[".backup/manifest.json"] = manifest_json
    stubbed_member_reader[MANIFEST_SIGNATURE_MEMBER] = sig_json
    archive = tmp_path / "bad.rar"
    archive.write_bytes(b"x")
    assert conftest.run_cli(["password", str(archive),
                             "--recipient-private-key",
                             str(tmp_path / RECIPIENT_PRIVATE_NAME)]) == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "signature" in captured.err.lower()


@needs_crypto
def test_password_command_unencrypted_archive_exit5(
        tmp_path, stubbed_member_reader, capsys):
    m = Manifest.from_json(manifest_dict())
    stubbed_member_reader[".backup/manifest.json"] = json_bytes(m.to_json())
    archive = tmp_path / "plain.rar"
    archive.write_bytes(b"x")
    assert conftest.run_cli(["password", str(archive)]) == 5
    assert "not encrypted" in capsys.readouterr().err


@needs_crypto
def test_password_command_wrong_recipient_key_exit5(
        tmp_path, stubbed_member_reader, capsys):
    manifest_json, sig_json, _ = write_encrypted_job(tmp_path)
    stubbed_member_reader[".backup/manifest.json"] = manifest_json
    stubbed_member_reader[MANIFEST_SIGNATURE_MEMBER] = sig_json
    archive = tmp_path / "gone.rar"
    archive.write_bytes(b"x")
    # replace the private key with a fresh, unrelated one
    fresh_priv, _, _ = crypto.generate_recipient_keypair()
    (tmp_path / RECIPIENT_PRIVATE_NAME).write_bytes(fresh_priv)
    assert conftest.run_cli(["password", str(archive),
                             "--recipient-private-key",
                             str(tmp_path / RECIPIENT_PRIVATE_NAME)]) == 5
    assert "password" in capsys.readouterr().err.lower()


@needs_crypto
def test_password_command_missing_pieces(tmp_path, stubbed_member_reader, capsys):
    # nonexistent archive path
    assert conftest.run_cli(["password", str(tmp_path / "no.rar")]) == 1
    assert "not found" in capsys.readouterr().err.lower()
    # no config anywhere above the archive -> exit 5 even for an encrypted one
    job = tmp_path / "job"
    manifest_json, sig_json, _ = write_encrypted_job(job)
    stubbed_member_reader[".backup/manifest.json"] = manifest_json
    stubbed_member_reader[MANIFEST_SIGNATURE_MEMBER] = sig_json
    orphan = tmp_path / "orphan"
    orphan.mkdir()
    archive = orphan / "a.rar"
    archive.write_bytes(b"x")
    assert conftest.run_cli(["password", str(archive)]) == 5
    assert "config" in capsys.readouterr().err.lower()


@needs_crypto
def test_password_keys_dir_override(tmp_path, stubbed_member_reader, capsys):
    manifest_json, sig_json, dek = write_encrypted_job(tmp_path)
    stubbed_member_reader[".backup/manifest.json"] = manifest_json
    stubbed_member_reader[MANIFEST_SIGNATURE_MEMBER] = sig_json
    # keys live in tmp_path; the archive sits somewhere without a config chain
    other = tmp_path / "elsewhere"
    other.mkdir()
    archive = other / "a.rar"
    archive.write_bytes(b"x")
    assert conftest.run_cli(
        ["password", str(archive), "--keys-dir", str(tmp_path)]) == 0
    assert capsys.readouterr().out == crypto.password_for_rar(dek).decode("ascii") + "\n"
