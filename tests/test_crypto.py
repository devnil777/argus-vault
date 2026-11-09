"""Unit tests for backuper.crypto: keygen, DEK wrap/unwrap, signing."""

import base64
import json
import re

import pytest

from backuper.crypto import (
    DEK_SIZE,
    SIG_ALGORITHM,
    WRAP_ALGORITHM,
    DecryptionError,
    KeyFormatError,
    Signature,
    SignatureError,
    WrappedKey,
    canonical_public_pem,
    generate_archive_password,
    generate_recipient_keypair,
    generate_signing_keypair,
    key_id_for_public,
    load_private_pem,
    load_public_pem,
    password_for_rar,
    sign_bytes,
    unwrap_key,
    verify_bytes,
    wrap_key,
)

_DATA = b"exact bytes to protect, no canonicalization"
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_KEY_ID_RE = re.compile(r"^[0-9a-f]{32}$", re.ASCII)


@pytest.fixture(scope="module")
def recipient():
    """One RSA recipient keypair reused across the module (keygen is slow)."""
    return generate_recipient_keypair()


@pytest.fixture(scope="module")
def signer():
    """One Ed25519 signing keypair reused across the module."""
    return generate_signing_keypair()


# ---------------------------------------------------------------------------
# Key generation / loading / key ids
# ---------------------------------------------------------------------------

def test_recipient_keypair_pem_and_key_id(recipient):
    private_pem, public_pem, key_id = recipient
    assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert _KEY_ID_RE.fullmatch(key_id)

    public = load_public_pem(public_pem)
    assert key_id_for_public(public) == key_id


def test_signing_keypair_pem_and_key_id(signer):
    private_pem, public_pem, key_id = signer
    assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert _KEY_ID_RE.fullmatch(key_id)
    assert key_id_for_public(load_public_pem(public_pem)) == key_id


def test_key_id_stable_across_calls_and_files(signer, tmp_path):
    _, public_pem, key_id = signer
    key_file = tmp_path / "signing.pub"
    key_file.write_bytes(public_pem)
    reread = key_file.read_bytes()
    assert key_id_for_public(load_public_pem(reread)) == key_id
    # Same key bytes -> same id, independent of the object instance.
    assert key_id_for_public(load_public_pem(public_pem)) == key_id_for_public(
        load_public_pem(public_pem)
    )


def test_canonical_public_pem_makes_yaml_keys_byte_equal(recipient):
    _, public_pem, _ = recipient
    assert canonical_public_pem(public_pem + b"\n") == canonical_public_pem(public_pem)
    assert canonical_public_pem(public_pem).endswith(b"-----END PUBLIC KEY-----\n")


def test_load_public_pem_tolerant_to_trailing_newline(recipient):
    _, public_pem, key_id = recipient
    assert key_id_for_public(load_public_pem(public_pem)) == key_id
    assert key_id_for_public(load_public_pem(public_pem.strip())) == key_id


def test_load_public_pem_garbage_raises_key_format_error():
    with pytest.raises(KeyFormatError):
        load_public_pem(b"not a pem at all")


def test_load_private_pem_garbage_raises_key_format_error(recipient):
    with pytest.raises(KeyFormatError):
        load_private_pem(b"-----BEGIN PRIVATE KEY-----\ngarbage\n-----END-----\n")


# ---------------------------------------------------------------------------
# DEK generation and RAR password derivation
# ---------------------------------------------------------------------------

def test_generate_archive_password_shape_and_uniqueness():
    dek1 = generate_archive_password()
    dek2 = generate_archive_password()
    assert len(dek1) == DEK_SIZE
    assert dek1 != dek2


def test_password_for_rar_is_lower_hex_64_and_matches_dek_hex():
    dek = generate_archive_password()
    password = password_for_rar(dek)
    assert _HEX64_RE.fullmatch(password.decode("ascii"))
    assert password == dek.hex().encode("ascii")


# ---------------------------------------------------------------------------
# Wrap / unwrap
# ---------------------------------------------------------------------------

def test_wrap_unwrap_round_trip(recipient):
    private_pem, public_pem, _ = recipient
    dek = generate_archive_password()
    wrapped = wrap_key(public_pem, dek)
    assert unwrap_key(private_pem, wrapped) == dek


def test_wrap_key_fields_and_constants(recipient):
    _, public_pem, key_id = recipient
    wrapped = wrap_key(public_pem, b"\x01" * DEK_SIZE)
    assert wrapped.algorithm == WRAP_ALGORITHM == "RSA-OAEP-SHA256"
    assert wrapped.recipient_key_id == key_id
    # base64 payload decodes to ciphertext of roughly RSA-3072 size.
    assert len(base64.b64decode(wrapped.wrapped)) == 384


def test_unwrap_with_wrong_private_key_raises(recipient, tmp_path):
    private_pem, public_pem, _ = recipient
    other_private, _, _ = generate_recipient_keypair()
    wrapped = wrap_key(public_pem, generate_archive_password())
    with pytest.raises(DecryptionError):
        unwrap_key(other_private, wrapped)


def test_unwrap_with_corrupted_ciphertext_raises(recipient):
    private_pem, public_pem, _ = recipient
    wrapped = wrap_key(public_pem, generate_archive_password())
    ct = bytearray(base64.b64decode(wrapped.wrapped))
    ct[0] ^= 0xFF
    wrapped.wrapped = base64.b64encode(bytes(ct)).decode("ascii")
    with pytest.raises(DecryptionError):
        unwrap_key(private_pem, wrapped)


def test_unwrap_key_id_mismatch_raises_without_rsa_work(recipient):
    private_pem, _, _ = recipient
    wrapped = WrappedKey(
        algorithm=WRAP_ALGORITHM,
        recipient_key_id="0" * 32,
        wrapped=base64.b64encode(b"\x00" * 384).decode("ascii"),
    )
    with pytest.raises(DecryptionError):
        unwrap_key(private_pem, wrapped)


# ---------------------------------------------------------------------------
# WrappedKey <-> JSON
# ---------------------------------------------------------------------------

def test_wrapped_key_json_round_trip_dict_and_string(recipient):
    _, public_pem, key_id = recipient
    wrapped = wrap_key(public_pem, generate_archive_password())

    obj = wrapped.to_json()
    assert obj == {"algorithm": WRAP_ALGORITHM, "recipient_key_id": key_id,
                   "wrapped": wrapped.wrapped}
    assert WrappedKey.from_json(obj) == wrapped

    text = json.dumps(obj)
    assert WrappedKey.from_json(text) == wrapped
    assert WrappedKey.from_json(obj).to_json() == obj


def test_wrapped_key_json_rejects_bad_shapes():
    with pytest.raises(KeyFormatError):
        WrappedKey.from_json({"algorithm": "RSA-PKCS1", "wrapped": ""})
    with pytest.raises(KeyFormatError):
        WrappedKey.from_json("not json")
    with pytest.raises(KeyFormatError):
        WrappedKey.from_json({"algorithm": WRAP_ALGORITHM, "wrapped": "%%%not-b64%%%"})


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------

def test_sign_verify_round_trip(signer):
    private_pem, public_pem, key_id = signer
    sig = sign_bytes(private_pem, _DATA)
    assert sig.algorithm == SIG_ALGORITHM == "Ed25519"
    assert sig.signing_key_id == key_id
    assert len(base64.b64decode(sig.signature)) == 64
    verify_bytes(public_pem, _DATA, sig)  # must not raise


def test_verify_bytes_is_detached_over_exact_bytes(signer):
    private_pem, public_pem, _ = signer
    sig = sign_bytes(private_pem, _DATA)
    verify_bytes(public_pem, _DATA + b"", sig)
    with pytest.raises(SignatureError):
        verify_bytes(public_pem, _DATA + b" tampered", sig)


def test_verify_with_wrong_public_key_raises(signer):
    private_pem, _, _ = signer
    other_private, other_public, _ = generate_signing_keypair()
    sig = sign_bytes(private_pem, _DATA)
    with pytest.raises(SignatureError):
        verify_bytes(other_public, _DATA, sig)


def test_verify_key_id_mismatch_raises(signer):
    _, public_pem, _ = signer
    sig = Signature(
        algorithm=SIG_ALGORITHM,
        signing_key_id="f" * 32,
        signature=base64.b64encode(b"\x00" * 64).decode("ascii"),
    )
    with pytest.raises(SignatureError):
        verify_bytes(public_pem, _DATA, sig)


def test_signature_json_round_trip_dict_and_string(signer):
    private_pem, public_pem, key_id = signer
    sig = sign_bytes(private_pem, _DATA)

    obj = sig.to_json()
    assert obj == {"algorithm": SIG_ALGORITHM, "signing_key_id": key_id,
                   "signature": sig.signature}
    assert Signature.from_json(obj) == sig

    text = json.dumps(obj)
    assert Signature.from_json(text) == sig

    verify_bytes(public_pem, _DATA, Signature.from_json(obj))


def test_signature_json_rejects_bad_lengths():
    with pytest.raises(KeyFormatError):
        Signature.from_json({"algorithm": SIG_ALGORITHM, "signature": "AAAA"})  # 3 bytes
    with pytest.raises(KeyFormatError):
        Signature.from_json({"algorithm": "RSA-PSS", "signature": "AAAA"})
    with pytest.raises(KeyFormatError):
        Signature.from_json([1, 2, 3])
