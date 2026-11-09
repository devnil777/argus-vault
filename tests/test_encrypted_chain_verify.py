"""Encrypted chain/verify unit tests -- synthetic manifests, no Rar.exe.

Builds manifest JSON bytes via :mod:`backuper.models` and a real test
signing pair, then exercises the verify-layer helpers
(:func:`backuper.verify.verify_manifest_signature`,
:func:`backuper.verify.resolve_archive_password`). Everything here is
pure python; the module never needs Rar.exe.
"""

import json
import uuid

import pytest

from backuper import crypto
from backuper.errors import VerificationError
from backuper.models import ENCRYPTION_DATA, Manifest, json_bytes
from backuper.verify import ArchiveUnlockError, resolve_archive_password, verify_manifest_signature


@pytest.fixture(scope="module")
def recipient():
    """(private_pem, public_pem, key_id) of one RSA recipient pair."""
    return crypto.generate_recipient_keypair()


@pytest.fixture(scope="module")
def signer():
    """(private_pem, public_pem, key_id) of one Ed25519 signer pair."""
    return crypto.generate_signing_keypair()


def _manifest(*, recipient=None, signer=None, dek=None,
              extra_wrapped=None) -> Manifest:
    """A synthetic encrypted manifest wrapping ``dek`` for ``recipient``."""
    wrapped = None
    if recipient is not None:
        if dek is None:
            dek = crypto.generate_archive_password()
        wrapped = [crypto.wrap_key(recipient[1], dek).to_json()]
        if extra_wrapped is not None:
            wrapped += extra_wrapped
    return Manifest(
        manifest_id=str(uuid.uuid4()),
        filename="2026-01-01_000000_full.rar",
        archive_type="full",
        created_utc="2026-01-01T00:00:00.0000000Z",
        config_name="config.yaml",
        config_sha256="0" * 64,
        script_version="0.2.0",
        rar_version="7.22",
        sources=["C:/nonexistent-source"],
        base_full=None,
        previous_manifest_id=None,
        previous_filename=None,
        excludes={"extensions": [], "dirs": []},
        added_empty_dirs=[],
        counters={"files": 0, "empty_dirs": 0, "skipped": 0, "bytes": 0,
                  "deleted_files": 0, "deleted_dirs": 0, "added_empty_dirs": 0},
        encryption=ENCRYPTION_DATA if wrapped is not None else None,
        wrapped_keys=wrapped,
        signing_key_id=(signer[2] if signer is not None else None),
    )


def _member_bytes(manifest: Manifest) -> bytes:
    """The EXACT manifest.json member bytes a signature would cover."""
    return json_bytes(manifest.to_json())


def _signed_manifest_bytes(signer) -> tuple[Manifest, bytes, bytes]:
    """(manifest, manifest member bytes, sig member bytes)."""
    manifest = _manifest(signer=signer)
    raw = _member_bytes(manifest)
    sig = crypto.sign_bytes(signer[0], raw)
    return manifest, raw, json_bytes(sig.to_json())


# ---------------------------------------------------------------------------
# verify_manifest_signature (raises crypto.SignatureError on any failure)
# ---------------------------------------------------------------------------

def test_signature_verifies_ok(signer):
    manifest, raw, sig_bytes = _signed_manifest_bytes(signer)
    verify_manifest_signature(raw, sig_bytes, signer[1])   # raises on failure


def test_signature_tampered_manifest_rejected(signer):
    manifest, raw, sig_bytes = _signed_manifest_bytes(signer)
    # flip exactly one manifest byte: every sensible mutation fails
    tampered = raw[:10] + bytes([raw[10] ^ 1]) + raw[11:]
    with pytest.raises(crypto.SignatureError):
        verify_manifest_signature(tampered, sig_bytes, signer[1])


def test_signature_wrong_trusted_key_rejected(signer):
    manifest, raw, sig_bytes = _signed_manifest_bytes(signer)
    other = crypto.generate_signing_keypair()
    with pytest.raises(crypto.SignatureError):
        verify_manifest_signature(raw, sig_bytes, other[1])


def test_signature_invalid_sig_member_rejected(signer):
    manifest, raw, _sig = _signed_manifest_bytes(signer)
    sig = {
        "algorithm": crypto.SIG_ALGORITHM,
        "signing_key_id": signer[2],
        "signature": "==== not base64 ====",
    }
    with pytest.raises(crypto.SignatureError, match="invalid"):
        verify_manifest_signature(raw, json_bytes(sig), signer[1])


def test_signature_corrupt_sig_char_rejected(signer):
    manifest, raw, _sig = _signed_manifest_bytes(signer)
    good_sig = json.loads(json_bytes(crypto.sign_bytes(signer[0], raw).to_json()))
    good_sig["signature"] = good_sig["signature"][:-1] + (
        "A" if good_sig["signature"][-1] != "A" else "B")
    with pytest.raises(crypto.SignatureError):
        verify_manifest_signature(raw, json_bytes(good_sig), signer[1])


def test_signature_non_utf8_member_rejected(signer):
    manifest, raw, _sig = _signed_manifest_bytes(signer)
    with pytest.raises(crypto.SignatureError, match="UTF-8"):
        verify_manifest_signature(raw, b"\xff\xfe garbage", signer[1])


def test_signature_key_id_mismatch_rejected(signer):
    manifest, raw, _sig = _signed_manifest_bytes(signer)
    sig = crypto.sign_bytes(signer[0], raw)
    wrong_id = dict(sig.to_json(), signing_key_id="a" * 32)
    with pytest.raises(crypto.SignatureError, match="claims key"):
        verify_manifest_signature(raw, json_bytes(wrong_id), signer[1])


# ---------------------------------------------------------------------------
# resolve_archive_password (unwrap -> DEK -> RAR password)
# ---------------------------------------------------------------------------

def test_resolve_password_round_trip(recipient, signer):
    dek = crypto.generate_archive_password()
    manifest = _manifest(recipient=recipient, signer=signer, dek=dek)
    password = resolve_archive_password(
        manifest, recipient[0], recipient[2])
    assert password == crypto.password_for_rar(dek)
    assert len(password) == 64


def test_resolve_password_prefers_matching_key_id(recipient, signer):
    dek = crypto.generate_archive_password()
    # prepend a foreign wrapped key; the matching-id entry must win
    other = crypto.generate_recipient_keypair()
    other_wrapped = crypto.wrap_key(other[1], b"B" * crypto.DEK_SIZE).to_json()
    manifest = _manifest(recipient=recipient, signer=signer, dek=dek,
                         extra_wrapped=[other_wrapped])
    raw_wrapped = manifest.wrapped_keys
    manifest.wrapped_keys = [other_wrapped, raw_wrapped[0]]
    password = resolve_archive_password(manifest, recipient[0], recipient[2])
    assert password == crypto.password_for_rar(dek)


def test_resolve_password_falls_back_to_first_entry(recipient, signer):
    dek = crypto.generate_archive_password()
    manifest = _manifest(recipient=recipient, signer=signer, dek=dek)
    resolve_archive_password(manifest, recipient[0], None)   # no pinned id


def test_resolve_password_wrong_recipient_key_is_wrapped_error(recipient, signer):
    dek = crypto.generate_archive_password()
    manifest = _manifest(recipient=recipient, signer=signer, dek=dek)
    other = crypto.generate_recipient_keypair()
    with pytest.raises(ArchiveUnlockError) as ei:
        resolve_archive_password(manifest, other[0], recipient[2])
    assert ei.value.exit_code == 3
    assert isinstance(ei.value, VerificationError)
    # nothing secret in the message
    assert dek.hex() not in str(ei.value)


def test_resolve_password_no_wrapped_keys_is_wrapped_error(signer):
    manifest = _manifest(signer=signer)
    manifest.wrapped_keys = None
    with pytest.raises(ArchiveUnlockError, match="wrapped_keys"):
        resolve_archive_password(manifest, b"unused")


def test_resolve_password_malformed_wrapped_key_is_wrapped_error(recipient, signer):
    manifest = _manifest(recipient=recipient, signer=signer)
    manifest.wrapped_keys = [{"recipient_key_id": recipient[2],
                              "wrapped": b"{OOPS"}]   # invalid base64
    with pytest.raises(ArchiveUnlockError, match="wrapped key data is invalid"):
        resolve_archive_password(manifest, recipient[0], recipient[2])


def test_resolve_password_corrupted_ciphertext_is_wrapped_error(recipient, signer):
    import base64
    dek = crypto.generate_archive_password()
    manifest = _manifest(recipient=recipient, signer=signer, dek=dek)
    wrapped = crypto.wrap_key(recipient[1], dek)
    raw = bytearray(base64.b64decode(wrapped.wrapped))
    raw[10] ^= 0xFF
    manifest.wrapped_keys = [dict(wrapped.to_json(),
                                  wrapped=base64.b64encode(bytes(raw)).decode("ascii"))]
    with pytest.raises(ArchiveUnlockError, match="unwrap"):
        resolve_archive_password(manifest, recipient[0], recipient[2])


def test_resolve_password_missing_private_pem_is_wrapped_error(recipient, signer):
    dek = crypto.generate_archive_password()
    manifest = _manifest(recipient=recipient, signer=signer, dek=dek)
    with pytest.raises(ArchiveUnlockError, match="unwrap"):
        resolve_archive_password(manifest, b"not a pem", recipient[2])


def test_manifest_encryption_envelope_round_trips(signer, recipient):
    """Manifest from/to_json keeps the additive envelope fields intact."""
    dek = crypto.generate_archive_password()
    manifest = _manifest(recipient=recipient, signer=signer, dek=dek)
    rebuilt = Manifest.from_json(json.loads(_member_bytes(manifest)))
    assert rebuilt.encryption == ENCRYPTION_DATA
    assert rebuilt.signing_key_id == manifest.signing_key_id
    assert rebuilt.wrapped_keys == manifest.wrapped_keys
