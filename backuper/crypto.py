"""Crypto layer: per-archive DEK wrapping and manifest signing.

Scheme (user-approved design):

- Every archive gets a RANDOM per-archive password, the DEK
  (:func:`generate_archive_password`, 32 random bytes). The DEK is
  deterministic in value only at generation time -- each run rolls a fresh
  one, so identical contents never imply identical encryption.
- The DEK is wrapped (encrypted) with the recipient's RSA-3072 public key
  (:func:`wrap_key`, RSA-OAEP with SHA-256) and stored, as JSON, inside the
  archive's metadata.
- The metadata is signed with an Ed25519 key (:func:`sign_bytes` /
  :func:`verify_bytes`); the signature is detached, computed over the EXACT
  bytes it covers (no canonical-JSON reshuffling).
- ``config.yaml`` holds PUBLIC keys only (PEM). Private keys live
  elsewhere (operator secrets) and are NEVER logged, never passed
  on the command line (argv is world-readable via process listings), and
  never embedded in archives. Only functions that explicitly take a
  private-PEM argument ever touch one, and none of them include it in an
  error message.

Key identifiers: a ``key_id`` is the first 16 bytes of SHA-256 over the
DER-encoded SubjectPublicKeyInfo, lowercased hex (32 chars) -- a short,
stable fingerprint used to match a wrapped key / signature to the
configured public key without trusting its self-declared identity.

Exceptions: this module carries its own tiny hierarchy rooted at
:class:`CryptoError` (KeyFormatError, DecryptionError, SignatureError). It
is deliberately local to avoid an edit conflict with
``backuper.errors``; a later integration wave may re-home the classes
under the ``BackuperError`` tree -- keep the names stable, they are
exported at module level.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

__all__ = [
    "CryptoError",
    "KeyFormatError",
    "DecryptionError",
    "SignatureError",
    "DEK_SIZE",
    "WRAP_ALGORITHM",
    "SIG_ALGORITHM",
    "PublicKey",
    "PrivateKey",
    "generate_recipient_keypair",
    "generate_signing_keypair",
    "load_public_pem",
    "load_private_pem",
    "key_id_for_public",
    "canonical_public_pem",
    "generate_archive_password",
    "password_for_rar",
    "wrap_key",
    "unwrap_key",
    "WrappedKey",
    "sign_bytes",
    "verify_bytes",
    "Signature",
]

# 32 random bytes -> 64-char lowercase hex, comfortably above RAR's
# practical password limits and printable over stdin without quoting.
DEK_SIZE = 32

# Literal algorithm tags stored alongside wrapped keys / signatures so
# manifests are self-describing and forward-compatible.
WRAP_ALGORITHM = "RSA-OAEP-SHA256"
SIG_ALGORITHM = "Ed25519"

PublicKey = rsa.RSAPublicKey | ed25519.Ed25519PublicKey
PrivateKey = rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey


# ---------------------------------------------------------------------------
# Exceptions (local hierarchy; may be re-homed with backuper.errors later)
# ---------------------------------------------------------------------------

class CryptoError(Exception):
    """Base class for all crypto-layer errors."""


class KeyFormatError(CryptoError):
    """A key (PEM) could not be parsed or has the wrong type."""


class DecryptionError(CryptoError):
    """Unwrapping a DEK failed: wrong recipient key or corrupted data."""


class SignatureError(CryptoError):
    """Signature verification failed: bad key, wrong key id, or bad sig."""


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def _serialize_pem(key: Any, *, private: bool) -> bytes:
    """PEM-encode a key, PKCS8 (private keys with no passphrase)."""
    if private:
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def generate_recipient_keypair() -> tuple[bytes, bytes, str]:
    """Generate an RSA-3072 recipient keypair for DEK wrapping.

    Returns ``(private_pem, public_pem, key_id)``; PEM is PKCS8 / SPKI
    respectively. The private PEM is OAEP-capable by construction.
    """
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = _serialize_pem(private, private=True)
    public_pem = _serialize_pem(private.public_key(), private=False)
    return private_pem, public_pem, key_id_for_public(private.public_key())


def generate_signing_keypair() -> tuple[bytes, bytes, str]:
    """Generate an Ed25519 signing keypair for manifest signatures.

    Returns ``(private_pem, public_pem, key_id)``; PEM is PKCS8 / SPKI.
    """
    private = ed25519.Ed25519PrivateKey.generate()
    private_pem = _serialize_pem(private, private=True)
    public_pem = _serialize_pem(private.public_key(), private=False)
    return private_pem, public_pem, key_id_for_public(private.public_key())


def key_id_for_public(public: Any) -> str:
    """Stable short fingerprint: SHA-256[:16] of the DER SPKI, lowercase hex."""
    der = public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).digest()[:16].hex()


def canonical_public_pem(data: bytes) -> bytes:
    """Canonicalize a public-key PEM by loading and re-serializing it.

    YAML-stored keys may differ in trailing newline / spacing; the
    canonical form makes them byte-comparable.
    """
    return _serialize_pem(load_public_pem(data), private=False)


# ---------------------------------------------------------------------------
# Load / parse
# ---------------------------------------------------------------------------

def _parse_public(data: bytes) -> Any:
    """Parse PEM input (strip surrounding whitespace); raise on failure."""
    try:
        return serialization.load_pem_public_key(data.strip())
    except (ValueError, TypeError) as exc:
        raise KeyFormatError(f"invalid PEM public key: {exc.__class__.__name__}") from exc


def _parse_private(data: bytes) -> Any:
    """Parse unencrypted PEM input (strip surrounding whitespace)."""
    try:
        return serialization.load_pem_private_key(data.strip(), password=None)
    except (ValueError, TypeError) as exc:
        raise KeyFormatError(f"invalid PEM private key: {exc.__class__.__name__}") from exc


def load_public_pem(data: bytes) -> PublicKey:
    """Load a PEM public key (RSA or Ed25519); tolerant to stray whitespace."""
    if isinstance(data, str):
        data = data.encode("ascii", errors="strict")
    return _parse_public(data)


def load_private_pem(data: bytes) -> PrivateKey:
    """Load a PEM private key (RSA or Ed25519); tolerant to stray whitespace."""
    if isinstance(data, str):
        data = data.encode("ascii", errors="strict")
    key = _parse_private(data)
    if isinstance(key, (rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey)):
        return key
    raise KeyFormatError(
        f"unsupported private key type {key.__class__.__name__}"
    )


# ---------------------------------------------------------------------------
# DEK generation and RAR password derivation
# ---------------------------------------------------------------------------

def generate_archive_password() -> bytes:
    """Generate a fresh random DEK for one archive (``secrets.token_bytes``)."""
    return secrets.token_bytes(DEK_SIZE)


def password_for_rar(dek: bytes) -> bytes:
    """Derive the exact password bytes handed to RAR: 64-char lowercase hex.

    Injective and constant for a given DEK, so the ``(DEK, password)`` pair
    round-trips: whoever holds the unwrapped DEK reconstructs the same
    password deterministically.
    """
    if len(dek) != DEK_SIZE:
        raise KeyFormatError(f"expected a {DEK_SIZE}-byte DEK, got {len(dek)}")
    return dek.hex().encode("ascii")


# ---------------------------------------------------------------------------
# WrappedKey (dataclass)
# ---------------------------------------------------------------------------

@dataclass
class WrappedKey:
    """An archive DEK wrapped for one recipient, embeddable in a manifest."""

    algorithm: str = WRAP_ALGORITHM
    recipient_key_id: str = ""
    wrapped: str = ""  # base64 of the RSA-OAEP ciphertext

    def to_json(self) -> dict[str, str]:
        """Return a small plain dict (JSON-ready) for manifest metadata."""
        return {
            "algorithm": self.algorithm,
            "recipient_key_id": self.recipient_key_id,
            "wrapped": self.wrapped,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any] | str) -> WrappedKey:
        """Build a :class:`WrappedKey` from a dict or its JSON string."""
        raw: Any = data
        if isinstance(raw, (str, bytes)):
            try:
                raw = json.loads(raw)
            except ValueError as exc:
                raise KeyFormatError("WrappedKey JSON is not valid JSON") from exc
        if not isinstance(raw, Mapping):
            raise KeyFormatError("WrappedKey must be a JSON object")
        algorithm = raw.get("algorithm")
        if algorithm != WRAP_ALGORITHM:
            raise KeyFormatError(f"unsupported wrap algorithm {algorithm!r}")
        wrapped = raw.get("wrapped")
        if not isinstance(wrapped, str):
            raise KeyFormatError("WrappedKey 'wrapped' must be a base64 string")
        try:
            base64.b64decode(wrapped, validate=True, altchars=None)
        except ValueError as exc:
            raise KeyFormatError("WrappedKey 'wrapped' is not valid base64") from exc
        return cls(
            algorithm=WRAP_ALGORITHM,
            recipient_key_id=str(raw.get("recipient_key_id", "")),
            wrapped=wrapped,
        )


def wrap_key(recipient_public_pem_bytes: bytes, dek: bytes) -> WrappedKey:
    """Wrap ``dek`` with an RSA-OAEP-SHA256 public key.

    The DEK is never stored in the clear anywhere; only the RSA-OAEP
    ciphertext ends up in the manifest metadata.
    """
    public = load_public_pem(recipient_public_pem_bytes)
    if not isinstance(public, rsa.RSAPublicKey):
        raise KeyFormatError(
            f"recipient key must be RSA, got {public.__class__.__name__}"
        )
    try:
        ct = public.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise DecryptionError(f"cannot wrap key: {exc.__class__.__name__}") from exc
    return WrappedKey(
        algorithm=WRAP_ALGORITHM,
        recipient_key_id=key_id_for_public(public),
        wrapped=base64.b64encode(ct).decode("ascii"),
    )


def unwrap_key(private_pem: bytes, wrapped: WrappedKey) -> bytes:
    """Unwrap a DEK with the recipient's RSA private key.

    Raises :class:`DecryptionError` when the recipient key id does not
    match :attr:`WrappedKey.recipient_key_id` or decryption fails
    (wrong key, corrupted data). The error message never includes the
    private key material.
    """
    private = load_private_pem(private_pem)
    if not isinstance(private, rsa.RSAPrivateKey):
        raise DecryptionError(
            f"recipient private key must be RSA, got {private.__class__.__name__}"
        )
    pub_id = key_id_for_public(private.public_key())
    if wrapped.recipient_key_id != pub_id:
        raise DecryptionError(
            f"wrapped key is for recipient {wrapped.recipient_key_id}, "
            f"not this key {pub_id}"
        )
    try:
        ct = base64.b64decode(wrapped.wrapped, validate=True)
    except ValueError as exc:
        raise DecryptionError("wrapped key payload is not valid base64") from exc
    try:
        return private.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise DecryptionError(f"cannot unwrap key: {exc.__class__.__name__}") from exc


# ---------------------------------------------------------------------------
# Signature (dataclass)
# ---------------------------------------------------------------------------

@dataclass
class Signature:
    """A detached Ed25519 signature over exact bytes, embeddable in a manifest."""

    algorithm: str = SIG_ALGORITHM
    signing_key_id: str = ""
    signature: str = ""  # base64 of the 64-byte Ed25519 signature

    def to_json(self) -> dict[str, str]:
        """Return a small plain dict (JSON-ready) for manifest metadata."""
        return {
            "algorithm": self.algorithm,
            "signing_key_id": self.signing_key_id,
            "signature": self.signature,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any] | str) -> Signature:
        """Build a :class:`Signature` from a dict or its JSON string."""
        raw: Any = data
        if isinstance(raw, (str, bytes)):
            try:
                raw = json.loads(raw)
            except ValueError as exc:
                raise KeyFormatError("Signature JSON is not valid JSON") from exc
        if not isinstance(raw, Mapping):
            raise KeyFormatError("Signature must be a JSON object")
        algorithm = raw.get("algorithm")
        if algorithm != SIG_ALGORITHM:
            raise KeyFormatError(f"unsupported signature algorithm {algorithm!r}")
        sig = raw.get("signature")
        if not isinstance(sig, str):
            raise KeyFormatError("Signature 'signature' must be a base64 string")
        try:
            decoded = base64.b64decode(sig, validate=True)
        except ValueError as exc:
            raise KeyFormatError("Signature 'signature' is not valid base64") from exc
        if len(decoded) != 64:
            raise KeyFormatError("Ed25519 signature must be 64 bytes long")
        return cls(
            algorithm=SIG_ALGORITHM,
            signing_key_id=str(raw.get("signing_key_id", "")),
            signature=sig,
        )


# ---------------------------------------------------------------------------
# Sign / verify (detached, over EXACT bytes)
# ---------------------------------------------------------------------------

def sign_bytes(signing_private_pem: bytes, data: bytes) -> Signature:
    """Sign ``data`` (exact bytes, no canonicalization) with an Ed25519 key."""
    private = load_private_pem(signing_private_pem)
    if not isinstance(private, ed25519.Ed25519PrivateKey):
        raise SignatureError(
            f"signing key must be Ed25519, got {private.__class__.__name__}"
        )
    raw = private.sign(data)
    return Signature(
        algorithm=SIG_ALGORITHM,
        signing_key_id=key_id_for_public(private.public_key()),
        signature=base64.b64encode(raw).decode("ascii"),
    )


def verify_bytes(signing_public_pem: bytes, data: bytes, sig: Signature) -> None:
    """Verify a detached signature over exact ``data`` bytes.

    Raises :class:`SignatureError` on a bad key, a key-id mismatch against
    the supplied public key, or an invalid signature.
    """
    public = load_public_pem(signing_public_pem)
    if not isinstance(public, ed25519.Ed25519PublicKey):
        raise SignatureError(
            f"signing key must be Ed25519, got {public.__class__.__name__}"
        )
    if sig.signing_key_id != key_id_for_public(public):
        raise SignatureError(
            f"signature claims key {sig.signing_key_id}, "
            f"configured signing key is {key_id_for_public(public)}"
        )
    try:
        raw = base64.b64decode(sig.signature, validate=True)
    except ValueError as exc:
        raise SignatureError("signature payload is not valid base64") from exc
    try:
        public.verify(raw, data)
    except InvalidSignature as exc:
        raise SignatureError("signature verification failed") from exc
