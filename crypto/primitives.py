"""Cryptographic primitives — thin wrappers over the `cryptography` library.

Responsibilities (Criterion 2: Cryptographic Correctness):
  - Ed25519: long-term identity signing / verification
  - X25519:  ephemeral ECDH key agreement
  - HKDF-SHA256: derive session key(s) from the shared secret
  - ChaCha20-Poly1305: AEAD encrypt / decrypt with associated data

Rules:
  - All randomness comes from the library's CSPRNG (os.urandom).
  - Nonces are NEVER reused under the same key (the caller derives a unique
    nonce per message from a monotonic counter; see client/session.py).
  - No primitive is hand-rolled; we only compose vetted building blocks.

All public keys cross the wire / are stored as raw bytes:
  - Ed25519 / X25519 public keys: 32 bytes (raw)
  - ChaCha20-Poly1305 key: 32 bytes; nonce: 12 bytes
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from protocol.constants import AEAD_KEY_LEN, AEAD_NONCE_LEN


# --- Errors -----------------------------------------------------------------

class CryptoError(Exception):
    """Raised when an authenticity/integrity check fails (reject the input)."""


# --- Identity (Ed25519) -----------------------------------------------------

def generate_identity_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a long-term Ed25519 identity key pair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign `message` with an Ed25519 private key. Returns a 64-byte signature."""
    return private_key.sign(message)


def verify(public_key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True iff valid (never raises)."""
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


# --- Key agreement (X25519) -------------------------------------------------

def generate_ephemeral_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an ephemeral X25519 key pair (one per session: forward secrecy)."""
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def x25519_shared_secret(
    my_private: X25519PrivateKey, peer_public: X25519PublicKey
) -> bytes:
    """Compute the raw X25519 shared secret (32 bytes).

    Note: the raw secret is NOT used directly as a key; it is always passed
    through HKDF (`derive_session_key`) to produce uniform key material.
    """
    return my_private.exchange(peer_public)


# --- Key derivation (HKDF-SHA256) ------------------------------------------

def derive_session_key(
    shared_secret: bytes,
    salt: bytes,
    info: bytes,
    length: int = AEAD_KEY_LEN,
) -> bytes:
    """Derive key material from a shared secret using HKDF-SHA256.

    `info` binds the derived key to a specific protocol/purpose; `salt` should
    be fresh per handshake (e.g. both ephemeral public keys) to diversify
    output across sessions.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(shared_secret)


# --- AEAD (ChaCha20-Poly1305) ----------------------------------------------

def aead_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes
) -> bytes:
    """AEAD-encrypt `plaintext`. Returns ciphertext with the appended tag.

    `associated_data` is authenticated but not encrypted; the caller binds it
    to sender‖recipient‖session_id‖counter so a ciphertext cannot be replayed
    into a different context.
    """
    if len(key) != AEAD_KEY_LEN:
        raise ValueError(f"key must be {AEAD_KEY_LEN} bytes")
    if len(nonce) != AEAD_NONCE_LEN:
        raise ValueError(f"nonce must be {AEAD_NONCE_LEN} bytes")
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, associated_data)


def aead_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes
) -> bytes:
    """AEAD-decrypt and verify. Raises CryptoError if the tag/AD is invalid.

    A failure here means integrity (SR2) or authenticity (SR3) was violated;
    the caller MUST reject the message and not use any partial output.
    """
    if len(key) != AEAD_KEY_LEN:
        raise ValueError(f"key must be {AEAD_KEY_LEN} bytes")
    if len(nonce) != AEAD_NONCE_LEN:
        raise ValueError(f"nonce must be {AEAD_NONCE_LEN} bytes")
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise CryptoError("AEAD authentication failed") from exc


def random_bytes(n: int) -> bytes:
    """Return `n` cryptographically secure random bytes."""
    return os.urandom(n)


# --- Serialization helpers --------------------------------------------------

def public_key_to_bytes(
    public_key: Ed25519PublicKey | X25519PublicKey,
) -> bytes:
    """Serialize an Ed25519/X25519 public key to its 32-byte raw form."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed25519_public_from_bytes(data: bytes) -> Ed25519PublicKey:
    """Parse a raw 32-byte Ed25519 public key."""
    return Ed25519PublicKey.from_public_bytes(data)


def identity_private_to_bytes(private_key: Ed25519PrivateKey) -> bytes:
    """Serialize an Ed25519 private key to its 32-byte raw form (local storage)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def identity_private_from_bytes(data: bytes) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from its raw 32-byte form."""
    return Ed25519PrivateKey.from_private_bytes(data)


def x25519_public_from_bytes(data: bytes) -> X25519PublicKey:
    """Parse a raw 32-byte X25519 public key."""
    return X25519PublicKey.from_public_bytes(data)
