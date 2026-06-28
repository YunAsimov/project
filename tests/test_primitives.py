"""Tests for crypto/primitives.py and crypto/fingerprint.py."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import fingerprint, primitives
from crypto.primitives import CryptoError


# --- Ed25519 ----------------------------------------------------------------

def test_sign_verify_roundtrip():
    priv, pub = primitives.generate_identity_keypair()
    msg = b"handshake material"
    sig = primitives.sign(priv, msg)
    assert primitives.verify(pub, sig, msg) is True


def test_verify_rejects_wrong_message():
    priv, pub = primitives.generate_identity_keypair()
    sig = primitives.sign(priv, b"original")
    assert primitives.verify(pub, sig, b"tampered") is False


def test_verify_rejects_wrong_key():
    priv, _ = primitives.generate_identity_keypair()
    _, other_pub = primitives.generate_identity_keypair()
    sig = primitives.sign(priv, b"msg")
    assert primitives.verify(other_pub, sig, b"msg") is False


# --- X25519 + HKDF ----------------------------------------------------------

def test_x25519_both_sides_agree():
    a_priv, a_pub = primitives.generate_ephemeral_keypair()
    b_priv, b_pub = primitives.generate_ephemeral_keypair()
    assert primitives.x25519_shared_secret(a_priv, b_pub) == \
        primitives.x25519_shared_secret(b_priv, a_pub)


def test_derive_session_key_deterministic_and_sized():
    secret = b"\x01" * 32
    k1 = primitives.derive_session_key(secret, salt=b"s", info=b"i")
    k2 = primitives.derive_session_key(secret, salt=b"s", info=b"i")
    assert k1 == k2 and len(k1) == 32


def test_derive_session_key_diversifies_on_info():
    secret = b"\x01" * 32
    k1 = primitives.derive_session_key(secret, salt=b"s", info=b"a")
    k2 = primitives.derive_session_key(secret, salt=b"s", info=b"b")
    assert k1 != k2


def test_full_key_exchange_to_session_key():
    a_priv, a_pub = primitives.generate_ephemeral_keypair()
    b_priv, b_pub = primitives.generate_ephemeral_keypair()
    salt = primitives.public_key_to_bytes(a_pub) + primitives.public_key_to_bytes(b_pub)
    ka = primitives.derive_session_key(
        primitives.x25519_shared_secret(a_priv, b_pub), salt=salt, info=b"sess")
    kb = primitives.derive_session_key(
        primitives.x25519_shared_secret(b_priv, a_pub), salt=salt, info=b"sess")
    assert ka == kb


# --- AEAD -------------------------------------------------------------------

def test_aead_roundtrip():
    key = primitives.random_bytes(32)
    nonce = primitives.random_bytes(12)
    ct = primitives.aead_encrypt(key, nonce, b"hello", b"AD")
    assert primitives.aead_decrypt(key, nonce, ct, b"AD") == b"hello"


def test_aead_rejects_modified_ciphertext():
    key = primitives.random_bytes(32)
    nonce = primitives.random_bytes(12)
    ct = bytearray(primitives.aead_encrypt(key, nonce, b"hello", b"AD"))
    ct[0] ^= 0x01
    with pytest.raises(CryptoError):
        primitives.aead_decrypt(key, nonce, bytes(ct), b"AD")


def test_aead_rejects_modified_associated_data():
    key = primitives.random_bytes(32)
    nonce = primitives.random_bytes(12)
    ct = primitives.aead_encrypt(key, nonce, b"hello", b"AD")
    with pytest.raises(CryptoError):
        primitives.aead_decrypt(key, nonce, ct, b"DIFFERENT")


def test_aead_rejects_wrong_key():
    nonce = primitives.random_bytes(12)
    ct = primitives.aead_encrypt(primitives.random_bytes(32), nonce, b"hi", b"")
    with pytest.raises(CryptoError):
        primitives.aead_decrypt(primitives.random_bytes(32), nonce, ct, b"")


def test_aead_validates_key_and_nonce_length():
    with pytest.raises(ValueError):
        primitives.aead_encrypt(b"short", b"\x00" * 12, b"x", b"")
    with pytest.raises(ValueError):
        primitives.aead_encrypt(b"\x00" * 32, b"short", b"x", b"")


# --- Serialization ----------------------------------------------------------

def test_ed25519_pubkey_serialization_roundtrip():
    _, pub = primitives.generate_identity_keypair()
    raw = primitives.public_key_to_bytes(pub)
    assert len(raw) == 32
    restored = primitives.ed25519_public_from_bytes(raw)
    assert primitives.public_key_to_bytes(restored) == raw


def test_x25519_pubkey_serialization_roundtrip():
    _, pub = primitives.generate_ephemeral_keypair()
    raw = primitives.public_key_to_bytes(pub)
    assert len(raw) == 32
    restored = primitives.x25519_public_from_bytes(raw)
    assert primitives.public_key_to_bytes(restored) == raw


# --- Fingerprint / safety number --------------------------------------------

def test_safety_number_order_independent():
    _, a = primitives.generate_identity_keypair()
    _, b = primitives.generate_identity_keypair()
    a_raw = primitives.public_key_to_bytes(a)
    b_raw = primitives.public_key_to_bytes(b)
    assert fingerprint.safety_number(a_raw, b_raw) == \
        fingerprint.safety_number(b_raw, a_raw)


def test_safety_number_differs_for_different_peers():
    _, a = primitives.generate_identity_keypair()
    _, b = primitives.generate_identity_keypair()
    _, c = primitives.generate_identity_keypair()
    a_raw = primitives.public_key_to_bytes(a)
    b_raw = primitives.public_key_to_bytes(b)
    c_raw = primitives.public_key_to_bytes(c)
    assert fingerprint.safety_number(a_raw, b_raw) != \
        fingerprint.safety_number(a_raw, c_raw)
