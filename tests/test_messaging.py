"""End-to-end messaging tests (SR1 round trip, SR2/SR3 reject, SR4 replay)."""

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import primitives
from protocol import messages
from client import handshake, messaging


def _established_sessions():
    """Run a real handshake and return (alice_session, bob_session)."""
    a_priv, a_pub = primitives.generate_identity_keypair()
    b_priv, b_pub = primitives.generate_identity_keypair()
    a_pub_b = primitives.public_key_to_bytes(a_pub)
    b_pub_b = primitives.public_key_to_bytes(b_pub)

    hs_init, pending = handshake.initiate(a_priv, "alice", "bob", b_pub_b)
    hs_resp, bob = handshake.respond(b_priv, "bob", a_pub_b, hs_init)
    alice = handshake.complete(pending, hs_resp)
    return alice, bob


# --- round trip (SR1) -------------------------------------------------------

def test_message_roundtrip_both_directions():
    alice, bob = _established_sessions()
    msg = messaging.encrypt_message(alice, b"hello bob")
    assert messaging.decrypt_message(bob, msg) == b"hello bob"

    reply = messaging.encrypt_message(bob, b"hi alice")
    assert messaging.decrypt_message(alice, reply) == b"hi alice"


def test_multiple_in_order_messages():
    alice, bob = _established_sessions()
    for i in range(5):
        m = messaging.encrypt_message(alice, f"msg {i}".encode())
        assert messaging.decrypt_message(bob, m) == f"msg {i}".encode()


def test_ciphertext_is_not_plaintext():
    alice, _ = _established_sessions()
    m = messaging.encrypt_message(alice, b"secret")
    assert b"secret" not in messages.b64d(m["ciphertext"])


def test_message_survives_wire_serialization():
    alice, bob = _established_sessions()
    m = messaging.encrypt_message(alice, b"over the wire")
    on_wire = messages.decode(messages.encode(m))
    assert messaging.decrypt_message(bob, on_wire) == b"over the wire"


# --- tampering rejected (SR2 / SR3) -----------------------------------------

def test_modified_ciphertext_rejected():
    alice, bob = _established_sessions()
    m = messaging.encrypt_message(alice, b"hello")
    ct = bytearray(messages.b64d(m["ciphertext"]))
    ct[0] ^= 0x01
    m["ciphertext"] = messages.b64e(bytes(ct))
    with pytest.raises(messaging.MessageError):
        messaging.decrypt_message(bob, m)


def test_modified_counter_rejected():
    # Changing the counter changes the AD -> tag verification fails.
    alice, bob = _established_sessions()
    m = messaging.encrypt_message(alice, b"hello")
    m["counter"] = m["counter"] + 1
    with pytest.raises(messaging.MessageError):
        messaging.decrypt_message(bob, m)


def test_spoofed_sender_rejected():
    alice, bob = _established_sessions()
    m = messaging.encrypt_message(alice, b"hello")
    m["from"] = "mallory"
    with pytest.raises(messaging.MessageError):
        messaging.decrypt_message(bob, m)


def test_wrong_session_rejected():
    alice, bob = _established_sessions()
    m = messaging.encrypt_message(alice, b"hello")
    m["session_id"] = "other"
    with pytest.raises(messaging.MessageError):
        messaging.decrypt_message(bob, m)


def test_forged_message_without_key_rejected():
    # An attacker with no session key cannot forge a valid frame (SR3).
    _, bob = _established_sessions()
    forged = messages.build_data(
        "alice", "bob", bob.session_id, 0,
        primitives.random_bytes(12), primitives.random_bytes(32))
    with pytest.raises(messaging.MessageError):
        messaging.decrypt_message(bob, forged)


# --- replay rejected (SR4) --------------------------------------------------

def test_exact_replay_rejected():
    alice, bob = _established_sessions()
    m = messaging.encrypt_message(alice, b"hello")
    assert messaging.decrypt_message(bob, copy.deepcopy(m)) == b"hello"
    with pytest.raises(messaging.MessageError):
        messaging.decrypt_message(bob, copy.deepcopy(m))  # captured & resent


def test_replay_does_not_corrupt_later_messages():
    alice, bob = _established_sessions()
    m0 = messaging.encrypt_message(alice, b"first")
    m1 = messaging.encrypt_message(alice, b"second")
    assert messaging.decrypt_message(bob, copy.deepcopy(m0)) == b"first"
    with pytest.raises(messaging.MessageError):
        messaging.decrypt_message(bob, copy.deepcopy(m0))      # replay
    assert messaging.decrypt_message(bob, m1) == b"second"     # still works


def test_forged_counter_does_not_poison_window():
    # A forged high-counter frame fails AEAD before the window is updated,
    # so a later legitimate message at that counter is still accepted.
    alice, bob = _established_sessions()
    forged = messages.build_data(
        "alice", "bob", bob.session_id, 0,
        primitives.random_bytes(12), primitives.random_bytes(32))
    with pytest.raises(messaging.MessageError):
        messaging.decrypt_message(bob, forged)
    legit = messaging.encrypt_message(alice, b"real")  # counter 0
    assert messaging.decrypt_message(bob, legit) == b"real"
