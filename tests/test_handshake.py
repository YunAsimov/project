"""Handshake tests (SR3 authenticity, A2 MitM resistance, B1 forward secrecy)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import primitives
from protocol import messages
from client import handshake


def _identity():
    priv, pub = primitives.generate_identity_keypair()
    return priv, primitives.public_key_to_bytes(pub)


def _run_handshake():
    a_priv, a_pub = _identity()
    b_priv, b_pub = _identity()
    hs_init, pending = handshake.initiate(a_priv, "alice", "bob", b_pub)
    hs_resp, b_session = handshake.respond(b_priv, "bob", a_pub, hs_init)
    a_session = handshake.complete(pending, hs_resp)
    return a_session, b_session, (a_priv, a_pub, b_priv, b_pub)


# --- happy path -------------------------------------------------------------

def test_handshake_agrees_on_directional_keys():
    a_session, b_session, _ = _run_handshake()
    # Initiator's send key == responder's recv key (and vice versa).
    assert a_session.send_key == b_session.recv_key
    assert a_session.recv_key == b_session.send_key
    assert a_session.session_id == b_session.session_id


def test_handshake_directions_use_distinct_keys():
    a_session, _, _ = _run_handshake()
    assert a_session.send_key != a_session.recv_key


def test_handshake_messages_validate_as_wire_format():
    a_priv, a_pub = _identity()
    b_priv, b_pub = _identity()
    hs_init, pending = handshake.initiate(a_priv, "alice", "bob", b_pub)
    messages.decode(messages.encode(hs_init))  # must be a valid frame
    hs_resp, _ = handshake.respond(b_priv, "bob", a_pub, hs_init)
    messages.decode(messages.encode(hs_resp))


# --- MitM / tampering rejection (A2, SR3) -----------------------------------

def test_responder_rejects_forged_init_signature():
    a_priv, a_pub = _identity()
    b_priv, b_pub = _identity()
    hs_init, _ = handshake.initiate(a_priv, "alice", "bob", b_pub)
    forged = dict(hs_init)
    forged["signature"] = messages.b64e(b"\x00" * 64)
    with pytest.raises(handshake.HandshakeError):
        handshake.respond(b_priv, "bob", a_pub, forged)


def test_responder_rejects_wrong_initiator_identity():
    # Attacker presents a different identity key than the one that signed.
    a_priv, _ = _identity()
    _, wrong_pub = _identity()
    b_priv, b_pub = _identity()
    hs_init, _ = handshake.initiate(a_priv, "alice", "bob", b_pub)
    with pytest.raises(handshake.HandshakeError):
        handshake.respond(b_priv, "bob", wrong_pub, hs_init)


def test_initiator_rejects_forged_resp_signature():
    a_priv, a_pub = _identity()
    b_priv, b_pub = _identity()
    hs_init, pending = handshake.initiate(a_priv, "alice", "bob", b_pub)
    hs_resp, _ = handshake.respond(b_priv, "bob", a_pub, hs_init)
    forged = dict(hs_resp)
    forged["signature"] = messages.b64e(b"\x00" * 64)
    with pytest.raises(handshake.HandshakeError):
        handshake.complete(pending, forged)


def test_initiator_rejects_swapped_ephemeral_key():
    # MitM swaps responder's ephemeral key -> signature no longer matches.
    a_priv, a_pub = _identity()
    b_priv, b_pub = _identity()
    hs_init, pending = handshake.initiate(a_priv, "alice", "bob", b_pub)
    hs_resp, _ = handshake.respond(b_priv, "bob", a_pub, hs_init)
    tampered = dict(hs_resp)
    _, ev = primitives.generate_ephemeral_keypair()
    tampered["eph_pub"] = messages.b64e(primitives.public_key_to_bytes(ev))
    with pytest.raises(handshake.HandshakeError):
        handshake.complete(pending, tampered)


def test_complete_rejects_session_id_mismatch():
    a_priv, a_pub = _identity()
    b_priv, b_pub = _identity()
    hs_init, pending = handshake.initiate(a_priv, "alice", "bob", b_pub)
    hs_resp, _ = handshake.respond(b_priv, "bob", a_pub, hs_init)
    bad = dict(hs_resp)
    bad["session_id"] = "deadbeef"
    with pytest.raises(handshake.HandshakeError):
        handshake.complete(pending, bad)


# --- forward secrecy property (B1) ------------------------------------------

def test_fresh_sessions_have_independent_keys():
    a_priv, a_pub = _identity()
    b_priv, b_pub = _identity()
    # Same long-term identities, two separate handshakes -> different keys,
    # because each uses fresh ephemeral X25519 keys (forward secrecy).
    hs1, p1 = handshake.initiate(a_priv, "alice", "bob", b_pub)
    r1, _ = handshake.respond(b_priv, "bob", a_pub, hs1)
    s1 = handshake.complete(p1, r1)

    hs2, p2 = handshake.initiate(a_priv, "alice", "bob", b_pub)
    r2, _ = handshake.respond(b_priv, "bob", a_pub, hs2)
    s2 = handshake.complete(p2, r2)

    assert s1.send_key != s2.send_key
    assert s1.recv_key != s2.recv_key
    assert s1.session_id != s2.session_id
