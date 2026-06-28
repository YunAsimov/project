"""Tests for protocol/messages.py wire format."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol import messages as m
from protocol.constants import MSG_DATA, MSG_REGISTER


# --- round trips ------------------------------------------------------------

def test_register_roundtrip():
    msg = m.build_register("alice", b"\x01" * 32)
    out = m.decode(m.encode(msg))
    assert out["type"] == MSG_REGISTER
    assert out["username"] == "alice"
    assert m.b64d(out["identity_pub"]) == b"\x01" * 32


def test_data_roundtrip_preserves_binary_and_counter():
    msg = m.build_data("alice", "bob", "sess1", 7, b"\xaa" * 12, b"\xbb" * 40)
    out = m.decode(m.encode(msg))
    assert out["type"] == MSG_DATA
    assert out["counter"] == 7
    assert m.b64d(out["nonce"]) == b"\xaa" * 12
    assert m.b64d(out["ciphertext"]) == b"\xbb" * 40


def test_handshake_roundtrip():
    msg = m.build_hs_init("alice", "bob", "sess1", b"\x02" * 32, b"\x03" * 64)
    out = m.decode(m.encode(msg))
    assert out["from"] == "alice" and out["to"] == "bob"
    assert m.b64d(out["eph_pub"]) == b"\x02" * 32
    assert m.b64d(out["signature"]) == b"\x03" * 64


def test_lookup_result_found_and_not_found():
    found = m.decode(m.encode(m.build_lookup_result("bob", b"\x04" * 32)))
    assert m.b64d(found["identity_pub"]) == b"\x04" * 32
    missing = m.decode(m.encode(m.build_lookup_result("ghost", None)))
    assert missing["found"] is False


# --- associated data --------------------------------------------------------

def test_associated_data_deterministic():
    ad1 = m.associated_data("alice", "bob", "s", 3)
    ad2 = m.associated_data("alice", "bob", "s", 3)
    assert ad1 == ad2


def test_associated_data_changes_with_context():
    base = m.associated_data("alice", "bob", "s", 3)
    assert m.associated_data("bob", "alice", "s", 3) != base   # direction
    assert m.associated_data("alice", "bob", "s2", 3) != base  # session
    assert m.associated_data("alice", "bob", "s", 4) != base   # counter


def test_associated_data_no_ambiguous_concatenation():
    # Separator must prevent ("ab","c") colliding with ("a","bc").
    assert m.associated_data("ab", "c", "s", 1) != m.associated_data("a", "bc", "s", 1)


# --- validation / rejection -------------------------------------------------

def test_decode_rejects_invalid_json():
    with pytest.raises(m.ProtocolError):
        m.decode(b"not json{{{")


def test_validate_rejects_unknown_type():
    with pytest.raises(m.ProtocolError):
        m.validate({"type": "bogus", "version": 1})


def test_validate_rejects_missing_field():
    with pytest.raises(m.ProtocolError):
        m.encode({"type": MSG_REGISTER, "version": 1, "username": "alice"})


def test_validate_rejects_wrong_version():
    msg = m.build_register("alice", b"\x01" * 32)
    msg["version"] = 999
    with pytest.raises(m.ProtocolError):
        m.encode(msg)


def test_b64d_rejects_garbage():
    with pytest.raises(m.ProtocolError):
        m.b64d("!!!not base64!!!")


def test_data_rejects_non_integer_counter():
    msg = m.build_data("a", "b", "s", 0, b"\x00" * 12, b"\x00")
    msg["counter"] = "0"
    with pytest.raises(m.ProtocolError):
        m.validate(msg)
