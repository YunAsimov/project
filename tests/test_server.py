"""Server dispatch tests: registration, lookup, routing (A3 behaviour)."""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol import messages
from protocol.constants import MSG_ERROR, MSG_LOOKUP_RESULT
from server.app import ChatServer


class FakeConn:
    """Stand-in for a websocket: records frames the server sends to it."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(self, raw: bytes) -> None:
        self.sent.append(messages.decode(raw))

    def last(self) -> dict:
        return self.sent[-1]


def run(coro):
    return asyncio.run(coro)


def _pub(n: int = 1) -> bytes:
    return bytes([n]) * 32


# --- registration -----------------------------------------------------------

def test_register_binds_connection_and_acks():
    srv = ChatServer()
    conn = FakeConn()
    msg = messages.encode(messages.build_register("alice", _pub()))
    username = run(srv.dispatch(conn, msg, None))
    assert username == "alice"
    assert srv.relay.is_online("alice")
    assert conn.last()["type"] == MSG_ERROR
    assert conn.last()["reason"].startswith("register:")


def test_register_conflict_does_not_bind():
    srv = ChatServer()
    run(srv.dispatch(FakeConn(), messages.encode(
        messages.build_register("alice", _pub(1))), None))
    # Different key, same username -> rejected.
    conn = FakeConn()
    username = run(srv.dispatch(conn, messages.encode(
        messages.build_register("alice", _pub(2))), None))
    assert username is None
    assert "different key" in conn.last()["reason"]


def test_reconnect_same_key_ok():
    srv = ChatServer()
    run(srv.dispatch(FakeConn(), messages.encode(
        messages.build_register("alice", _pub(1))), None))
    conn = FakeConn()
    username = run(srv.dispatch(conn, messages.encode(
        messages.build_register("alice", _pub(1))), None))
    assert username == "alice"
    assert conn.last()["reason"] == "register:reconnect"


# --- lookup -----------------------------------------------------------------

def test_lookup_returns_published_key():
    srv = ChatServer()
    run(srv.dispatch(FakeConn(), messages.encode(
        messages.build_register("bob", _pub(7))), None))
    conn = FakeConn()
    run(srv.dispatch(conn, messages.encode(messages.build_lookup("bob")), "alice"))
    res = conn.last()
    assert res["type"] == MSG_LOOKUP_RESULT
    assert messages.b64d(res["identity_pub"]) == _pub(7)


def test_lookup_unknown_user_returns_not_found():
    srv = ChatServer()
    conn = FakeConn()
    run(srv.dispatch(conn, messages.encode(messages.build_lookup("ghost")), "alice"))
    assert conn.last()["found"] is False


# --- routing (relay) --------------------------------------------------------

def test_data_forwarded_to_recipient_unchanged():
    srv = ChatServer()
    alice, bob = FakeConn(), FakeConn()
    run(srv.dispatch(alice, messages.encode(
        messages.build_register("alice", _pub(1))), None))
    run(srv.dispatch(bob, messages.encode(
        messages.build_register("bob", _pub(2))), None))

    data = messages.build_data("alice", "bob", "s1", 0, b"\xaa" * 12, b"\xbb" * 20)
    run(srv.dispatch(alice, messages.encode(data), "alice"))

    # Bob receives the exact frame; the server did not alter the payload.
    forwarded = bob.last()
    assert forwarded["from"] == "alice" and forwarded["to"] == "bob"
    assert messages.b64d(forwarded["ciphertext"]) == b"\xbb" * 20


def test_relay_to_offline_recipient_reports_error():
    srv = ChatServer()
    alice = FakeConn()
    run(srv.dispatch(alice, messages.encode(
        messages.build_register("alice", _pub(1))), None))
    data = messages.build_data("alice", "bob", "s1", 0, b"\xaa" * 12, b"\xbb" * 20)
    run(srv.dispatch(alice, messages.encode(data), "alice"))
    assert alice.last()["type"] == MSG_ERROR
    assert "offline" in alice.last()["reason"]


# --- robustness -------------------------------------------------------------

def test_malformed_frame_is_rejected_gracefully():
    srv = ChatServer()
    conn = FakeConn()
    username = run(srv.dispatch(conn, b"garbage{{{", "alice"))
    assert username == "alice"  # connection survives
    assert conn.last()["type"] == MSG_ERROR
