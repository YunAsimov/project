"""Wire-format message (de)serialization.

Encoding: UTF-8 JSON. Binary fields are base64-encoded strings so they survive
JSON transport. Every protocol message type is built and validated here so the
report's handshake / message-flow diagrams can be checked against the code.

Message schemas (all carry `type` and `version`):

  register       { type, version, username, identity_pub }
                   client -> server: publish long-term identity public key

  lookup         { type, version, username }
                   client -> server: request a peer's identity public key

  lookup_result  { type, version, username, identity_pub }   # found
                 { type, version, username, found: false }   # not found

  hs_init        { type, version, from, to, session_id, eph_pub, signature }
  hs_resp        { type, version, from, to, session_id, eph_pub, signature }
                   authenticated key exchange; signature is over
                   transcript bytes (see client/handshake.py)

  data           { type, version, from, to, session_id, counter, nonce,
                   ciphertext }
                   encrypted application message; AEAD associated data is
                   `associated_data(from, to, session_id, counter)`

The relay server reads only routing fields (`from`, `to`); `eph_pub`,
`signature`, `nonce`, and `ciphertext` are opaque to it.
"""

from __future__ import annotations

import base64
import json

from protocol.constants import (
    MSG_DATA,
    MSG_ERROR,
    MSG_HANDSHAKE_INIT,
    MSG_HANDSHAKE_RESP,
    MSG_LOOKUP,
    MSG_LOOKUP_RESULT,
    MSG_REGISTER,
    PROTOCOL_VERSION,
)


class ProtocolError(Exception):
    """Raised when a message is malformed or fails schema validation."""


# --- base64 helpers ---------------------------------------------------------

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise ProtocolError("invalid base64 field") from exc


# --- associated data (canonical, shared by sender and recipient) ------------

def associated_data(
    sender: str, recipient: str, session_id: str, counter: int
) -> bytes:
    """Canonical AEAD associated data binding routing + ordering context.

    Binding sender‖recipient‖session_id‖counter means a ciphertext is only
    valid for one direction, one session, and one position in the stream —
    defeating misrouting, cross-session reuse, and (with the recipient's
    replay window) replay (SR4).
    """
    return b"\x1f".join([
        sender.encode("utf-8"),
        recipient.encode("utf-8"),
        session_id.encode("utf-8"),
        str(counter).encode("ascii"),
    ])


# --- builders ---------------------------------------------------------------

def build_register(username: str, identity_pub: bytes) -> dict:
    return {
        "type": MSG_REGISTER,
        "version": PROTOCOL_VERSION,
        "username": username,
        "identity_pub": b64e(identity_pub),
    }


def build_lookup(username: str) -> dict:
    return {"type": MSG_LOOKUP, "version": PROTOCOL_VERSION, "username": username}


def build_lookup_result(username: str, identity_pub: bytes | None) -> dict:
    msg = {
        "type": MSG_LOOKUP_RESULT,
        "version": PROTOCOL_VERSION,
        "username": username,
    }
    if identity_pub is None:
        msg["found"] = False
    else:
        msg["identity_pub"] = b64e(identity_pub)
    return msg


def _build_handshake(
    msg_type: str,
    sender: str,
    recipient: str,
    session_id: str,
    eph_pub: bytes,
    signature: bytes,
) -> dict:
    return {
        "type": msg_type,
        "version": PROTOCOL_VERSION,
        "from": sender,
        "to": recipient,
        "session_id": session_id,
        "eph_pub": b64e(eph_pub),
        "signature": b64e(signature),
    }


def build_hs_init(
    sender: str, recipient: str, session_id: str, eph_pub: bytes, signature: bytes
) -> dict:
    return _build_handshake(
        MSG_HANDSHAKE_INIT, sender, recipient, session_id, eph_pub, signature)


def build_hs_resp(
    sender: str, recipient: str, session_id: str, eph_pub: bytes, signature: bytes
) -> dict:
    return _build_handshake(
        MSG_HANDSHAKE_RESP, sender, recipient, session_id, eph_pub, signature)


def build_error(reason: str, ref: str | None = None) -> dict:
    """Server-side control message (e.g. recipient offline, bad request).

    Carries no security guarantees — clients treat it only as a hint and never
    relax any cryptographic check because of it.
    """
    msg = {"type": MSG_ERROR, "version": PROTOCOL_VERSION, "reason": reason}
    if ref is not None:
        msg["ref"] = ref
    return msg


def build_data(
    sender: str,
    recipient: str,
    session_id: str,
    counter: int,
    nonce: bytes,
    ciphertext: bytes,
) -> dict:
    return {
        "type": MSG_DATA,
        "version": PROTOCOL_VERSION,
        "from": sender,
        "to": recipient,
        "session_id": session_id,
        "counter": counter,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
    }


# --- validation -------------------------------------------------------------

# Required keys per message type (besides type/version, validated separately).
_REQUIRED: dict[str, tuple[str, ...]] = {
    MSG_REGISTER: ("username", "identity_pub"),
    MSG_LOOKUP: ("username",),
    MSG_LOOKUP_RESULT: ("username",),  # identity_pub XOR found:false checked below
    MSG_HANDSHAKE_INIT: ("from", "to", "session_id", "eph_pub", "signature"),
    MSG_HANDSHAKE_RESP: ("from", "to", "session_id", "eph_pub", "signature"),
    MSG_DATA: ("from", "to", "session_id", "counter", "nonce", "ciphertext"),
    MSG_ERROR: ("reason",),
}


def validate(message: dict) -> dict:
    """Validate a decoded message against its schema. Returns it unchanged.

    Raises ProtocolError on any structural problem so callers can uniformly
    reject malformed input (relevant to A2: injected/garbage frames).
    """
    if not isinstance(message, dict):
        raise ProtocolError("message must be an object")
    msg_type = message.get("type")
    if msg_type not in _REQUIRED:
        raise ProtocolError(f"unknown message type: {msg_type!r}")
    if message.get("version") != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported version: {message.get('version')!r}")

    for field in _REQUIRED[msg_type]:
        if field not in message:
            raise ProtocolError(f"{msg_type}: missing field {field!r}")

    if msg_type == MSG_LOOKUP_RESULT:
        if "identity_pub" not in message and message.get("found") is not False:
            raise ProtocolError("lookup_result: need identity_pub or found:false")
    if msg_type == MSG_DATA and not isinstance(message["counter"], int):
        raise ProtocolError("data: counter must be an integer")
    return message


# --- encode / decode --------------------------------------------------------

def encode(message: dict) -> bytes:
    """Serialize a (built) message dict to UTF-8 JSON bytes for transport."""
    validate(message)
    return json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")


def decode(raw: bytes) -> dict:
    """Parse and validate transport bytes into a message dict."""
    try:
        message = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProtocolError("invalid JSON frame") from exc
    return validate(message)
