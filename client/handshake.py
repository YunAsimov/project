"""Authenticated key exchange (defeats A2 MitM; enables B1 forward secrecy).

Protocol (initiator = the user who starts the chat, responder = the peer):

  initiator:
    - generate ephemeral X25519 keypair
    - sign  T_init = H(session_id, init_id_pub, resp_id_pub, init_eph_pub)
            with the long-term Ed25519 identity key
    - send hs_init { from, to, session_id, eph_pub, signature }

  responder (on hs_init):
    - verify the initiator's signature with the looked-up identity key
      (reject on failure -> no MitM can complete the handshake)
    - generate ephemeral X25519 keypair
    - sign  T_resp = H(session_id, resp_id_pub, init_id_pub,
                       init_eph_pub, resp_eph_pub)   # binds the whole transcript
    - compute shared secret, derive directional keys -> Session
    - send hs_resp { from, to, session_id, eph_pub, signature }

  initiator (on hs_resp):
    - verify the responder's signature (binds to init_eph_pub -> this handshake)
    - compute shared secret, derive directional keys -> Session

Forward secrecy (SR5/B1): the ephemeral X25519 private keys are discarded after
the handshake; a later leak of a long-term identity key cannot recover the
shared secret, so past session keys (and traffic) stay confidential.

Identity binding (SR3): both signatures cover both parties' identity public
keys, preventing identity-misbinding / unknown-key-share attacks.
"""

from __future__ import annotations

from dataclasses import dataclass

from crypto import primitives
from protocol import messages
from protocol.constants import HKDF_INFO_SESSION
from client.session import Session


class HandshakeError(Exception):
    """Raised when a handshake message fails verification (reject it)."""


# --- transcript / signed material ------------------------------------------

def _concat(*parts: bytes) -> bytes:
    """Unambiguous concatenation: each part prefixed with its 4-byte length."""
    out = bytearray()
    for part in parts:
        out += len(part).to_bytes(4, "big")
        out += part
    return bytes(out)


def _transcript_init(
    session_id: str, init_id_pub: bytes, resp_id_pub: bytes, init_eph_pub: bytes
) -> bytes:
    return _concat(
        b"comp5355-hs-init-v1",
        session_id.encode("utf-8"),
        init_id_pub,
        resp_id_pub,
        init_eph_pub,
    )


def _transcript_resp(
    session_id: str,
    resp_id_pub: bytes,
    init_id_pub: bytes,
    init_eph_pub: bytes,
    resp_eph_pub: bytes,
) -> bytes:
    return _concat(
        b"comp5355-hs-resp-v1",
        session_id.encode("utf-8"),
        resp_id_pub,
        init_id_pub,
        init_eph_pub,
        resp_eph_pub,
    )


# --- key derivation ---------------------------------------------------------

def _derive_directional_keys(
    shared_secret: bytes, init_eph_pub: bytes, resp_eph_pub: bytes
) -> tuple[bytes, bytes]:
    """Derive (k_i2r, k_r2i) from the shared secret.

    Salt = both ephemeral public keys (initiator first) so the keys are unique
    per handshake; separate `info` labels give independent keys per direction.
    """
    salt = init_eph_pub + resp_eph_pub
    k_i2r = primitives.derive_session_key(shared_secret, salt, HKDF_INFO_SESSION + b"|i2r")
    k_r2i = primitives.derive_session_key(shared_secret, salt, HKDF_INFO_SESSION + b"|r2i")
    return k_i2r, k_r2i


# --- initiator side ---------------------------------------------------------

@dataclass
class PendingHandshake:
    """Initiator state kept between sending hs_init and receiving hs_resp."""
    session_id: str
    local_name: str
    remote_name: str
    eph_private: object              # X25519PrivateKey
    init_eph_pub: bytes
    init_id_pub: bytes
    remote_identity_pub: bytes       # responder's long-term identity (raw)


def initiate(
    local_identity_private,
    local_name: str,
    remote_name: str,
    remote_identity_pub: bytes,
    session_id: str | None = None,
) -> tuple[dict, PendingHandshake]:
    """Start a handshake. Returns (hs_init message, pending state)."""
    if session_id is None:
        session_id = primitives.random_bytes(16).hex()

    eph_private, eph_public = primitives.generate_ephemeral_keypair()
    init_eph_pub = primitives.public_key_to_bytes(eph_public)
    init_id_pub = primitives.public_key_to_bytes(local_identity_private.public_key())

    transcript = _transcript_init(
        session_id, init_id_pub, remote_identity_pub, init_eph_pub)
    signature = primitives.sign(local_identity_private, transcript)

    msg = messages.build_hs_init(
        local_name, remote_name, session_id, init_eph_pub, signature)
    pending = PendingHandshake(
        session_id=session_id,
        local_name=local_name,
        remote_name=remote_name,
        eph_private=eph_private,
        init_eph_pub=init_eph_pub,
        init_id_pub=init_id_pub,
        remote_identity_pub=remote_identity_pub,
    )
    return msg, pending


def complete(pending: PendingHandshake, hs_resp: dict) -> Session:
    """Finish the handshake on the initiator side. Returns an established Session."""
    if hs_resp.get("session_id") != pending.session_id:
        raise HandshakeError("session_id mismatch in hs_resp")
    if hs_resp.get("from") != pending.remote_name or hs_resp.get("to") != pending.local_name:
        raise HandshakeError("routing mismatch in hs_resp")

    resp_eph_pub = messages.b64d(hs_resp["eph_pub"])
    signature = messages.b64d(hs_resp["signature"])

    transcript = _transcript_resp(
        pending.session_id,
        pending.remote_identity_pub,
        pending.init_id_pub,
        pending.init_eph_pub,
        resp_eph_pub,
    )
    resp_identity = primitives.ed25519_public_from_bytes(pending.remote_identity_pub)
    if not primitives.verify(resp_identity, signature, transcript):
        raise HandshakeError("responder signature verification failed")

    shared = primitives.x25519_shared_secret(
        pending.eph_private, primitives.x25519_public_from_bytes(resp_eph_pub))
    k_i2r, k_r2i = _derive_directional_keys(
        shared, pending.init_eph_pub, resp_eph_pub)

    # Initiator sends with i2r, receives with r2i.
    return Session(
        session_id=pending.session_id,
        send_key=k_i2r,
        recv_key=k_r2i,
        local_name=pending.local_name,
        remote_name=pending.remote_name,
    )


# --- responder side ---------------------------------------------------------

def respond(
    local_identity_private,
    local_name: str,
    remote_identity_pub: bytes,
    hs_init: dict,
) -> tuple[dict, Session]:
    """Handle hs_init. Returns (hs_resp message, established Session).

    `remote_identity_pub` is the initiator's long-term identity key, looked up
    from the server; the signature check binds this handshake to that identity.
    """
    if hs_init.get("to") != local_name:
        raise HandshakeError("hs_init not addressed to this user")
    remote_name = hs_init.get("from")
    session_id = hs_init["session_id"]
    init_eph_pub = messages.b64d(hs_init["eph_pub"])
    signature = messages.b64d(hs_init["signature"])

    resp_id_pub = primitives.public_key_to_bytes(local_identity_private.public_key())

    transcript = _transcript_init(
        session_id, remote_identity_pub, resp_id_pub, init_eph_pub)
    init_identity = primitives.ed25519_public_from_bytes(remote_identity_pub)
    if not primitives.verify(init_identity, signature, transcript):
        raise HandshakeError("initiator signature verification failed")

    eph_private, eph_public = primitives.generate_ephemeral_keypair()
    resp_eph_pub = primitives.public_key_to_bytes(eph_public)

    resp_transcript = _transcript_resp(
        session_id, resp_id_pub, remote_identity_pub, init_eph_pub, resp_eph_pub)
    resp_signature = primitives.sign(local_identity_private, resp_transcript)

    shared = primitives.x25519_shared_secret(
        eph_private, primitives.x25519_public_from_bytes(init_eph_pub))
    k_i2r, k_r2i = _derive_directional_keys(shared, init_eph_pub, resp_eph_pub)

    msg = messages.build_hs_resp(
        local_name, remote_name, session_id, resp_eph_pub, resp_signature)
    # Responder sends with r2i, receives with i2r.
    session = Session(
        session_id=session_id,
        send_key=k_r2i,
        recv_key=k_i2r,
        local_name=local_name,
        remote_name=remote_name,
    )
    return msg, session
