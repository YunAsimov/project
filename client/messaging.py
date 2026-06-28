"""Application message encryption / decryption (SR1, SR2, SR3, SR4).

Encrypt (sender direction):
    counter <- session.next_send_counter()
    nonce   <- nonce_for_counter(counter)
    AD      <- associated_data(local, remote, session_id, counter)
    ct      <- AEAD(session.send_key, nonce, plaintext, AD)
  - Confidentiality (SR1): ChaCha20-Poly1305 keeps plaintext from A1/A3.
  - Integrity (SR2) + authenticity (SR3): the Poly1305 tag covers ciphertext
    and AD; AD binds direction, session, and position, so a ciphertext is only
    valid in exactly one place.

Decrypt (recipient direction) — order matters:
    1. structural checks (routing matches this session)
    2. AEAD verify+decrypt with recv_key and the reconstructed AD  (SR2/SR3)
    3. replay-window check on the counter                          (SR4)
  AEAD is verified before the replay window is updated, so an attacker cannot
  poison the window with a forged counter (the forged frame fails step 2 first).
"""

from __future__ import annotations

from crypto import primitives
from protocol import messages
from client.session import Session


class MessageError(Exception):
    """Raised when an incoming message must be rejected (SR2/SR3/SR4)."""


def encrypt_message(session: Session, plaintext: bytes) -> dict:
    """Encrypt `plaintext` into a `data` message ready for transport."""
    counter = session.next_send_counter()
    nonce = Session.nonce_for_counter(counter)
    ad = messages.associated_data(
        session.local_name, session.remote_name, session.session_id, counter)
    ciphertext = primitives.aead_encrypt(session.send_key, nonce, plaintext, ad)
    return messages.build_data(
        session.local_name,
        session.remote_name,
        session.session_id,
        counter,
        nonce,
        ciphertext,
    )


def decrypt_message(session: Session, data_msg: dict) -> bytes:
    """Verify, replay-check, and decrypt an incoming `data` message.

    Returns the plaintext, or raises MessageError if the message is forged,
    tampered, misrouted, or replayed.
    """
    # 1. Structural / routing checks: the message must belong to this session
    #    and be addressed from the peer to us.
    if data_msg.get("session_id") != session.session_id:
        raise MessageError("session_id mismatch")
    if data_msg.get("from") != session.remote_name or \
            data_msg.get("to") != session.local_name:
        raise MessageError("routing mismatch")

    counter = data_msg["counter"]
    nonce = messages.b64d(data_msg["nonce"])
    ciphertext = messages.b64d(data_msg["ciphertext"])

    # The AD is reconstructed from the claimed routing/counter fields; if an
    # attacker altered any of them, the tag check below fails.
    ad = messages.associated_data(
        data_msg["from"], data_msg["to"], session.session_id, counter)

    # 2. Authenticated decryption (SR2 integrity, SR3 authenticity).
    try:
        plaintext = primitives.aead_decrypt(session.recv_key, nonce, ciphertext, ad)
    except primitives.CryptoError as exc:
        raise MessageError("AEAD verification failed") from exc

    # 3. Replay protection (SR4) — only after the frame is proven authentic.
    if not session.accept_recv_counter(counter):
        raise MessageError("replay or out-of-window counter")

    return plaintext
