"""Public-key fingerprints / safety numbers (Bonus B2: malicious server).

If the relay server hands out a fake public key (A5), users detect it by
comparing a short, human-readable representation of the identity keys out of
band. The base protocol already rejects a forged handshake signature; the
safety number is the independent confirmation that the *right* identity key
was used in the first place.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes


def _digits(data: bytes, n_groups: int = 12, group_len: int = 5) -> str:
    """Render bytes as fixed-length decimal groups (Signal-style safety number)."""
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    digest = h.finalize()
    value = int.from_bytes(digest, "big")
    modulus = 10 ** group_len
    groups = []
    for _ in range(n_groups):
        groups.append(f"{value % modulus:0{group_len}d}")
        value //= modulus
    return " ".join(groups)


def fingerprint(identity_public_key: bytes) -> str:
    """Stable, human-comparable fingerprint of one identity public key."""
    return _digits(identity_public_key)


def safety_number(local_pub: bytes, remote_pub: bytes) -> str:
    """Order-independent safety number for a pair of identities.

    Sorting the two keys makes both peers compute the same value, so they can
    read it aloud / scan it and confirm they share the same view of each
    other's keys.
    """
    a, b = sorted([local_pub, remote_pub])
    return _digits(a + b)
