"""User registration and public-key distribution.

Maps username -> long-term identity public key. Under the base model (A3) the
server is honest-but-curious and distributes correct keys; the client-side
handshake signature still protects against an active network attacker (A2).

To avoid silently overwriting a published key, re-registering an existing
username with a *different* key is refused (returns "conflict"). Detecting a
genuinely malicious key-substituting server (A5/B2) is out of the base model's
power and relies on out-of-band fingerprint comparison (crypto/fingerprint.py).
"""

from __future__ import annotations

from server.storage import PublicKeyStore

REGISTER_OK = "ok"
REGISTER_RECONNECT = "reconnect"   # same user, same key: treat as login
REGISTER_CONFLICT = "conflict"     # username taken with a different key


class Registry:
    def __init__(self, store: PublicKeyStore | None = None) -> None:
        self._store = store or PublicKeyStore()

    def register(self, username: str, identity_pub_b64: str) -> str:
        existing = self._store.get(username)
        if existing is None:
            self._store.put(username, identity_pub_b64)
            return REGISTER_OK
        if existing == identity_pub_b64:
            return REGISTER_RECONNECT
        return REGISTER_CONFLICT

    def lookup(self, username: str) -> str | None:
        """Return the user's identity public key (base64), or None if unknown."""
        return self._store.get(username)
