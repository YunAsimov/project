"""Long-term Ed25519 identity key: generation, local storage, loading.

Key lifecycle:
  - Generated once with the library CSPRNG at first use.
  - Private key stored locally only, in a keystore directory that is excluded
    from version control (.gitignore). It is never sent to the server.
  - Public key is uploaded to the server for distribution.

NOTE: the private key is stored unencrypted on disk for simplicity. The threat
model assumes endpoints are not compromised (A4/device theft is bonus only);
a production system would wrap it with a passphrase-derived key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from crypto import primitives

DEFAULT_KEYSTORE = "client_store"


@dataclass
class Identity:
    username: str
    private_key: object        # Ed25519PrivateKey
    public_bytes: bytes        # raw 32-byte identity public key


def _key_path(keystore_dir: str, username: str) -> str:
    return os.path.join(keystore_dir, f"{username}.key")


def load_or_create(username: str, keystore_dir: str = DEFAULT_KEYSTORE) -> Identity:
    """Load this user's identity, creating and persisting it if absent."""
    path = _key_path(keystore_dir, username)
    if os.path.exists(path):
        with open(path, "rb") as fh:
            private_key = primitives.identity_private_from_bytes(fh.read())
    else:
        private_key, _ = primitives.generate_identity_keypair()
        os.makedirs(keystore_dir, exist_ok=True)
        raw = primitives.identity_private_to_bytes(private_key)
        # Write with owner-only permissions where the OS supports it.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
    public_bytes = primitives.public_key_to_bytes(private_key.public_key())
    return Identity(username=username, private_key=private_key, public_bytes=public_bytes)
