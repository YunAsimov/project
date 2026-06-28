"""Simple JSON persistence for the registry.

Stores ONLY public information: a mapping of username -> identity public key
(base64). No private keys, session keys, or plaintext are ever stored here.
"""

from __future__ import annotations

import json
import os


class PublicKeyStore:
    """Persistent username -> identity-public-key (base64) mapping."""

    def __init__(self, path: str | None = None) -> None:
        self._path = path
        self._data: dict[str, str] = {}
        if path and os.path.exists(path):
            self._load()

    def _load(self) -> None:
        with open(self._path, "r", encoding="utf-8") as fh:
            self._data = json.load(fh)

    def _save(self) -> None:
        if not self._path:
            return  # in-memory only (e.g. tests)
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2, sort_keys=True)
        os.replace(tmp, self._path)  # atomic on the same filesystem

    def get(self, username: str) -> str | None:
        return self._data.get(username)

    def put(self, username: str, identity_pub_b64: str) -> None:
        self._data[username] = identity_pub_b64
        self._save()

    def __contains__(self, username: str) -> bool:
        return username in self._data
