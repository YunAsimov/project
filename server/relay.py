"""Message routing / forwarding.

Tracks which username is reachable over which live connection and forwards
handshake/data messages by their `to` field. The payload (eph_pub, signature,
nonce, ciphertext) is opaque to the server: it is never decrypted, and
end-to-end integrity is enforced by the recipient's AEAD check, not here.
"""

from __future__ import annotations


class Relay:
    def __init__(self) -> None:
        # username -> connection object (e.g. a websocket)
        self._connections: dict[str, object] = {}

    def bind(self, username: str, connection: object) -> None:
        """Associate a username with its live connection (login)."""
        self._connections[username] = connection

    def unbind(self, username: str) -> None:
        """Remove a username's connection (on disconnect)."""
        self._connections.pop(username, None)

    def connection_for(self, username: str) -> object | None:
        """Return the live connection for `username`, or None if offline."""
        return self._connections.get(username)

    def is_online(self, username: str) -> bool:
        return username in self._connections
