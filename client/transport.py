"""Network transport between client and relay server (WebSocket).

The network is fully adversarial (A1/A2); this layer provides NO security on
its own. All confidentiality, integrity, authenticity, and replay guarantees
come from the cryptographic protocol layered above it.
"""

from __future__ import annotations

from protocol import messages


class Transport:
    """Async WebSocket client wrapper that sends/receives protocol messages."""

    def __init__(self, connection) -> None:
        self._conn = connection

    @classmethod
    async def connect(cls, url: str) -> "Transport":
        import websockets
        connection = await websockets.connect(url)
        return cls(connection)

    async def send(self, message: dict) -> None:
        await self._conn.send(messages.encode(message))

    async def recv(self) -> dict:
        raw = await self._conn.recv()
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        return messages.decode(raw)

    async def close(self) -> None:
        await self._conn.close()
