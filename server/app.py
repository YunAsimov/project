"""Relay server: registration, public-key distribution, message routing.

Trust model: honest-but-curious (A3). The server sees ciphertext and routing
metadata only; it never holds session keys or plaintext. All end-to-end
security is enforced by the clients.

Client-server binding is intentionally minimal (the project focuses on the
end-to-end protocol, not client-server auth): a client `register`s, which
publishes its identity key and binds the username to the live connection.
Subsequent `hs_init` / `hs_resp` / `data` messages are routed by their `to`
field; `lookup` returns a peer's published identity key.
"""

from __future__ import annotations

import argparse
import asyncio

from protocol import messages
from protocol.constants import (
    MSG_DATA,
    MSG_HANDSHAKE_INIT,
    MSG_HANDSHAKE_RESP,
    MSG_LOOKUP,
    MSG_REGISTER,
)
from server.registry import REGISTER_CONFLICT, Registry
from server.relay import Relay
from server.storage import PublicKeyStore

_RELAY_TYPES = (MSG_HANDSHAKE_INIT, MSG_HANDSHAKE_RESP, MSG_DATA)


class ChatServer:
    """Protocol dispatch for the relay server (transport-agnostic core)."""

    def __init__(self, store_path: str | None = None) -> None:
        self.registry = Registry(PublicKeyStore(store_path))
        self.relay = Relay()

    async def _send(self, connection, message: dict) -> None:
        await connection.send(messages.encode(message))

    async def dispatch(self, connection, raw: bytes, username: str | None) -> str | None:
        """Handle one inbound frame. Returns the connection's (maybe new) username."""
        try:
            msg = messages.decode(raw)
        except messages.ProtocolError:
            await self._send(connection, messages.build_error("malformed message"))
            return username

        mtype = msg["type"]
        if mtype == MSG_REGISTER:
            return await self._handle_register(connection, msg)
        if mtype == MSG_LOOKUP:
            await self._handle_lookup(connection, msg)
            return username
        if mtype in _RELAY_TYPES:
            await self._handle_relay(connection, msg)
            return username

        await self._send(connection, messages.build_error(f"unexpected type: {mtype}"))
        return username

    async def _handle_register(self, connection, msg: dict) -> str | None:
        username = msg["username"]
        status = self.registry.register(username, msg["identity_pub"])
        if status == REGISTER_CONFLICT:
            await self._send(connection, messages.build_error(
                "username already registered with a different key", ref=username))
            return None  # not bound; client must pick another name
        self.relay.bind(username, connection)
        await self._send(connection, messages.build_error(
            f"register:{status}", ref=username))
        return username

    async def _handle_lookup(self, connection, msg: dict) -> None:
        username = msg["username"]
        pub_b64 = self.registry.lookup(username)
        identity_pub = messages.b64d(pub_b64) if pub_b64 is not None else None
        await self._send(
            connection, messages.build_lookup_result(username, identity_pub))

    async def _handle_relay(self, connection, msg: dict) -> None:
        target = self.relay.connection_for(msg["to"])
        if target is None:
            await self._send(connection, messages.build_error(
                "recipient offline", ref=msg["to"]))
            return
        # Forward the opaque ciphertext/handshake frame unchanged.
        await self._send(target, msg)

    async def handle_connection(self, connection) -> None:
        """WebSocket connection handler: pump frames through dispatch()."""
        username: str | None = None
        try:
            async for raw in connection:
                username = await self.dispatch(connection, raw, username)
        finally:
            if username is not None:
                self.relay.unbind(username)


async def serve(host: str, port: int, store_path: str | None) -> None:
    import websockets  # imported here so the module loads without the dep

    server = ChatServer(store_path)
    async with websockets.serve(server.handle_connection, host, port):
        print(f"relay server listening on ws://{host}:{port}")
        await asyncio.Future()  # run forever


def main() -> None:
    parser = argparse.ArgumentParser(description="E2EE relay server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--store", default="keystore.json",
                        help="path to the public-key store (public data only)")
    args = parser.parse_args()
    asyncio.run(serve(args.host, args.port, args.store))


if __name__ == "__main__":
    main()
