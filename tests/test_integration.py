"""Full-stack integration test over real WebSockets.

Starts the relay server in-process and drives two real clients through
register -> lookup -> authenticated handshake -> encrypted message exchange,
exercising every layer (transport, server routing, crypto) together.
"""

import asyncio
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

websockets = pytest.importorskip("websockets")

from client import identity
from client.cli import ClientApp
from client.transport import Transport
from server.app import ChatServer


class CapturingApp(ClientApp):
    """ClientApp that records decrypted inbound messages for assertions."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.inbox: list[tuple[str, bytes]] = []

    def _on_data(self, msg):
        from client import messaging
        session = self.sessions.get(msg["from"])
        plaintext = messaging.decrypt_message(session, msg)
        self.inbox.append((msg["from"], plaintext))


async def _wait_until(predicate, timeout=3.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


async def _make_client(name, url, keystore):
    ident = identity.load_or_create(name, keystore_dir=keystore)
    transport = await Transport.connect(url)
    app = CapturingApp(ident, transport)
    await app.register()
    task = asyncio.create_task(app.recv_loop())
    return app, task


async def _scenario():
    server = ChatServer()  # in-memory registry
    async with websockets.serve(server.handle_connection, "127.0.0.1", 0) as ws_server:
        port = ws_server.sockets[0].getsockname()[1]
        url = f"ws://127.0.0.1:{port}"

        with tempfile.TemporaryDirectory() as keystore:
            alice, a_task = await _make_client("alice", url, keystore)
            bob, b_task = await _make_client("bob", url, keystore)
            await asyncio.sleep(0.05)  # let registrations settle

            # Alice initiates the handshake with Bob.
            await alice.start_chat_with("bob")
            assert await _wait_until(
                lambda: "bob" in alice.sessions and "alice" in bob.sessions), \
                "handshake did not complete"

            # Bidirectional encrypted exchange.
            await alice.send_text("bob", "hello bob")
            assert await _wait_until(lambda: bob.inbox), "bob received nothing"
            assert bob.inbox[-1] == ("alice", b"hello bob")

            await bob.send_text("alice", "hi alice")
            assert await _wait_until(lambda: alice.inbox), "alice received nothing"
            assert alice.inbox[-1] == ("bob", b"hi alice")

            # Both ends derived the same directional keys.
            assert alice.sessions["bob"].send_key == bob.sessions["alice"].recv_key

            for t in (a_task, b_task):
                t.cancel()
            await alice.transport.close()
            await bob.transport.close()


def test_full_stack_message_exchange():
    asyncio.run(_scenario())
