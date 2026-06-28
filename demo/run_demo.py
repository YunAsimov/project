"""Scripted demo: two real clients talk to a running relay server.

Run the server first:
    python -m server.app

Then:
    python demo/run_demo.py
"""

import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client import identity, messaging
from client.cli import ClientApp
from client.transport import Transport

URL = "ws://127.0.0.1:8765"


class DemoApp(ClientApp):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.inbox = []

    def _on_data(self, msg):
        session = self.sessions.get(msg["from"])
        pt = messaging.decrypt_message(session, msg)
        self.inbox.append((msg["from"], pt))
        print(f"    [{self.id.username} received]  {msg['from']}> {pt.decode()}")


async def wait_until(pred, timeout=3.0):
    end = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < end:
        if pred():
            return True
        await asyncio.sleep(0.02)
    return False


async def make(name, keystore):
    ident = identity.load_or_create(name, keystore_dir=keystore)
    tr = await Transport.connect(URL)
    app = DemoApp(ident, tr)
    await app.register()
    asyncio.create_task(app.recv_loop())
    return app


async def main():
    with tempfile.TemporaryDirectory() as ks:
        print("== connecting two clients to", URL)
        alice = await make("alice", ks)
        bob = await make("bob", ks)
        await asyncio.sleep(0.1)

        print("== alice runs authenticated handshake with bob")
        await alice.start_chat_with("bob")
        ok = await wait_until(lambda: "bob" in alice.sessions and "alice" in bob.sessions)
        print("   handshake complete:", ok)

        print("== exchanging encrypted messages")
        await alice.send_text("bob", "hello bob, this is end-to-end encrypted")
        await wait_until(lambda: bob.inbox)
        await bob.send_text("alice", "got it, replying securely")
        await wait_until(lambda: alice.inbox)

        same = alice.sessions["bob"].send_key == bob.sessions["alice"].recv_key
        print("== both sides share matching directional keys:", same)

        # Show what a passive attacker / server sees on the wire.
        wire = messaging.encrypt_message(alice.sessions["bob"], b"hello bob, this is end-to-end encrypted")
        print("== sample wire frame (what A1/A3 see): ciphertext only")
        print("   ", {k: wire[k] for k in ("type", "from", "to", "counter")},
              "ciphertext=", wire["ciphertext"][:40], "...")

        await alice.transport.close()
        await bob.transport.close()
        print("== demo done")


if __name__ == "__main__":
    asyncio.run(main())
