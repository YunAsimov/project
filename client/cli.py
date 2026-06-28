"""Minimal interactive CLI demonstrating the end-to-end protocol.

Subcommands:
  register --user NAME [--server URL]   create identity, publish public key
  chat     --user NAME [--server URL]   register, then chat interactively

Interactive commands (inside `chat`):
  /chat <peer>     look up <peer>, run the authenticated handshake
  /verify <peer>   print the safety number for an out-of-band check (B2)
  /peers           list users you have an established session with
  /quit            exit
  <text>           send <text> to the most recently selected peer

This wires together identity -> transport -> handshake -> session -> messaging.
The interface is intentionally minimal; all security lives in the layers below.
"""

from __future__ import annotations

import argparse
import asyncio

from crypto import fingerprint
from client import handshake, identity, messaging
from client.transport import Transport
from protocol import messages
from protocol.constants import (
    MSG_DATA,
    MSG_ERROR,
    MSG_HANDSHAKE_INIT,
    MSG_HANDSHAKE_RESP,
    MSG_LOOKUP_RESULT,
)

DEFAULT_SERVER = "ws://127.0.0.1:8765"


class ClientApp:
    def __init__(self, ident: identity.Identity, transport: Transport) -> None:
        self.id = ident
        self.transport = transport
        self.sessions: dict[str, object] = {}        # peer -> Session
        self.pending: dict[str, object] = {}         # session_id -> PendingHandshake
        self.peer_keys: dict[str, bytes] = {}        # peer -> identity pubkey
        self._lookups: dict[str, asyncio.Future] = {}
        self.active_peer: str | None = None
        self._tasks: set[asyncio.Task] = set()

    def _log(self, text: str) -> None:
        """User-facing feedback. Overridable so a GUI/bridge can intercept it."""
        print(text)

    # --- server interactions ------------------------------------------------

    async def register(self) -> None:
        await self.transport.send(
            messages.build_register(self.id.username, self.id.public_bytes))

    async def _get_peer_key(self, peer: str) -> bytes | None:
        if peer in self.peer_keys:
            return self.peer_keys[peer]
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._lookups[peer] = fut
        await self.transport.send(messages.build_lookup(peer))
        return await fut

    async def start_chat_with(self, peer: str) -> None:
        peer_key = await self._get_peer_key(peer)
        if peer_key is None:
            self._log(f"[!] unknown user: {peer}")
            return
        hs_init, pending = handshake.initiate(
            self.id.private_key, self.id.username, peer, peer_key)
        self.pending[pending.session_id] = pending
        await self.transport.send(hs_init)
        self._log(f"[*] handshake initiated with {peer} ...")

    def show_safety_number(self, peer: str) -> None:
        peer_key = self.peer_keys.get(peer)
        if peer_key is None:
            self._log(f"[!] no key cached for {peer}; run /chat {peer} first")
            return
        number = fingerprint.safety_number(self.id.public_bytes, peer_key)
        self._log(f"[safety number with {peer}] {number}")
        self._log("    Compare this out of band; matching numbers => no MitM (B2).")

    async def send_text(self, peer: str, text: str) -> None:
        session = self.sessions.get(peer)
        if session is None:
            self._log(f"[!] no session with {peer}; run /chat {peer} first")
            return
        await self.transport.send(messaging.encrypt_message(session, text.encode()))

    # --- inbound message handling ------------------------------------------

    async def _handle(self, msg: dict) -> None:
        mtype = msg["type"]
        if mtype == MSG_LOOKUP_RESULT:
            self._on_lookup_result(msg)
        elif mtype == MSG_HANDSHAKE_INIT:
            # Responding needs a peer-key lookup, which is resolved by this same
            # recv loop; run it in a task so the loop is not blocked on itself.
            task = asyncio.create_task(self._on_hs_init(msg))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        elif mtype == MSG_HANDSHAKE_RESP:
            self._on_hs_resp(msg)
        elif mtype == MSG_DATA:
            self._on_data(msg)
        elif mtype == MSG_ERROR:
            self._log(f"[server] {msg['reason']}")

    def _on_lookup_result(self, msg: dict) -> None:
        peer = msg["username"]
        key = messages.b64d(msg["identity_pub"]) if "identity_pub" in msg else None
        if key is not None:
            self.peer_keys[peer] = key
        fut = self._lookups.pop(peer, None)
        if fut and not fut.done():
            fut.set_result(key)

    async def _on_hs_init(self, msg: dict) -> None:
        peer = msg["from"]
        peer_key = await self._get_peer_key(peer)
        if peer_key is None:
            self._log(f"[!] cannot verify handshake from unknown user {peer}")
            return
        try:
            hs_resp, session = handshake.respond(
                self.id.private_key, self.id.username, peer_key, msg)
        except handshake.HandshakeError as exc:
            self._log(f"[!] rejected handshake from {peer}: {exc}")
            return
        self.sessions[peer] = session
        self.active_peer = peer
        await self.transport.send(hs_resp)
        self._log(f"[*] session established with {peer} (they started it)")

    def _on_hs_resp(self, msg: dict) -> None:
        pending = self.pending.pop(msg.get("session_id"), None)
        if pending is None:
            self._log("[!] unexpected handshake response")
            return
        try:
            session = handshake.complete(pending, msg)
        except handshake.HandshakeError as exc:
            self._log(f"[!] handshake failed: {exc}")
            return
        self.sessions[pending.remote_name] = session
        self.active_peer = pending.remote_name
        self._log(f"[*] session established with {pending.remote_name}")

    def _on_data(self, msg: dict) -> None:
        peer = msg["from"]
        session = self.sessions.get(peer)
        if session is None:
            self._log(f"[!] data from {peer} with no session; dropped")
            return
        try:
            plaintext = messaging.decrypt_message(session, msg)
        except messaging.MessageError as exc:
            self._log(f"[!] rejected message from {peer}: {exc}")
            return
        self._log(f"\n{peer}> {plaintext.decode(errors='replace')}")

    # --- loops --------------------------------------------------------------

    async def recv_loop(self) -> None:
        try:
            while True:
                await self._handle(await self.transport.recv())
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # connection closed, etc.
            print(f"[*] connection closed: {exc}")

    async def input_loop(self) -> None:
        loop = asyncio.get_event_loop()
        print("Commands: /chat <peer>, /verify <peer>, /peers, /quit")
        while True:
            line = (await loop.run_in_executor(None, input)).strip()
            if not line:
                continue
            if line == "/quit":
                return
            if line == "/peers":
                print("sessions:", ", ".join(self.sessions) or "(none)")
                continue
            if line.startswith("/chat "):
                await self.start_chat_with(line.split(maxsplit=1)[1].strip())
                continue
            if line.startswith("/verify "):
                self.show_safety_number(line.split(maxsplit=1)[1].strip())
                continue
            if self.active_peer is None:
                print("[!] no active peer; use /chat <peer> first")
                continue
            await self.send_text(self.active_peer, line)


async def _run_chat(username: str, server: str) -> None:
    ident = identity.load_or_create(username)
    transport = await Transport.connect(server)
    app = ClientApp(ident, transport)
    await app.register()
    print(f"[*] connected as {username}; fingerprint {fingerprint.fingerprint(ident.public_bytes)}")

    recv_task = asyncio.create_task(app.recv_loop())
    try:
        await app.input_loop()
    finally:
        recv_task.cancel()
        await transport.close()


async def _run_register(username: str, server: str) -> None:
    ident = identity.load_or_create(username)
    transport = await Transport.connect(server)
    app = ClientApp(ident, transport)
    await app.register()
    print(await transport.recv())
    await transport.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="E2EE messaging client")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("register", "chat"):
        p = sub.add_parser(name)
        p.add_argument("--user", required=True)
        p.add_argument("--server", default=DEFAULT_SERVER)

    args = parser.parse_args()
    if args.command == "register":
        asyncio.run(_run_register(args.user, args.server))
    else:
        asyncio.run(_run_chat(args.user, args.server))


if __name__ == "__main__":
    main()
