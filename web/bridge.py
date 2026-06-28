"""Local bridge: a thin web API in front of the existing CLI client.

Architecture (Plan B):

    browser (UI only)  <--ws(localhost)-->  this bridge (the real endpoint)
                                                   |  reuses client/* crypto
                                                   v
                                            relay server  <-->  peer

All end-to-end cryptography is the SAME tested Python code used by the CLI
client (`client.cli.ClientApp`). The browser holds no E2EE keys and never sees
the protocol; it sends high-level commands (register / login / chat / send) and
renders decrypted plaintext pushed back to it. The browser<->bridge link is
loopback on the user's own machine, i.e. inside the endpoint trust boundary.

Account auth (username + password) is handled here against MySQL, with scrypt
password hashing (see web/db.py). This is client-server auth only and is
independent of the E2EE identity keys.

Run:
    python -m server.app                 # relay server (port 8765)
    python -m web.bridge                 # this bridge: web UI + browser API
    # open http://127.0.0.1:8000, register/login, chat
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import http.server
import json
import os
import threading

import websockets

from crypto import fingerprint
from client import handshake, identity, messaging
from client.cli import ClientApp
from client.transport import Transport
from protocol.constants import MSG_ERROR
from web.db import UserDB

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
KEYSTORE = "client_store"
MIN_PASSWORD_LEN = 8

# Translations for the few control strings the relay server emits.
_SERVER_ZH = {
    "recipient offline": "对方当前不在线",
}


class BridgeApp(ClientApp):
    """ClientApp whose feedback is pushed to a browser as Chinese JSON events."""

    def __init__(self, ident, transport, browser_ws) -> None:
        super().__init__(ident, transport)
        self.browser_ws = browser_ws

    # --- emit to browser ----------------------------------------------------
    def _emit(self, payload: dict) -> None:
        task = asyncio.create_task(self._safe_send(payload))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _safe_send(self, payload: dict) -> None:
        try:
            await self.browser_ws.send(json.dumps(payload))
        except Exception:
            pass

    def _log(self, text: str) -> None:
        # Suppress the CLI's English diagnostics; the bridge emits Chinese events.
        pass

    def _info(self, text: str) -> None:
        self._emit({"event": "info", "text": text})

    # --- outgoing actions (called by the browser handler) -------------------
    async def chat(self, peer: str) -> None:
        if not peer:
            self._emit({"event": "error", "message": "请输入对方用户名"})
            return
        peer_key = await self._get_peer_key(peer)
        if peer_key is None:
            self._emit({"event": "error", "message": f"用户「{peer}」不存在或未上线"})
            return
        hs_init, pending = handshake.initiate(
            self.id.private_key, self.id.username, peer, peer_key)
        self.pending[pending.session_id] = pending
        await self.transport.send(hs_init)
        self._info(f"正在与 {peer} 建立加密会话…")

    async def send_message(self, peer: str, text: str) -> bool:
        session = self.sessions.get(peer)
        if session is None:
            self._emit({"event": "error", "message": f"尚未与 {peer} 建立会话"})
            return False
        await self.transport.send(messaging.encrypt_message(session, text.encode()))
        return True

    def verify(self, peer: str) -> None:
        peer_key = self.peer_keys.get(peer)
        if peer_key is None:
            self._emit({"event": "error", "message": f"尚无 {peer} 的公钥，请先建立会话"})
            return
        number = fingerprint.safety_number(self.id.public_bytes, peer_key)
        self._emit({"event": "safety", "peer": peer, "number": number})

    # --- inbound handlers (Chinese) ----------------------------------------
    async def _handle(self, msg: dict) -> None:
        if msg["type"] == MSG_ERROR:
            reason = msg.get("reason", "")
            if reason.startswith("register:"):
                return  # already reflected by the bridge's "ready" event
            self._info(_SERVER_ZH.get(reason, reason))
            return
        await super()._handle(msg)

    async def _on_hs_init(self, msg: dict) -> None:
        peer = msg["from"]
        peer_key = await self._get_peer_key(peer)
        if peer_key is None:
            self._info(f"无法验证来自 {peer} 的握手（对方未注册）")
            return
        try:
            hs_resp, session = handshake.respond(
                self.id.private_key, self.id.username, peer_key, msg)
        except handshake.HandshakeError as exc:
            self._emit({"event": "error", "message": f"已拒绝来自 {peer} 的握手：{exc}"})
            return
        self.sessions[peer] = session
        self.active_peer = peer
        await self.transport.send(hs_resp)
        self._emit({"event": "session", "peer": peer})
        self._info(f"已与 {peer} 建立加密会话（对方发起）")

    def _on_hs_resp(self, msg: dict) -> None:
        pending = self.pending.pop(msg.get("session_id"), None)
        if pending is None:
            self._info("收到意外的握手响应")
            return
        try:
            session = handshake.complete(pending, msg)
        except handshake.HandshakeError as exc:
            self._emit({"event": "error", "message": f"握手失败：{exc}"})
            return
        self.sessions[pending.remote_name] = session
        self.active_peer = pending.remote_name
        self._emit({"event": "session", "peer": pending.remote_name})
        self._info(f"已与 {pending.remote_name} 建立加密会话")

    def _on_data(self, msg: dict) -> None:
        peer = msg["from"]
        session = self.sessions.get(peer)
        if session is None:
            self._info(f"收到来自 {peer} 的消息但无会话，已丢弃")
            return
        try:
            plaintext = messaging.decrypt_message(session, msg)
        except messaging.MessageError as exc:
            self._emit({"event": "error", "message": f"已拒绝来自 {peer} 的消息：{exc}"})
            return
        self._emit({"event": "message", "peer": peer, "dir": "in",
                    "text": plaintext.decode(errors="replace")})

    async def recv_loop(self) -> None:
        try:
            while True:
                await self._handle(await self.transport.recv())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._info(f"与服务器的连接已断开：{exc}")


async def _send(ws, payload: dict) -> None:
    await ws.send(json.dumps(payload))


def _make_browser_handler(relay_url: str, db: UserDB):
    async def browser_handler(browser_ws) -> None:
        app: BridgeApp | None = None
        recv_task: asyncio.Task | None = None
        try:
            async for raw in browser_ws:
                try:
                    cmd = json.loads(raw)
                except (ValueError, TypeError):
                    await _send(browser_ws, {"event": "error", "message": "请求格式错误"})
                    continue
                action = cmd.get("action")

                if action in ("register", "login"):
                    if app is not None:
                        await _send(browser_ws, {"event": "error", "message": "已登录，请刷新页面切换用户"})
                        continue
                    username = (cmd.get("username") or "").strip()
                    password = cmd.get("password") or ""
                    if not username or not password:
                        await _send(browser_ws, {"event": "error", "message": "用户名和密码均不能为空"})
                        continue

                    try:
                        if action == "register":
                            if len(password) < MIN_PASSWORD_LEN:
                                await _send(browser_ws, {"event": "error",
                                            "message": f"密码至少 {MIN_PASSWORD_LEN} 位"})
                                continue
                            if not db.create(username, password):
                                await _send(browser_ws, {"event": "error", "message": "用户名已存在，请直接登录"})
                                continue
                        else:  # login
                            if not db.verify(username, password):
                                await _send(browser_ws, {"event": "error", "message": "用户名或密码错误"})
                                continue
                    except Exception as exc:
                        await _send(browser_ws, {"event": "error",
                                    "message": f"数据库错误：{exc}"})
                        continue

                    ident = identity.load_or_create(username, keystore_dir=KEYSTORE)
                    transport = await Transport.connect(relay_url)
                    app = BridgeApp(ident, transport, browser_ws)
                    await app.register()
                    recv_task = asyncio.create_task(app.recv_loop())
                    await _send(browser_ws, {
                        "event": "ready",
                        "username": username,
                        "fingerprint": fingerprint.fingerprint(ident.public_bytes),
                    })

                elif action == "chat":
                    if app is None:
                        await _send(browser_ws, {"event": "error", "message": "请先登录"})
                        continue
                    await app.chat((cmd.get("peer") or "").strip())

                elif action == "send":
                    if app is None:
                        await _send(browser_ws, {"event": "error", "message": "请先登录"})
                        continue
                    peer = (cmd.get("peer") or "").strip()
                    text = cmd.get("text") or ""
                    if await app.send_message(peer, text):
                        await _send(browser_ws, {"event": "message", "peer": peer,
                                                 "dir": "out", "text": text})

                elif action == "verify":
                    if app is None:
                        await _send(browser_ws, {"event": "error", "message": "请先登录"})
                        continue
                    app.verify((cmd.get("peer") or "").strip())

                else:
                    await _send(browser_ws, {"event": "error", "message": f"未知指令：{action}"})
        except websockets.ConnectionClosed:
            pass
        finally:
            if recv_task is not None:
                recv_task.cancel()
            if app is not None:
                try:
                    await app.transport.close()
                except Exception:
                    pass

    return browser_handler


def _start_http(host: str, port: int) -> None:
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=WEB_DIR)
    httpd = http.server.ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"web UI on http://{host}:{port}")


async def serve(host: str, http_port: int, ws_port: int, relay_url: str) -> None:
    db = UserDB()
    try:
        db.init()
        print(f"MySQL ready: {db.cfg['user']}@{db.cfg['host']}:{db.cfg['port']}/{db.cfg['db']}")
    except Exception as exc:
        print("\n[!] 无法连接 MySQL，注册/登录将不可用。")
        print(f"    {exc}")
        print("    请设置环境变量 MYSQL_USER / MYSQL_PASSWORD / MYSQL_DB 后重试。\n")

    _start_http(host, http_port)
    handler = _make_browser_handler(relay_url, db)
    async with websockets.serve(handler, host, ws_port):
        print(f"bridge API on ws://{host}:{ws_port}  (relay: {relay_url})")
        await asyncio.Future()


def main() -> None:
    parser = argparse.ArgumentParser(description="Local web bridge for the E2EE client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8000)
    parser.add_argument("--ws-port", type=int, default=8766)
    parser.add_argument("--relay", default="ws://127.0.0.1:8765")
    args = parser.parse_args()
    try:
        asyncio.run(serve(args.host, args.http_port, args.ws_port, args.relay))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
