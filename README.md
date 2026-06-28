# E2EE Messaging System (COMP5355 Project — Task 1)

End-to-end encrypted one-to-one messaging system.

- **Identity keys:** Ed25519 (long-term, sign handshake material)
- **Key exchange:** ephemeral X25519 + signature → authenticated, forward-secret
- **KDF:** HKDF-SHA256
- **AEAD:** ChaCha20-Poly1305 (AD binds `sender‖recipient‖session_id‖counter`)
- **Replay protection:** monotonic counter + sliding window

Threat model: A1 (passive), A2 (active/MitM), A3 (honest-but-curious server),
satisfying SR1–SR4. Bonus targets: B1 forward secrecy, B2 malicious-server resistance.

## Requirements

- Python 3.10+
- See `requirements.txt`

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

## Run

```bash
# 1. start the relay server (terminal 1)
python -m server.app                 # listens on ws://127.0.0.1:8765

# 2. start two clients (terminals 2 and 3)
python -m client.cli chat --user alice
python -m client.cli chat --user bob
```

Each client auto-registers on connect (publishes its identity public key).
Inside a `chat` session:

```
/chat <peer>     # run the authenticated handshake with <peer>
/verify <peer>   # print the safety number for out-of-band comparison (B2)
/peers           # list established sessions
/quit            # exit
<text>           # send <text> to the most recently selected peer
```

Example: in Alice's terminal type `/chat bob`, wait for
`session established with bob`, then type a message. It appears in Bob's
terminal as `alice> ...`.

## Test

```bash
python -m pytest tests/ -q
```

## Project layout

```
server/    relay server (weakly trusted: only handles ciphertext + routing metadata)
client/    client (sole trust anchor: holds private keys and plaintext)
protocol/  shared wire-format / message definitions
crypto/    thin wrappers over the vetted `cryptography` library
tests/     unit tests (tamper / replay rejection, handshake)
demo/      scripted two-client demonstration
report/    group report + handshake & message-flow diagrams
```

## Security note

No secrets, private keys, or credentials are committed to this repository
(see `.gitignore`).
