# COMP5355 Group Report — E2EE Messaging System (Task 1)

> Weighting reminder: the four criteria are 25% each, three of which are
> design / crypto / defense reasoning. Keep this document in sync with the code.

## 1. System Design & Threat Model (Criterion 1)
- Architecture diagram (sender, relay server, recipient) — see `diagrams/`.
- Trust boundaries & assumptions (endpoints trusted; server honest-but-curious;
  network fully adversarial). State out-of-scope items (availability, endpoint
  compromise except bonus A4).
- Handshake & message-flow diagram, matching the implementation.

## 2. Protocol & Key-Management Lifecycle
- Identity keys (Ed25519): generation, storage, distribution.
- Session keys: ephemeral X25519 + HKDF-SHA256 derivation, lifetime, disposal.
- Wire format for each message type (cross-reference `protocol/messages.py`).

## 3. Per-Adversary Defense Argument
| Adversary | Mechanism | Requirement | Residual limitation |
|-----------|-----------|-------------|---------------------|
| A1 passive | AEAD encryption | SR1 | metadata/length leakage |
| A2 active — tamper | AEAD tag | SR2 | — |
| A2 active — MitM | signed handshake | SR3 | trust in key distribution |
| A2 active — replay | counter + window | SR4 | — |
| A3 server | E2E encryption | SR1 | sees routing metadata |

## 4. Bonus (if attempted)
- B1 Forward Secrecy (vs A4): ephemeral keys discarded per session.
- B2 Malicious-Server Resistance (vs A5): out-of-band safety-number comparison.

## 5. Mapping code ↔ design
- crypto/, client/, server/, protocol/ — brief pointer per module.
