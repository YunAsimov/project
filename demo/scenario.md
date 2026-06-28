# Demo scenario — two-client message exchange

Scripted scenario for the README / presentation (Criterion 4).

## Steps

1. Start the relay server.
2. Register Alice and Bob (each generates an Ed25519 identity locally,
   publishes the public key).
3. (Optional, B2) Alice and Bob compare safety numbers out of band.
4. Alice looks up Bob's public key and runs the authenticated handshake.
5. Alice sends "hello" -> Bob decrypts and displays it.
6. Bob replies -> Alice decrypts and displays it.

## Adversary demonstrations (Criterion 3)

- **A1 passive:** show captured traffic is ciphertext only.
- **A2 tamper:** flip a ciphertext byte in transit -> recipient rejects.
- **A2 replay:** resend a captured message -> recipient rejects (SR4).
- **A3 server view:** print what the server sees (ciphertext + metadata, no plaintext).
