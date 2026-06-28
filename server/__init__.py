"""Relay server package (weakly trusted: honest-but-curious, A3).

Provides registration, public-key distribution, and message routing.
Only ever handles ciphertext and routing metadata — never plaintext or keys.
"""
