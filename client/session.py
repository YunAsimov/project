"""Per-session state: directional keys, send counter, replay window.

A session holds two AEAD keys derived by the handshake:
  - send_key: used to encrypt outgoing messages
  - recv_key: used to decrypt incoming messages
The two directions use *different* keys so that both counters can start at 0
without ever reusing a (key, nonce) pair.

Replay protection (SR4): outgoing messages carry a monotonic counter. The
receiver tracks the highest counter seen plus a sliding bitmap window of recent
counters (RFC 6479-style); duplicates and out-of-window counters are rejected.
"""

from __future__ import annotations

from protocol.constants import AEAD_NONCE_LEN, REPLAY_WINDOW_SIZE


class Session:
    """Cryptographic state for one established session between two users."""

    def __init__(
        self,
        session_id: str,
        send_key: bytes,
        recv_key: bytes,
        local_name: str,
        remote_name: str,
    ) -> None:
        self.session_id = session_id
        self.send_key = send_key
        self.recv_key = recv_key
        self.local_name = local_name
        self.remote_name = remote_name

        self._send_counter = 0           # next counter to use when sending
        self._recv_highest = -1          # highest counter accepted so far
        self._recv_bitmap = 0            # window: bit p set => (highest - p) seen
        self._window_mask = (1 << REPLAY_WINDOW_SIZE) - 1

    # --- sending ------------------------------------------------------------

    def next_send_counter(self) -> int:
        """Return a fresh, never-reused counter for an outgoing message."""
        counter = self._send_counter
        self._send_counter += 1
        return counter

    # --- receiving / replay protection -------------------------------------

    def accept_recv_counter(self, counter: int) -> bool:
        """Check `counter` against the replay window; update state if accepted.

        Returns False (without changing state) for duplicates, out-of-window
        (too old) counters, or negative values — the caller must drop the
        message. Returns True for fresh counters and records them.
        """
        if counter < 0:
            return False

        if counter > self._recv_highest:
            # New highest: slide the window forward by the gap.
            shift = counter - self._recv_highest
            if shift >= REPLAY_WINDOW_SIZE:
                self._recv_bitmap = 0
            else:
                self._recv_bitmap = (self._recv_bitmap << shift) & self._window_mask
            self._recv_bitmap |= 1  # bit 0 marks the new highest as seen
            self._recv_highest = counter
            return True

        # counter <= highest: must fall within the window and be unseen.
        offset = self._recv_highest - counter
        if offset >= REPLAY_WINDOW_SIZE:
            return False  # too old
        if self._recv_bitmap & (1 << offset):
            return False  # already seen -> replay
        self._recv_bitmap |= (1 << offset)
        return True

    # --- nonce derivation ---------------------------------------------------

    @staticmethod
    def nonce_for_counter(counter: int) -> bytes:
        """Deterministic AEAD nonce from a counter (unique per key/direction).

        Counters are unique per direction and each direction has its own key,
        so the derived nonce is never reused under a given key.
        """
        return counter.to_bytes(AEAD_NONCE_LEN, "big")
