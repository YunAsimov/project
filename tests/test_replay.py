"""Replay-protection / session-window tests (SR4)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.session import Session
from protocol.constants import REPLAY_WINDOW_SIZE


def _session() -> Session:
    return Session("sess", b"\x01" * 32, b"\x02" * 32, "alice", "bob")


# --- send counters ----------------------------------------------------------

def test_send_counter_is_monotonic_and_unique():
    s = _session()
    counters = [s.next_send_counter() for _ in range(5)]
    assert counters == [0, 1, 2, 3, 4]


def test_nonce_unique_per_counter():
    nonces = {Session.nonce_for_counter(i) for i in range(100)}
    assert len(nonces) == 100


# --- replay window ----------------------------------------------------------

def test_in_order_counters_accepted():
    s = _session()
    assert all(s.accept_recv_counter(i) for i in range(10))


def test_duplicate_counter_rejected():
    s = _session()
    assert s.accept_recv_counter(5) is True
    assert s.accept_recv_counter(5) is False  # replay


def test_out_of_order_within_window_accepted_once():
    s = _session()
    assert s.accept_recv_counter(10) is True
    assert s.accept_recv_counter(8) is True   # older but within window, unseen
    assert s.accept_recv_counter(8) is False  # now a replay


def test_out_of_window_counter_rejected():
    s = _session()
    assert s.accept_recv_counter(REPLAY_WINDOW_SIZE + 5) is True
    # 0 is now far below the window -> rejected as too old
    assert s.accept_recv_counter(0) is False


def test_large_jump_forward_accepted():
    s = _session()
    assert s.accept_recv_counter(0) is True
    assert s.accept_recv_counter(1000) is True
    assert s.accept_recv_counter(999) is True   # within window of new highest
    assert s.accept_recv_counter(1000) is False  # replay of highest


def test_negative_counter_rejected():
    s = _session()
    assert s.accept_recv_counter(-1) is False


def test_window_boundary_exact():
    s = _session()
    assert s.accept_recv_counter(REPLAY_WINDOW_SIZE) is True
    # offset == WINDOW_SIZE is just outside the window
    assert s.accept_recv_counter(0) is False
    # offset == WINDOW_SIZE - 1 is the oldest still inside
    assert s.accept_recv_counter(1) is True
