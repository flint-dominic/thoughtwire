"""Tests for replay protection."""

import time
from thoughtwire.signing import ReplayGuard
from thoughtwire.protocol import encode


class TestReplayGuard:
    def setup_method(self):
        self.guard = ReplayGuard(max_age_seconds=60, max_nonces=100)

    def test_accept_fresh_frame(self):
        frame = encode("chat", 1, 1.0, "inform", b"hello")
        ts = int(time.time())
        ok, reason = self.guard.check(frame, ts)
        assert ok is True
        assert reason is None

    def test_reject_duplicate(self):
        frame = encode("chat", 1, 1.0, "inform", b"hello")
        ts = int(time.time())
        ok1, _ = self.guard.check(frame, ts)
        ok2, reason = self.guard.check(frame, ts)
        assert ok1 is True
        assert ok2 is False
        assert "replay" in reason

    def test_reject_expired(self):
        frame = encode("chat", 1, 1.0, "inform", b"old message")
        old_ts = int(time.time()) - 300  # 5 min ago, max_age is 60
        ok, reason = self.guard.check(frame, old_ts)
        assert ok is False
        assert "expired" in reason

    def test_different_frames_accepted(self):
        f1 = encode("chat", 1, 1.0, "inform", b"message 1")
        f2 = encode("chat", 1, 1.0, "inform", b"message 2")
        ts = int(time.time())
        ok1, _ = self.guard.check(f1, ts)
        ok2, _ = self.guard.check(f2, ts)
        assert ok1 is True
        assert ok2 is True

    def test_eviction_by_size(self):
        guard = ReplayGuard(max_age_seconds=3600, max_nonces=5)
        ts = int(time.time())
        for i in range(10):
            frame = encode("chat", 1, 1.0, "inform", f"msg-{i}".encode())
            guard.check(frame, ts)
        assert len(guard._seen) <= 5

    def test_eviction_by_time(self):
        guard = ReplayGuard(max_age_seconds=1, max_nonces=10000)
        ts = int(time.time())
        frame = encode("chat", 1, 1.0, "inform", b"old")
        guard.check(frame, ts)
        assert len(guard._seen) == 1
        
        # Simulate time passing by manipulating the stored timestamp
        nonce = list(guard._seen.keys())[0]
        guard._seen[nonce] = time.time() - 5  # 5 seconds ago
        
        # New frame triggers eviction
        frame2 = encode("chat", 1, 1.0, "inform", b"new")
        guard.check(frame2, ts)
        assert len(guard._seen) == 1  # old one evicted

    def test_stats(self):
        guard = ReplayGuard(max_age_seconds=60)
        ts = int(time.time())
        frame = encode("chat", 1, 1.0, "inform", b"test")
        guard.check(frame, ts)
        guard.check(frame, ts)  # duplicate
        
        s = guard.stats()
        assert s["accepted"] == 1
        assert s["rejected_replay"] == 1
        assert s["nonces_cached"] == 1
        assert s["max_age_seconds"] == 60

    def test_future_timestamp_within_window(self):
        """Frames slightly in the future (clock skew) should be accepted."""
        frame = encode("chat", 1, 1.0, "inform", b"future")
        ts = int(time.time()) + 30  # 30s in the future, within 60s window
        ok, _ = self.guard.check(frame, ts)
        assert ok is True

    def test_future_timestamp_outside_window(self):
        """Frames far in the future should be rejected."""
        frame = encode("chat", 1, 1.0, "inform", b"way future")
        ts = int(time.time()) + 120  # 2min in the future, outside 60s window
        ok, reason = self.guard.check(frame, ts)
        assert ok is False
        assert "expired" in reason

    def test_thread_safety(self):
        """Basic concurrency test."""
        import threading
        guard = ReplayGuard(max_age_seconds=60, max_nonces=10000)
        ts = int(time.time())
        results = []

        def check_many(start):
            for i in range(100):
                frame = encode("chat", 1, 1.0, "inform", f"thread-{start}-{i}".encode())
                ok, _ = guard.check(frame, ts)
                results.append(ok)

        threads = [threading.Thread(target=check_many, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 400
        assert all(results)  # All unique, all should pass
        assert guard.stats()["accepted"] == 400
