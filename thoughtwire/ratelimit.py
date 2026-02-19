"""
Thoughtwire Rate Limiter — Token bucket rate limiting for MQTT publish.

Provides both outbound (publish) and inbound (receive) rate limiting
at the application layer. Portable — travels with the code, not the host.
"""

import logging
import threading
import time

log = logging.getLogger("thoughtwire.ratelimit")


class TokenBucket:
    """Token bucket rate limiter.
    
    Allows `rate` messages per second with burst capacity of `burst`.
    Thread-safe.
    """
    
    def __init__(self, rate: float = 50.0, burst: int = 100):
        self.rate = rate          # tokens per second
        self.burst = burst        # max tokens (burst capacity)
        self.tokens = float(burst)
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()
    
    def consume(self, n: int = 1) -> bool:
        """Try to consume n tokens. Returns True if allowed, False if rate limited."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now
            
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False
    
    def wait(self, n: int = 1, timeout: float = 5.0) -> bool:
        """Block until tokens available or timeout. Returns True if acquired."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.consume(n):
                return True
            time.sleep(0.01)
        return False


class RateLimiter:
    """Per-client rate limiter for Thoughtwire agents.
    
    Tracks publish rates per client/agent and enforces limits.
    """
    
    def __init__(self, publish_rate: float = 50.0, publish_burst: int = 100,
                 inbound_rate: float = 100.0, inbound_burst: int = 200):
        self.publish_rate = publish_rate
        self.publish_burst = publish_burst
        self.inbound_rate = inbound_rate
        self.inbound_burst = inbound_burst
        
        self._publish_bucket = TokenBucket(publish_rate, publish_burst)
        self._inbound_buckets = {}  # per-sender
        self._lock = threading.Lock()
        
        # Stats
        self.publish_allowed = 0
        self.publish_denied = 0
        self.inbound_allowed = 0
        self.inbound_denied = 0
    
    def check_publish(self) -> bool:
        """Check if we can publish a message. Returns True if allowed."""
        if self._publish_bucket.consume():
            self.publish_allowed += 1
            return True
        self.publish_denied += 1
        log.warning(f"🚫 Publish rate limited ({self.publish_rate}/s)")
        return False
    
    def check_inbound(self, sender_id: str) -> bool:
        """Check if we should accept an inbound message from sender."""
        with self._lock:
            if sender_id not in self._inbound_buckets:
                self._inbound_buckets[sender_id] = TokenBucket(
                    self.inbound_rate, self.inbound_burst
                )
        
        bucket = self._inbound_buckets[sender_id]
        if bucket.consume():
            self.inbound_allowed += 1
            return True
        self.inbound_denied += 1
        log.warning(f"🚫 Inbound rate limited from {sender_id}")
        return False
    
    def stats(self) -> dict:
        return {
            "publish_rate": self.publish_rate,
            "publish_burst": self.publish_burst,
            "publish_allowed": self.publish_allowed,
            "publish_denied": self.publish_denied,
            "inbound_rate": self.inbound_rate,
            "inbound_burst": self.inbound_burst,
            "inbound_allowed": self.inbound_allowed,
            "inbound_denied": self.inbound_denied,
            "tracked_senders": len(self._inbound_buckets),
        }


# Default instance — 50 msg/s publish, 100 msg/s per inbound sender
_default = None


def get_default(publish_rate: float = 50.0, publish_burst: int = 100,
                inbound_rate: float = 100.0, inbound_burst: int = 200) -> RateLimiter:
    """Get or create the default rate limiter."""
    global _default
    if _default is None:
        _default = RateLimiter(publish_rate, publish_burst,
                               inbound_rate, inbound_burst)
    return _default
