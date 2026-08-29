"""Token-bucket rate limiter for MCP tool calls."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class Bucket:
    tokens: float
    last_refill: float
    max_tokens: float
    refill_rate: float  # tokens per second

    def consume(self, n: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


class RateLimiter:
    """Per-client token-bucket rate limiter."""

    def __init__(self, rpm: int = 120, burst: int = 20):
        self._rpm = rpm
        self._burst = burst
        self._buckets: dict[str, Bucket] = defaultdict(
            lambda: Bucket(
                tokens=float(burst),
                last_refill=time.monotonic(),
                max_tokens=float(burst),
                refill_rate=rpm / 60.0,
            )
        )

    def allow(self, client_id: str = "default") -> bool:
        return self._buckets[client_id].consume()

    def remaining(self, client_id: str = "default") -> int:
        bucket = self._buckets[client_id]
        now = time.monotonic()
        elapsed = now - bucket.last_refill
        tokens = min(bucket.max_tokens, bucket.tokens + elapsed * bucket.refill_rate)
        return int(tokens)
