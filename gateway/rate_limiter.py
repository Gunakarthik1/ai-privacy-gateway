"""
Token-bucket rate limiter with per-API-key state stored in memory.
Capacity: 100 tokens per key.  Refill rate: 10 tokens / second.
"""

import time
import threading
from typing import Dict, Tuple
from dataclasses import dataclass, field
from .models import RateLimitStats


BUCKET_CAPACITY: int = 100
REFILL_RATE: float = 10.0       # tokens per second
TOKENS_PER_REQUEST: float = 1.0 # cost per request
STALE_AFTER_SECONDS: int = 3600 # clean up keys idle for 1 hour


@dataclass
class _Bucket:
    tokens: float = float(BUCKET_CAPACITY)
    last_refill: float = field(default_factory=time.monotonic)
    requests_made: int = 0
    requests_blocked: int = 0
    last_access: float = field(default_factory=time.monotonic)


class TokenBucketRateLimiter:
    """
    Per-API-key token-bucket rate limiter.

    Thread-safe via a per-key lock strategy backed by a global registry lock.
    """

    def __init__(
        self,
        capacity: int = BUCKET_CAPACITY,
        refill_rate: float = REFILL_RATE,
        tokens_per_request: float = TOKENS_PER_REQUEST,
    ) -> None:
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._tokens_per_request = tokens_per_request
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_create(self, api_key: str) -> _Bucket:
        """Return the bucket for *api_key*, creating it if absent. Caller holds lock."""
        if api_key not in self._buckets:
            self._buckets[api_key] = _Bucket()
        return self._buckets[api_key]

    def _refill(self, bucket: _Bucket) -> None:
        """Add tokens based on elapsed time since last refill. Caller holds lock."""
        now = time.monotonic()
        elapsed = now - bucket.last_refill
        gained = elapsed * self._refill_rate
        bucket.tokens = min(self._capacity, bucket.tokens + gained)
        bucket.last_refill = now
        bucket.last_access = now

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, api_key: str) -> Tuple[bool, int, int]:
        """
        Attempt to consume one token for *api_key*.

        Returns:
            (allowed, remaining_tokens, retry_after_ms)
            - allowed: True if the request is permitted
            - remaining_tokens: integer tokens left after this call
            - retry_after_ms: milliseconds to wait before retrying (0 if allowed)
        """
        with self._lock:
            bucket = self._get_or_create(api_key)
            self._refill(bucket)

            if bucket.tokens >= self._tokens_per_request:
                bucket.tokens -= self._tokens_per_request
                bucket.requests_made += 1
                remaining = int(bucket.tokens)
                return True, remaining, 0
            else:
                bucket.requests_blocked += 1
                # Time until one token is available
                deficit = self._tokens_per_request - bucket.tokens
                retry_after_ms = int((deficit / self._refill_rate) * 1000)
                return False, 0, retry_after_ms

    def get_stats(self, api_key: str) -> RateLimitStats:
        """Return usage statistics for *api_key*."""
        with self._lock:
            bucket = self._get_or_create(api_key)
            self._refill(bucket)
            return RateLimitStats(
                api_key=api_key,
                requests_made=bucket.requests_made,
                requests_blocked=bucket.requests_blocked,
                current_tokens=round(bucket.tokens, 2),
                capacity=self._capacity,
                refill_rate=self._refill_rate,
            )

    def cleanup_stale(self) -> int:
        """
        Remove buckets that have not been accessed recently.
        Returns number of keys removed.
        """
        now = time.monotonic()
        with self._lock:
            stale = [
                k for k, b in self._buckets.items()
                if now - b.last_access > STALE_AFTER_SECONDS
            ]
            for k in stale:
                del self._buckets[k]
        return len(stale)

    def reset(self, api_key: str) -> None:
        """Reset a key's bucket to full capacity (useful for testing)."""
        with self._lock:
            self._buckets[api_key] = _Bucket()
