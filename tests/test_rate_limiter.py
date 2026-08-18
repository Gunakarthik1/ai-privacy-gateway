"""
Tests for the TokenBucketRateLimiter.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import threading
import pytest
from gateway.rate_limiter import TokenBucketRateLimiter


@pytest.fixture
def limiter():
    return TokenBucketRateLimiter(capacity=10, refill_rate=10.0)


class TestTokenConsumption:
    def test_first_request_allowed(self, limiter):
        allowed, remaining, retry_ms = limiter.check("key-a")
        assert allowed is True
        assert remaining == 9  # 10 - 1

    def test_subsequent_requests_consume_tokens(self, limiter):
        key = "key-b"
        for _ in range(5):
            allowed, _, _ = limiter.check(key)
            assert allowed is True

        _, remaining, _ = limiter.check(key)
        assert remaining < 5

    def test_exhausted_bucket_blocks(self, limiter):
        key = "key-c"
        # Drain all 10 tokens
        for _ in range(10):
            limiter.check(key)
        # Next request should be blocked
        allowed, remaining, retry_ms = limiter.check(key)
        assert allowed is False
        assert remaining == 0
        assert retry_ms > 0

    def test_retry_after_positive_when_blocked(self, limiter):
        key = "key-d"
        for _ in range(10):
            limiter.check(key)
        allowed, _, retry_ms = limiter.check(key)
        assert not allowed
        assert retry_ms > 0

    def test_different_keys_independent(self, limiter):
        for _ in range(10):
            limiter.check("key-x")
        # Exhaust key-x — key-y should still be full
        allowed_y, remaining_y, _ = limiter.check("key-y")
        assert allowed_y is True
        assert remaining_y == 9


class TestRefill:
    def test_tokens_refill_over_time(self):
        # Use a fast refill rate for testing
        limiter = TokenBucketRateLimiter(capacity=5, refill_rate=50.0)
        key = "refill-test"
        # Drain all tokens
        for _ in range(5):
            limiter.check(key)
        # Wait for refill (50 tokens/sec → 5 tokens in 0.1s)
        time.sleep(0.12)
        allowed, remaining, _ = limiter.check(key)
        assert allowed is True

    def test_tokens_do_not_exceed_capacity(self):
        limiter = TokenBucketRateLimiter(capacity=5, refill_rate=100.0)
        key = "cap-test"
        time.sleep(0.1)  # Plenty of refill time
        stats = limiter.get_stats(key)
        assert stats.current_tokens <= 5.0


class TestStats:
    def test_stats_requests_made(self, limiter):
        key = "stats-a"
        for _ in range(3):
            limiter.check(key)
        stats = limiter.get_stats(key)
        assert stats.requests_made == 3
        assert stats.requests_blocked == 0

    def test_stats_requests_blocked(self, limiter):
        key = "stats-b"
        for _ in range(10):
            limiter.check(key)
        for _ in range(3):
            limiter.check(key)
        stats = limiter.get_stats(key)
        assert stats.requests_blocked == 3

    def test_stats_current_tokens(self, limiter):
        key = "stats-c"
        limiter.check(key)
        stats = limiter.get_stats(key)
        assert 0 <= stats.current_tokens <= 10

    def test_stats_unknown_key_defaults(self, limiter):
        stats = limiter.get_stats("brand-new-key")
        assert stats.requests_made == 0
        assert stats.requests_blocked == 0
        assert stats.current_tokens == limiter._capacity


class TestReset:
    def test_reset_restores_full_bucket(self, limiter):
        key = "reset-key"
        for _ in range(10):
            limiter.check(key)
        limiter.reset(key)
        allowed, remaining, _ = limiter.check(key)
        assert allowed is True
        assert remaining == 9


class TestThreadSafety:
    def test_concurrent_requests(self):
        limiter = TokenBucketRateLimiter(capacity=50, refill_rate=5.0)
        key = "concurrent"
        results = []
        lock = threading.Lock()

        def fire():
            r = limiter.check(key)
            with lock:
                results.append(r[0])

        threads = [threading.Thread(target=fire) for _ in range(60)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed_count = sum(1 for r in results if r)
        blocked_count = sum(1 for r in results if not r)
        # Exactly 50 should be allowed, 10 blocked
        assert allowed_count == 50
        assert blocked_count == 10
