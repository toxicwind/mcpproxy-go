"""Tests for rate limiting."""

from mcp_nexus.middleware.rate_limit import RateLimiter


def test_basic_rate_limit():
    rl = RateLimiter(rpm=60, burst=5)
    # Should allow burst
    for _ in range(5):
        assert rl.allow("test") is True
    # Should deny after burst exhausted
    assert rl.allow("test") is False


def test_remaining():
    rl = RateLimiter(rpm=60, burst=10)
    assert rl.remaining("test") == 10
    rl.allow("test")
    # Should be 9 (approximately, due to refill)
    assert rl.remaining("test") <= 10


def test_separate_clients():
    rl = RateLimiter(rpm=60, burst=2)
    assert rl.allow("client-a") is True
    assert rl.allow("client-a") is True
    assert rl.allow("client-a") is False
    # Different client should still have tokens
    assert rl.allow("client-b") is True
