import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.host_ratelimit import HostRateLimiter
from core.http_client import GhostMode
from core.resilience import CircuitBreaker


class TestGhostModeAsync(unittest.IsolatedAsyncioTestCase):
    def test_ghost_mode_stealth_headers(self):
        headers = GhostMode.get_stealth_headers("test.com")
        self.assertEqual(headers["Host"], "test.com")
        self.assertIn("User-Agent", headers)
        self.assertEqual(headers["Connection"], "close")


class TestGhostModeAutoStealth(unittest.TestCase):
    """Auto-stealth chain: RateLimiter escalation drives GhostMode headers."""

    def test_rate_limiter_drives_auto_stealth(self):
        from core.ratelimit import RateLimiter
        rl = RateLimiter(per_host_delay=0.01)
        GhostMode.ENABLED = False
        GhostMode.set_rate_limiter(rl)
        try:
            self.assertFalse(GhostMode.should_stealth("waf.example"))
            rl._host_stealth_auto["waf.example"] = True
            self.assertTrue(GhostMode.should_stealth("waf.example"))
        finally:
            GhostMode.set_rate_limiter(None)

    def test_global_rate_limiter_is_a_singleton(self):
        from core.ratelimit import get_global_rate_limiter
        self.assertIs(get_global_rate_limiter(), get_global_rate_limiter())


class TestHostRateLimiter(unittest.IsolatedAsyncioTestCase):
    async def test_acquire_and_release(self):
        limiter = HostRateLimiter(default_max_concurrent=2)
        # Acquire slot
        res1 = await limiter.acquire("example.com")
        res2 = await limiter.acquire("example.com")
        self.assertTrue(res1)
        self.assertTrue(res2)

        # Release with status 200
        limiter.release("example.com", status=200)
        limiter.release("example.com", status=200)

    async def test_backoff_on_429(self):
        limiter = HostRateLimiter(default_max_concurrent=2)
        await limiter.acquire("example.com")
        # Release with 429 rate limit
        limiter.release("example.com", status=429)
        # Should trigger backoff for example.com
        state = limiter._hosts.get("example.com")
        self.assertIsNotNone(state)
        self.assertGreater(state.backoff_until, 0)


class TestCircuitBreaker(unittest.TestCase):
    def setUp(self):
        self.cb = CircuitBreaker(failure_threshold=3, cooldown_base=5)

    def test_circuit_state_transition(self):
        host = "target.com"
        self.assertTrue(self.cb.allow_request(host))

        # Record failures (429/403)
        self.cb.record_failure(host, status_code=429)
        self.cb.record_failure(host, status_code=429)
        self.assertTrue(self.cb.allow_request(host))

        # 3rd failure opens circuit
        self.cb.record_failure(host, status_code=429)
        self.assertFalse(self.cb.allow_request(host))
        self.assertGreater(self.cb.get_cooldown_remaining(host), 0)

        # Reset circuit breaker
        self.cb.reset(host)
        self.assertTrue(self.cb.allow_request(host))


class TestAdaptiveRateLimiter(unittest.TestCase):
    def test_adaptive_backoff_escalation_and_recovery(self):
        from core.ratelimit import RateLimiter
        limiter = RateLimiter(per_host_delay=0.1, max_backoff=5.0)

        # Baseline check
        self.assertFalse(limiter.is_adaptive_active("target.com"))
        self.assertFalse(limiter.is_auto_stealth("target.com"))

        # Feed 429 anomalies into sliding window
        for _ in range(5):
            limiter.report_response("target.com", 429)

        # Should escalate and enable auto-stealth
        self.assertTrue(limiter.is_adaptive_active("target.com"))
        self.assertTrue(limiter.is_auto_stealth("target.com"))
        self.assertGreater(limiter.get_host_delay("target.com"), 0.1)

        # Feed consecutive 200 OK success streak (recovery)
        # Need enough to: (1) flush anomalies from 50-entry sliding window (~48)
        # and (2) gradually reduce delay back to baseline via 0.85x factor (~24)
        for _ in range(100):
            limiter.report_response("target.com", 200)

        # Should recover and deactivate adaptive auto-stealth
        self.assertFalse(limiter.is_adaptive_active("target.com"))
        self.assertFalse(limiter.is_auto_stealth("target.com"))


if __name__ == "__main__":
    unittest.main()
