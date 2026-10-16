"""Paket 4 (sync→async refactor): TakeoverChecker async conversion.

Old implementation spun a ThreadPoolExecutor around blocking
`subprocess.check_output(["host", ...])`. It now drives the same probe
through asyncio.create_subprocess_exec with a bounded semaphore —
these tests pin the detection contract and the concurrency bound.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from modules.extras.takeover import TakeoverChecker
from core.ratelimit import RateLimiter


def _fake_proc(output: bytes):
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(output, b""))
    return proc


class TestTakeoverCheckerAsync(unittest.IsolatedAsyncioTestCase):
    async def test_detects_dangling_cname_for_known_service(self):
        checker = TakeoverChecker(["dev.example.com"])
        output = b"dev.example.com is an alias for dev.example.s3.amazonaws.com.\n"

        with patch("asyncio.create_subprocess_exec",
                   AsyncMock(return_value=_fake_proc(output))) as mock_exec:
            results = await checker.run()

        mock_exec.assert_awaited_once_with(
            "host", "-t", "CNAME", "dev.example.com",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self.assertEqual(results, [{
            "sub": "dev.example.com",
            "cname": "dev.example.s3.amazonaws.com",
            "service": "AWS/S3",
            "risk": "High",
        }])
        self.assertEqual(checker.findings, results)

    async def test_no_cname_record_yields_no_findings(self):
        checker = TakeoverChecker(["plain.example.com"])
        with patch("asyncio.create_subprocess_exec",
                   AsyncMock(return_value=_fake_proc(b"Host plain.example.com not found: 3(NXDOMAIN)\n"))):
            results = await checker.run()
        self.assertEqual(results, [])

    async def test_broken_subprocess_is_swallowed_not_fatal(self):
        checker = TakeoverChecker(["ghost.example.com"])
        with patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=FileNotFoundError)):
            results = await checker.run()
        self.assertEqual(results, [])

    async def test_concurrency_bounded_by_semaphore(self):
        checker = TakeoverChecker([f"s{i}.example.com" for i in range(10)], concurrency=3)
        in_flight = {"now": 0, "peak": 0}

        async def slow_probe(sub):
            in_flight["now"] += 1
            in_flight["peak"] = max(in_flight["peak"], in_flight["now"])
            await asyncio.sleep(0.01)
            in_flight["now"] -= 1
            return None

        with patch.object(checker, "_check_cname", slow_probe):
            results = await checker.run()

        self.assertEqual(results, [])
        self.assertLessEqual(in_flight["peak"], 3)


class TestRateLimiterAsyncOnly(unittest.IsolatedAsyncioTestCase):
    async def test_wait_async_still_paces_requests(self):
        rl = RateLimiter(global_delay=0.0, per_host_delay=0.02, jitter=0.0)
        d1 = await rl.wait_async("example.com")
        d2 = await rl.wait_async("example.com")
        self.assertGreaterEqual(d2, 0.0)
        self.assertIsNotNone(d1)

    def test_sync_wait_api_removed(self):
        self.assertFalse(hasattr(RateLimiter, "wait"),
                         "sync RateLimiter.wait() was removed in the async refactor")


if __name__ == "__main__":
    unittest.main()
