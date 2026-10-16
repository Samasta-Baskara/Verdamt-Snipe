"""Paket 3 (sync→async refactor): ParamBruteforcer sync façade.

The sync class used to carry a full duplicate of the diffing logic
(ThreadPoolExecutor + thttp). It now only delegates to
AsyncParamBruteforcer inside a private event loop — these tests pin
that contract so the two implementations cannot drift apart again.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from modules.extras.arjun import PARAM_WORDLIST, AsyncParamBruteforcer, ParamBruteforcer


class TestParamBruteforcerFacade(unittest.TestCase):
    def test_init_strips_params_and_defaults_wordlist(self):
        bf = ParamBruteforcer("https://example.com/page?id=1&x=2")
        self.assertEqual(bf.url, "https://example.com/page")
        self.assertIs(bf.wordlist, PARAM_WORDLIST)

    def test_run_delegates_to_async_implementation_and_sorts(self):
        bf = ParamBruteforcer("https://example.com/page", wordlist=["zeta", "alpha"])

        async def fake_run(self):
            return ["zeta", "alpha"]

        with patch.object(AsyncParamBruteforcer, "run", fake_run), \
             patch("modules.extras.arjun.AsyncNetworkEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.close = AsyncMock()
            mock_engine_cls.return_value = mock_engine

            result = bf.run()

        self.assertEqual(result, ["alpha", "zeta"])
        self.assertEqual(bf.found, {"alpha", "zeta"})
        # engine constructed with the sync caller's policy and closed after
        self.assertIs(mock_engine_cls.call_args.kwargs.get("policy"), None)
        mock_engine.close.assert_awaited_once()

    def test_engine_closed_even_when_async_run_raises(self):
        bf = ParamBruteforcer("https://example.com/page")

        async def boom(self):
            raise RuntimeError("scan exploded")

        with patch.object(AsyncParamBruteforcer, "run", boom), \
             patch("modules.extras.arjun.AsyncNetworkEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.close = AsyncMock()
            mock_engine_cls.return_value = mock_engine

            with self.assertRaises(RuntimeError):
                bf.run()

            mock_engine.close.assert_awaited_once()

    def test_threads_maps_to_concurrency(self):
        bf = ParamBruteforcer("https://example.com/page", threads=7)
        seen = {}

        async def fake_run(self):
            seen["concurrency"] = self.concurrency
            return []

        with patch.object(AsyncParamBruteforcer, "run", fake_run), \
             patch("modules.extras.arjun.AsyncNetworkEngine") as mock_engine_cls:
            mock_engine_cls.return_value.close = AsyncMock()
            bf.run()

        self.assertEqual(seen["concurrency"], 7)


class TestAsyncParamBruteforcerBasics(unittest.IsolatedAsyncioTestCase):
    async def test_send_respects_semaphore_and_passes_session(self):
        engine = MagicMock()
        engine.ahttp_send = AsyncMock(return_value={"status": 200, "body": "x", "headers": {}})
        session = object()
        bf = AsyncParamBruteforcer("https://example.com/", engine, concurrency=2,
                                   session_manager=session)

        r = await bf._send("https://example.com/?a=1", timeout=5)

        self.assertEqual(r["status"], 200)
        engine.ahttp_send.assert_awaited_once_with(
            "https://example.com/?a=1", timeout=5, state_context=session
        )
        self.assertEqual(bf._sem._value, 2)  # semaphore released after send

    async def test_rate_limited_response_increments_counter(self):
        engine = MagicMock()
        engine.ahttp_send = AsyncMock(return_value={"status": 429, "body": "", "headers": {}})
        bf = AsyncParamBruteforcer("https://example.com/", engine)
        bf.baseline = {"status": 200, "length": 1, "body_hash": 0, "headers": set()}

        hit = await bf._test_single("token")

        self.assertIsNone(hit)
        self.assertEqual(bf.rate_limited, 1)


if __name__ == "__main__":
    unittest.main()
