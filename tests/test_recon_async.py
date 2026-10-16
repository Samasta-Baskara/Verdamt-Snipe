"""Paket 1 (sync->async refactor): modules/recon/scanner.py.

SubdomainFinder/WaybackCollector dropped their thread pools + blocking
http_send/thttp in favor of AsyncNetworkEngine; ParamExtractor's run()
is awaitable so callers skip the to_thread hop. These tests pin the
detection contracts and engine-ownership rules.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from modules.recon.scanner import ParamExtractor, SubdomainFinder, WaybackCollector


def _engine(response):
    eng = MagicMock()
    eng.ahttp_send = AsyncMock(return_value=response)
    eng.close = AsyncMock()
    return eng


class TestSubdomainFinderAsync(unittest.IsolatedAsyncioTestCase):
    async def test_crtsh_json_parsed_and_dns_validated(self):
        crtsh_body = '{"name_value":"www.example.com\napi.example.com\nbad.other.net"}'
        eng = _engine({"status": 200, "body": crtsh_body, "headers": {}})
        finder = SubdomainFinder("example.com", engine=eng)

        loop = asyncio.get_running_loop()
        resolved = {"www.example.com": [(2, 1, 6, "", ("93.184.216.34", 80))]}

        async def fake_gaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if host in resolved:
                return resolved[host]
            raise socket_gaierror()

        def socket_gaierror():
            import socket
            return socket.gaierror("NXDOMAIN")

        with patch.object(loop, "getaddrinfo", fake_gaddrinfo):
            result = await finder.run()

        # validated subs + apex; other.net filtered by domain suffix
        self.assertEqual(result, ["example.com", "www.example.com"])
        # 5 sources were queried via the injected engine
        self.assertEqual(eng.ahttp_send.await_count, 5)
        eng.close.assert_not_awaited()  # injected engine belongs to caller

    async def test_private_engine_is_created_and_closed(self):
        eng = _engine({"status": 0, "body": "", "headers": {}})
        finder = SubdomainFinder("example.com")
        with patch("modules.recon.scanner.AsyncNetworkEngine", return_value=eng):
            result = await finder.run()
        self.assertEqual(result, ["example.com"])  # apex only
        eng.close.assert_awaited_once()

    async def test_source_failure_is_survivable(self):
        eng = MagicMock()
        eng.ahttp_send = AsyncMock(side_effect=RuntimeError("source down"))
        eng.close = AsyncMock()
        finder = SubdomainFinder("example.com", engine=eng)
        with patch.object(asyncio.get_running_loop(), "getaddrinfo",
                          AsyncMock(side_effect=OSError())):
            result = await finder.run()
        self.assertEqual(result, ["example.com"])


class TestWaybackCollectorAsync(unittest.IsolatedAsyncioTestCase):
    async def test_collects_urls_and_strips_quotes(self):
        body = '"https://example.com/a"\nhttp://example.com/b\nnot-a-url\n'
        eng = _engine({"status": 200, "body": body, "headers": {}})
        collector = WaybackCollector("example.com", engine=eng)

        urls = await collector.run()

        self.assertEqual(sorted(urls), ["http://example.com/b", "https://example.com/a"])
        eng.close.assert_not_awaited()


class TestParamExtractorAsync(unittest.IsolatedAsyncioTestCase):
    async def test_extracts_query_params_per_path(self):
        urls = [
            "https://example.com/search?q=1&page=2",
            "https://example.com/search?q=other",
            "https://example.com/about",
        ]
        result = await ParamExtractor(urls).run()
        self.assertEqual(result["/search"], ["page", "q"])
        # path without params still appears when extra_params injected
        result2 = await ParamExtractor(["https://example.com/about"],
                                       extra_params=["debug"]).run()
        self.assertEqual(result2["/about"], ["debug"])


if __name__ == "__main__":
    unittest.main()
