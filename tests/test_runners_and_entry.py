"""Behavioral tests for the recon-light/surface runners and the CLI entry.

The orchestration layer decides which tool path runs and how turbo mode
mutates/restores engine knobs — none of it was covered. External tools
(subfinder, httpx, katana, engines) are mocked; the control flow,
link extraction and turbo save/restore run for real.
"""
import asyncio
import contextlib
import io
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from runners.recon_light import _extract_links, run_recon_light
from runners.surface import run_surface_scan


def _scope_passthrough():
    guard = MagicMock()
    guard.filter_urls.side_effect = lambda urls, **kw: list(urls)
    return guard


class TestExtractLinks(unittest.TestCase):
    def test_absolute_and_relative_links(self):
        html = ('<a href="https://example.com/a#frag">1</a>'
                '<a href="/local/b">2</a>'
                "<a href='https://other.net/ignored'>3</a>")
        urls = sorted(_extract_links(html, "https://example.com/"))
        self.assertIn("https://example.com/a", urls)
        self.assertIn("https://example.com/local/b", urls)

    def test_fragments_stripped(self):
        urls = _extract_links('<a href="/x#top">', "https://e.com/")
        self.assertEqual(urls, ["https://e.com/x"])


class TestRunReconLight(unittest.IsolatedAsyncioTestCase):
    def _engine(self):
        eng = MagicMock()
        eng.ahttp_send = AsyncMock(return_value={
            "status": 200,
            "body": '<a href="/found/page">x</a>',
            "headers": {},
        })
        eng.rate_limiter = MagicMock(current_delay=0.4)
        eng.circuit_breaker = MagicMock(failure_threshold=5)
        return eng

    async def test_crawl_collects_links_and_returns_scan_urls(self):
        eng = self._engine()

        async def passthrough(urls, scope_guard, engine, session_manager=None, max_urls=0):
            return list(urls)

        with patch("runners.recon_light.validate_recon_urls", side_effect=passthrough), \
             patch("runners.recon_light.AsyncVulnEngine") as vuln_cls:
            vuln_cls.return_value.config_checks = AsyncMock(return_value=[])
            vuln_cls.return_value.header_checks = AsyncMock(return_value=[])
            vuln_cls.return_value.cors_checks = AsyncMock(return_value=[])
            findings, scan_urls = await run_recon_light(
                "example.com", "https://example.com/", [], [], [],
                _scope_passthrough(), eng)

        self.assertEqual(findings, [])
        self.assertIn("https://example.com/found/page", scan_urls)

    async def test_turbo_mutates_then_restores_engine_knobs(self):
        eng = self._engine()

        async def passthrough(urls, scope_guard, engine, session_manager=None, max_urls=0):
            return list(urls)

        seen = {}

        async def config(url):
            seen["delay"] = eng.rate_limiter.current_delay
            seen["threshold"] = eng.circuit_breaker.failure_threshold
            return []

        with patch("runners.recon_light.validate_recon_urls", side_effect=passthrough), \
             patch("runners.recon_light.AsyncVulnEngine") as vuln_cls:
            vuln_cls.return_value.config_checks = config
            vuln_cls.return_value.header_checks = AsyncMock(return_value=[])
            vuln_cls.return_value.cors_checks = AsyncMock(return_value=[])
            await run_recon_light(
                "example.com", "https://example.com/",
                [{"url": "https://example.com/"}], [], [],
                _scope_passthrough(), eng, is_turbo=True)

        # inside the check: turbo zeros delay and disables the breaker
        self.assertEqual(seen["delay"], 0)
        self.assertEqual(seen["threshold"], 999999)
        # after the run: originals restored
        self.assertEqual(eng.rate_limiter.current_delay, 0.4)
        self.assertEqual(eng.circuit_breaker.failure_threshold, 5)

    async def test_vuln_engine_findings_aggregated(self):
        eng = self._engine()

        async def passthrough(urls, scope_guard, engine, session_manager=None, max_urls=0):
            return list(urls)

        with patch("runners.recon_light.validate_recon_urls", side_effect=passthrough), \
             patch("runners.recon_light.AsyncVulnEngine") as vuln_cls:
            vuln_cls.return_value.config_checks = AsyncMock(
                return_value=[{"type": "missing_header"}])
            vuln_cls.return_value.header_checks = AsyncMock(return_value=[])
            vuln_cls.return_value.cors_checks = AsyncMock(return_value=[])
            findings, _ = await run_recon_light(
                "example.com", "https://example.com/",
                [{"url": "https://example.com/"}], [], [],
                _scope_passthrough(), eng)

        self.assertEqual(findings, [{"type": "missing_header"}])


class TestRunSurfaceScan(unittest.IsolatedAsyncioTestCase):
    def test_subfinder_results_skip_python_fallback(self):
        eng_services = [{"url": "https://a.example.com", "final_url": "https://a.example.com"}]

        with patch("runners.surface.run_subfinder",
                   return_value=["a.example.com"]), \
             patch("runners.surface.run_httpx", return_value=eng_services), \
             patch("runners.surface.SubdomainFinder") as finder_cls:
            subs, services, urls = asyncio.run(run_surface_scan(
                "example.com", "https://example.com/", _scope_passthrough()))

        self.assertEqual(subs, ["a.example.com"])
        self.assertEqual(services, eng_services)
        finder_cls.assert_not_called()
        self.assertIn("https://a.example.com", urls)

    def test_python_finder_fallback_when_binary_empty(self):
        with patch("runners.surface.run_subfinder", return_value=[]), \
             patch("runners.surface.run_httpx",
                   return_value=[{"url": "https://example.com",
                                  "final_url": "https://example.com"}]), \
             patch("runners.surface.SubdomainFinder") as finder_cls:
            finder_cls.return_value.run = AsyncMock(return_value=["b.example.com"])
            subs, _, _ = asyncio.run(run_surface_scan(
                "example.com", "https://example.com/", _scope_passthrough()))

        self.assertEqual(subs, ["b.example.com"])
        finder_cls.return_value.run.assert_awaited_once()

    def test_http_prober_fallback_when_external_httpx_empty(self):
        prober_services = [{"url": "https://c.example.com",
                            "final_url": "https://c.example.com"}]
        with patch("runners.surface.run_subfinder", return_value=["c.example.com"]), \
             patch("runners.surface.run_httpx", return_value=[]), \
             patch("runners.surface.HTTPProber") as prober_cls:
            prober_cls.return_value.run = AsyncMock(return_value=prober_services)
            _subs, services, urls = asyncio.run(run_surface_scan(
                "example.com", "https://example.com/", _scope_passthrough()))

        self.assertEqual(services, prober_services)
        prober_cls.return_value.run.assert_awaited_once()
        self.assertIn("https://c.example.com", urls)

    def test_root_domain_kept_when_all_tools_fail(self):
        with patch("runners.surface.run_subfinder", side_effect=OSError("no bin")), \
             patch("runners.surface.run_httpx", side_effect=OSError("no bin")), \
             patch("runners.surface.SubdomainFinder") as finder_cls, \
             patch("runners.surface.HTTPProber") as prober_cls:
            finder_cls.return_value.run = AsyncMock(return_value=[])
            prober_cls.return_value.run = AsyncMock(return_value=[])
            subs, services, _ = asyncio.run(run_surface_scan(
                "example.com", "https://example.com/", _scope_passthrough()))

        self.assertEqual(subs, ["example.com"])
        self.assertEqual(services, [])


if __name__ == "__main__":
    unittest.main()


class TestCLIEntry(unittest.TestCase):
    """In-process entry-point paths (counts toward verd.py coverage)."""

    def _run_main(self, argv):
        import verd
        buf = io.StringIO()
        with patch("sys.argv", argv), contextlib.redirect_stdout(buf):
            try:
                asyncio.run(verd.main_cli())
            except SystemExit as e:
                return e.code, buf.getvalue()
        return None, buf.getvalue()

    def test_version_prints_and_exits(self):
        code, out = self._run_main(["verd.py", "--version"])
        self.assertEqual(code, 0)
        self.assertIn("verdamt-snipe v", out)

    def test_no_args_shows_banner_and_help(self):
        code, out = self._run_main(["verd.py"])
        self.assertEqual(code, 0)
        self.assertIn("Verdammt", out)

    def test_missing_target_errors(self):
        code, out = self._run_main(["verd.py", "--recon"])
        self.assertEqual(code, 1)
        self.assertIn("Target or --resume", out)

    def test_bare_resume_without_state_errors(self):
        code, out = self._run_main(["verd.py", "--resume", "outputs/missing.state"])
        self.assertEqual(code, 1)
        self.assertIn("State file not found", out)
