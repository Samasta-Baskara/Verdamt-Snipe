"""Behavioral tests for AsyncVulnEngine/VulnVerifier and AuthTester helpers.

modules/scanners/scanner.py (267 statements uncovered) and the pure
helpers of modules/auth/tester.py — the detection verdicts and
re-verification contracts previously only ran inside full scans.
"""
import unittest
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import unquote

from core.http_client import HTTPResponse
from modules.auth.tester import AuthTester
from modules.scanners.scanner import (
    AsyncVulnEngine,
    VulnVerifier,
    _is_ip_literal,
)


def _eng(response):
    eng = MagicMock()
    if callable(response):
        eng.ahttp_send = AsyncMock(side_effect=response)
    else:
        eng.ahttp_send = AsyncMock(return_value=response)
    eng.origin_host_overrides = {}
    eng.origin_host_map = {}
    return eng


class TestIPLiteral(unittest.TestCase):
    def test_v4_v6_and_domain(self):
        self.assertTrue(_is_ip_literal("93.184.216.34"))
        self.assertTrue(_is_ip_literal("2606:2800::1"))
        self.assertFalse(_is_ip_literal("example.com"))
        self.assertFalse(_is_ip_literal(""))


class TestXSSDetection(unittest.IsolatedAsyncioTestCase):
    async def test_reflected_trigger_is_confirmed(self):
        baseline_url = "https://x.com/search?q=1"

        async def respond(url, **kw):
            if url == baseline_url:
                return {"status": 200, "body": "clean baseline page", "headers": {}, "waf": []}
            # every probe URL echoes its (decoded) payload + a trigger marker
            return {"status": 200, "body": unquote(url) + " onerror=evil",
                    "headers": {}, "waf": []}

        engine = AsyncVulnEngine(_eng(respond))
        finding = await engine.xss("https://x.com/search?q=1", "q")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["type"], "reflected_xss")
        self.assertEqual(finding["confidence"], "confirmed")

    async def test_reflection_in_baseline_is_not_a_finding(self):
        eng = _eng({"status": 200, "body": "onerror= already here", "headers": {}, "waf": []})
        engine = AsyncVulnEngine(eng)
        self.assertIsNone(await engine.xss("https://x.com/search?q=1", "q"))


class TestHeaderConfigCors(unittest.IsolatedAsyncioTestCase):
    async def test_missing_security_headers_flagged(self):
        engine = AsyncVulnEngine(_eng(
            {"status": 200, "headers": {"server": "nginx"}, "body": "x" * 30}))
        findings = await engine.header_checks("https://x.com/")
        titles = [f["title"] for f in findings]
        self.assertIn("Missing X-Frame-Options", titles)
        self.assertIn("Missing CSP Header", titles)
        self.assertIn("Missing X-Content-Type-Options", titles)

    async def test_hardened_headers_no_findings(self):
        engine = AsyncVulnEngine(_eng({"status": 200, "headers": {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        }, "body": ""}))
        self.assertIsNone(await engine.header_checks("https://x.com/"))

    async def test_env_exposure_detected(self):
        async def respond(url, **kw):
            if url.endswith("/.env"):
                return {"status": 200, "body": "DB_PASSWORD=hunter2\nAPP_KEY=abc",
                        "headers": {}, "waf": []}
            return {"status": 404, "body": "not found", "headers": {}, "waf": []}

        engine = AsyncVulnEngine(_eng(respond))
        findings = await engine.config_checks("https://x.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("/.env", findings[0]["title"])

    async def test_soft_404_not_flagged(self):
        async def respond(url, **kw):
            return {"status": 200,
                    "body": "Sorry — page not found, error 404 for you",
                    "headers": {}, "waf": []}

        engine = AsyncVulnEngine(_eng(respond))
        self.assertEqual(await engine.config_checks("https://x.com"), [])

    async def test_cors_reflected_origin_with_credentials(self):
        engine = AsyncVulnEngine(_eng({
            "status": 200, "body": "", "waf": [],
            "headers": {"Access-Control-Allow-Origin": "https://evil.com",
                        "Access-Control-Allow-Credentials": "true"},
        }))
        finding = await engine.cors_checks("https://x.com/")
        self.assertEqual(finding["type"], "cors_misconfig")

    async def test_cors_safe_when_origin_not_reflected(self):
        engine = AsyncVulnEngine(_eng({
            "status": 200, "body": "", "waf": [], "headers": {}}))
        self.assertIsNone(await engine.cors_checks("https://x.com/"))


class TestRedirectAndIDOR(unittest.IsolatedAsyncioTestCase):
    async def test_open_redirect_to_canary(self):
        engine = AsyncVulnEngine(_eng({
            "status": 302, "waf": [], "body": "",
            "headers": {"Location": "https://google.com/login"}}))
        finding = await engine.open_redirect("https://x.com/go?url=https://x.com", "url")
        self.assertEqual(finding["type"], "open_redirect")

    async def test_idor_changed_length_no_denial(self):
        async def respond(url, **kw):
            if "id=0" in url:
                return {"status": 200, "body": "B" * 500, "headers": {}, "waf": []}
            return {"status": 200, "body": "A" * 100, "headers": {}, "waf": []}

        engine = AsyncVulnEngine(_eng(respond))
        finding = await engine.idor_checks("https://x.com/api?id=5", "id")
        self.assertEqual(finding["type"], "idor")

    async def test_idor_skips_non_numeric_param(self):
        engine = AsyncVulnEngine(_eng({}))
        self.assertIsNone(await engine.idor_checks("https://x.com/api?name=bob", "name"))


class TestVulnVerifier(unittest.IsolatedAsyncioTestCase):
    async def test_missing_type_or_url_refuted(self):
        self.assertFalse(await VulnVerifier.verify({}, MagicMock()))
        self.assertFalse(await VulnVerifier.verify({"type": "xss"}, MagicMock()))

    async def test_dom_xss_never_probes(self):
        engine = MagicMock()
        engine.ahttp_send = AsyncMock()
        result = await VulnVerifier.verify(
            {"type": "dom_xss", "url": "https://x.com/", "confidence": "suspected"}, engine)
        self.assertTrue(result)
        engine.ahttp_send.assert_not_awaited()

    async def test_xss_confirmed_stashes_evidence(self):
        proof = "<svg/onload=confirm(1)>"
        engine = _eng({"status": 200, "body": f"echo {proof}", "headers": {}, "url": "u"})
        finding = {"type": "reflected_xss", "url": "https://x.com/?q=1"}
        self.assertTrue(await VulnVerifier.verify(finding, engine))
        self.assertIn(proof, finding["evidence"])

    async def test_xss_refuted_when_payload_not_reflected(self):
        engine = _eng({"status": 200, "body": "nothing here", "headers": {}, "url": "u"})
        self.assertFalse(await VulnVerifier.verify(
            {"type": "reflected_xss", "url": "https://x.com/?q=1"}, engine))

    async def test_untestable_probe_returns_none_not_false(self):
        engine = _eng({"status": 0, "error": "policy_denied:budget", "headers": {}})
        result = await VulnVerifier.verify(
            {"type": "reflected_xss", "url": "https://x.com/?q=1"}, engine)
        self.assertIsNone(result)

    async def test_sqli_time_based_delay_detection(self):
        calls = {"n": 0}

        async def respond(url, **kw):
            calls["n"] += 1
            t = 10.0 if "SLEEP" in url else 0.1
            return {"status": 200, "body": "x", "headers": {}, "time": t}

        engine = _eng(respond)
        result = await VulnVerifier.verify(
            {"type": "sqli_time", "url": "https://x.com/?id=1"}, engine)
        self.assertTrue(result)

    async def test_with_payload_targets_suspicious_param(self):
        out = VulnVerifier._with_payload("https://x.com/?id=1&q=test'x", "PROOF")
        self.assertIn("q=PROOF", out)
        out2 = VulnVerifier._with_payload("https://x.com/", "PROOF")
        self.assertIn("verd_verify=PROOF", out2)


class TestAuthTesterHelpers(unittest.TestCase):
    def setUp(self):
        self.tester = AuthTester(["https://x.com"])

    def test_response_similarity_bounds(self):
        self.assertEqual(self.tester._response_similarity("", ""), 1.0)
        self.assertEqual(self.tester._response_similarity("abc", ""), 0.0)
        self.assertGreater(self.tester._response_similarity("<html>same</html>", "<html>same</html>"), 0.99)

    def test_numeric_param_candidates(self):
        cands = self.tester._numeric_param_candidates("https://x.com/a?user_id=5&name=bob")
        self.assertIn(("user_id", 5), cands)
        # path segment: /users/42 -> users_id (plural stripped)
        cands2 = self.tester._numeric_param_candidates("https://x.com/users/42")
        self.assertIn(("user_id", 42), cands2)

    def test_replace_param_value_in_query_and_path(self):
        out = self.tester._replace_param_value("https://x.com/?id=1&page=2", "id", 99)
        self.assertIn("id=99", out)
        self.assertIn("page=2", out)
        out2 = self.tester._replace_param_value("https://x.com/users/42/profile", "user_id", 7)
        self.assertIn("/users/7/", out2)

    def _resp(self, status=200, text="ok", content_type="text/html"):
        return HTTPResponse(status, {"content-type": content_type},
                            text, text.encode(), "https://x.com/")

    def test_sensitive_success_requires_markers_and_no_login_words(self):
        payload = '{"users":[{"name":"alice","email":"alice@example.com","role":"admin"}]}'
        self.assertTrue(self.tester._looks_sensitive_success(self._resp(text=payload)))
        # login page with markers is NOT success
        self.assertFalse(self.tester._looks_sensitive_success(
            self._resp(text="please login — username password form name")))
        # too small
        self.assertFalse(self.tester._looks_sensitive_success(
            self._resp(text="x" * 10)))

    def test_spa_fallback_similarity_gate(self):
        big = "<html>" + "A" * 400 + "</html>"
        self.assertTrue(self.tester._is_spa_fallback(self._resp(text=big), self._resp(text=big)))
        self.assertFalse(self.tester._is_spa_fallback(
            self._resp(text=big), self._resp(text="<html>" + "B" * 400 + "</html>")))

    def test_add_finding_dedupes(self):
        f = {"type": "t", "url": "u", "title": "x", "detail": "d"}
        self.assertTrue(self.tester._add_finding(dict(f)))
        self.assertFalse(self.tester._add_finding(dict(f)))
        self.assertEqual(len(self.tester.findings), 1)


if __name__ == "__main__":
    unittest.main()
