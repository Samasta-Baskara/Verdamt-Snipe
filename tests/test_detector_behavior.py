"""Behavioral tests for the detection logic of web scanner modules.

These modules carried ~1400 uncovered statements: every probe was
mocked around at the runner level, never at the detector level, so the
payload/detection contracts themselves were unpinned. Each test drives
the real detector against a fake engine returning canned responses.
"""
import base64
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from modules.web.api_auth.openapi_parser import OpenAPIParser
from modules.web.client_side.blind_xss import BlindXSSHunter
from modules.web.server_side.cache_poison import _probe_single_header
from modules.web.server_side.crlf import scan_crlf
from modules.web.server_side.host_header import scan_host_header
from modules.web.server_side.lfi_rce_chain import LFItoRCE
from modules.web.server_side.sqli_extractor import SQLiExtractor


def _engine(response):
    eng = MagicMock()
    if callable(response):
        eng.ahttp_send = AsyncMock(side_effect=response)
    else:
        eng.ahttp_send = AsyncMock(return_value=response)
    return eng


class TestCRLFDetection(unittest.IsolatedAsyncioTestCase):
    async def test_header_injection_confirmed_on_reflected_header(self):
        async def respond(url, **kw):
            if "X-Injected" in url or "%0d%0aX-Injected" in url:
                return {"status": 200, "headers": {"X-Injected": "test"}, "body": ""}
            return {"status": 200, "headers": {}, "body": ""}

        findings = await scan_crlf("https://example.com/s", _engine(respond))
        types = [f["type"] for f in findings]
        self.assertIn("crlf_injection", types)
        hit = next(f for f in findings if f["type"] == "crlf_injection")
        self.assertEqual(hit["confidence"], "confirmed")

    async def test_response_splitting_detected_via_double_response_body(self):
        async def respond(url, **kw):
            if "response_splitting" in url or "HTTP/1.1%20200" in url:
                return {"status": 200, "headers": {},
                        "body": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"}
            return {"status": 200, "headers": {}, "body": ""}

        findings = await scan_crlf("https://example.com/s", _engine(respond))
        self.assertIn("crlf_response_splitting", [f["type"] for f in findings])

    async def test_existing_query_string_uses_ampersand_separator(self):
        # Regression: payload used to be appended with "?" producing
        # `...?a=1?q=...` — never a valid param (comment in crlf.py).
        sent = []

        async def respond(url, **kw):
            sent.append(url)
            return {"status": 200, "headers": {}, "body": ""}

        await scan_crlf("https://example.com/s?a=1", _engine(respond))
        for url in sent:
            self.assertNotIn("a=1?q=", url)
            self.assertIn("a=1&q=", url)

    async def test_clean_response_yields_no_findings(self):
        findings = await scan_crlf(
            "https://example.com/s", _engine({"status": 200, "headers": {}, "body": "ok"}))
        self.assertEqual(findings, [])


class TestHostHeaderDetection(unittest.IsolatedAsyncioTestCase):
    async def test_reflected_evil_host_is_confirmed(self):
        async def respond(url, **kw):
            body = "reset at https://evil.attacker.com/reset?token=abc" if "evil" in str(kw.get("headers", {})) else ""
            return {"status": 200, "headers": {}, "body": body}

        findings = await scan_host_header("https://example.com/login", _engine(respond))
        types = [f["type"] for f in findings]
        self.assertIn("host_header_injection", types)
        self.assertIn("password_reset_poisoning", types)

    async def test_probe_passes_host_override_header(self):
        seen = []

        async def respond(url, **kw):
            seen.append(kw.get("headers") or {})
            return {"status": 404, "headers": {}, "body": ""}

        await scan_host_header("https://example.com/login", _engine(respond))
        self.assertTrue(any("Host" in h for h in seen))


class TestSQLiExtractorHelpers(unittest.TestCase):
    def test_inject_replaces_existing_param_and_keeps_others(self):
        ex = SQLiExtractor(engine=None)
        out = ex._inject("https://x.com/?id=1&page=2", "id", "PAYLOAD")
        self.assertIn("id=PAYLOAD", out)
        self.assertIn("page=2", out)

    def test_inject_appends_missing_param(self):
        ex = SQLiExtractor(engine=None)
        out = ex._inject("https://x.com/?id=1", "debug", "P")
        self.assertIn("debug=P", out)
        self.assertIn("id=1", out)

    def test_obfuscate_identity_when_random_disabled(self):
        with patch("modules.web.server_side.sqli_extractor.random.random", return_value=0.0):
            self.assertEqual(SQLiExtractor._obfuscate("1' AND SLEEP(5)--"), "1' AND SLEEP(5)--")

    def test_obfuscate_wraps_keywords_in_mysql_comment(self):
        with patch("modules.web.server_side.sqli_extractor.random.random", return_value=1.0):
            out = SQLiExtractor._obfuscate("1' AND SLEEP(5)--")
        self.assertIn("/*!50000AND*/", out)
        self.assertIn("/*!50000SLEEP*/", out)


class TestLFIDetection(unittest.TestCase):
    def test_extract_creds_from_php_source(self):
        lfi = LFItoRCE(engine=None)
        src = '<?php $db_host = "localhost"; $db_user = "root"; $db_pass = "s3cret"; ?>'
        creds = lfi._extract_creds(src)
        self.assertIn("s3cret", creds)

    def test_extract_creds_empty_on_clean_source(self):
        lfi = LFItoRCE(engine=None)
        self.assertEqual(lfi._extract_creds("<?php echo 'hi'; ?>"), "")


class TestLFIFilterChain(unittest.IsolatedAsyncioTestCase):
    async def test_base64_source_leak_detected(self):
        php = base64.b64encode(
            b'<?php $db_host = "localhost"; $db_pass = "s3cret"; ?>').decode()
        eng = _engine({"status": 200, "body": php, "headers": {}})
        lfi = LFItoRCE(eng)

        findings = await lfi.php_filter_chain("https://example.com/page", "file")

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "lfi_source_leak")
        self.assertEqual(findings[0]["confidence"], "confirmed")  # creds extracted

    async def test_random_base64_without_markers_is_ignored(self):
        eng = _engine({"status": 200,
                       "body": base64.b64encode(b"just some page content here...").decode(),
                       "headers": {}})
        lfi = LFItoRCE(eng)
        findings = await lfi.php_filter_chain("https://example.com/page", "file")
        self.assertEqual(findings, [])


class TestCachePoisonProbe(unittest.IsolatedAsyncioTestCase):
    async def test_reflected_poison_value_is_confirmed(self):
        async def respond(url, headers=None, **kw):
            value = (headers or {}).get("X-Forwarded-Host", "")
            return {"status": 200, "body": f"host: {value}", "headers": {}, "waf": []}

        finding = await _probe_single_header(
            "https://example.com/", _engine(respond),
            "X-Forwarded-Host", "poison-1234.evil", 200, None)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["confidence"], "confirmed")
        self.assertIn("reflected", finding["detail"])

    async def test_status_shift_is_suspected_only(self):
        eng = _engine({"status": 500, "body": "", "headers": {}, "waf": []})
        finding = await _probe_single_header(
            "https://example.com/", eng, "X-Forwarded-Host", "pv", 200, None)
        self.assertEqual(finding["confidence"], "suspected")

    async def test_identical_response_yields_none(self):
        eng = _engine({"status": 200, "body": "same", "headers": {}})
        finding = await _probe_single_header(
            "https://example.com/", eng, "X-Forwarded-Host", "pv", 200, None)
        self.assertIsNone(finding)


class TestBlindXSS(unittest.TestCase):
    def test_payload_template_gets_callback_domain(self):
        hunter = BlindXSSHunter(engine=None, interactsh_domain="oast.fun")
        payload = hunter.combined("marker1")
        self.assertIn("https://marker1.oast.fun/x", payload)
        self.assertNotIn("__CB__", payload)

    def test_stored_variants_cover_filter_bypass_shapes(self):
        hunter = BlindXSSHunter(engine=None, interactsh_domain="oast.fun")
        variants = hunter.stored_xss_payloads("m1")
        self.assertEqual(len(variants), 9)
        for v in variants:
            self.assertIn("m1.oast.fun", v)
        joined = " ".join(variants)
        for shape in ("<img", "<svg", "<body", "<input", "<details", "<marquee", "<video"):
            self.assertIn(shape, joined)


class TestOpenAPIParser(unittest.TestCase):
    def test_openapi_v3_paths_and_params(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users/{id}": {
                    "get": {"parameters": [
                        {"name": "fields", "in": "query"},
                        {"name": "id", "in": "path"},
                    ]},
                    "post": {},
                },
            },
        }
        import json
        p = OpenAPIParser(base_url="https://api.example.com")
        out = p.parse_spec(json.dumps(spec))
        self.assertIn("https://api.example.com/users/1", out["endpoints"])
        self.assertIn("fields", out["params"].get("/users/1", []))

    def test_spec_url_derives_base_url(self):
        import json
        spec = {"openapi": "3.0.0", "paths": {"/ping": {"get": {}}}}
        p = OpenAPIParser()
        p.parse_spec(json.dumps(spec), spec_url="https://svc.internal/v3/api.json")
        self.assertEqual(p.base_url, "https://svc.internal")
        self.assertIn("https://svc.internal/ping", p.endpoints)

    def test_invalid_json_returns_empty(self):
        p = OpenAPIParser(base_url="https://x")
        self.assertEqual(p.parse_spec("{not json"), {"endpoints": [], "params": {}})

    def test_empty_content_returns_empty(self):
        p = OpenAPIParser()
        self.assertEqual(p.parse_spec(""), {"endpoints": [], "params": {}})


if __name__ == "__main__":
    unittest.main()
