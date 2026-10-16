"""Behavioral tests for origin_hunter providers, external tool wrappers
and the API profiler helpers (previously 6-30% covered).

Every network/subprocess boundary is mocked; IP filtering, JSONL
parsing, budget charging and response classification run for real.
"""
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from core.external_tools import (
    _nuclei_severity_to_cvss,
    _tool_proxy,
    run_dalfox,
    run_gau,
    run_nuclei,
)
from core.http_client import HTTPResponse
from modules.waf import origin_hunter as oh
from modules.web.recon_crawlers.api_profiler import APIProfiler


class TestOriginHunterIPFilters(unittest.TestCase):
    def test_is_valid_ip_bounds(self):
        self.assertTrue(oh._is_valid_ip("8.8.8.8"))
        self.assertFalse(oh._is_valid_ip("999.1.1.1"))
        self.assertFalse(oh._is_valid_ip("not-an-ip"))
        self.assertFalse(oh._is_valid_ip(""))

    def test_cloudflare_and_akamai_ranges_flagged(self):
        is_waf, provider = oh._is_waf_ip("104.16.0.1")   # Cloudflare
        self.assertTrue(is_waf)
        self.assertIn("loudflare", provider)
        is_waf2, _ = oh._is_waf_ip("8.8.8.8")     # generic
        self.assertFalse(is_waf2)


class TestOriginHunterProviders(unittest.IsolatedAsyncioTestCase):
    async def test_crt_ip_extracts_and_dedupes(self):
        data = [
            {"name_value": "8.8.8.8\n208.67.222.222", "common_name": "example.com"},
            {"name_value": "8.8.8.8", "common_name": "999.999.999.999"},
        ]
        with patch.object(oh, "_curl_json", AsyncMock(return_value=data)):
            results = await oh._method_crt_ip("example.com")
        ips = [r["ip"] for r in results]
        self.assertEqual(sorted(ips), ["208.67.222.222", "8.8.8.8"])  # deduped + invalid dropped

    async def test_otx_filters_record_types_and_waf_ips(self):
        data = {"passive_dns": [
            {"record_type": "A", "address": "8.8.8.8", "hostname": "www.example.com",
             "first": "2020", "last": "2024"},
            {"record_type": "CNAME", "address": "8.8.8.8"},
            {"record_type": "A", "address": "104.16.0.1", "hostname": "cdn.example.com"},
            {"record_type": "A", "address": "999.1.1.1"},
        ]}
        with patch.object(oh, "_curl_json", AsyncMock(return_value=data)):
            results = await oh._method_otx("example.com")
        self.assertEqual([r["ip"] for r in results], ["8.8.8.8"])
        self.assertIn("www.example.com", results[0]["source"])

    async def test_wayback_resolves_discovered_subdomains(self):
        cdx = [["original"], ["https://mail.example.com/a"], ["https://example.com/b"]]
        with patch.object(oh, "_curl_json", AsyncMock(return_value=cdx)), \
             patch.object(oh, "_resolve", return_value=["9.9.9.9"]):
            results = await oh._method_wayback("example.com")
        self.assertEqual(results[0]["ip"], "9.9.9.9")
        self.assertIn("mail.example.com", results[0]["source"])

    async def test_curl_command_includes_host_and_headers(self):
        captured = {}

        async def fake_run(cmd, timeout):
            captured["cmd"] = cmd
            return 0, b"HTTP/1.1 200 OK\r\n\r\n"

        with patch.object(oh, "_run_subprocess", fake_run):
            await oh._curl("https://origin.test/", headers={"X-T": "1"},
                               host="real.example.com", timeout=5)
        cmd = captured["cmd"]
        self.assertIn("curl", cmd)
        self.assertIn("Host: real.example.com", cmd)
        self.assertIn("X-T: 1", cmd)
        self.assertIn("https://origin.test/", cmd)


class TestExternalToolHelpers(unittest.TestCase):
    def test_nuclei_severity_mapping(self):
        self.assertEqual(_nuclei_severity_to_cvss("Critical"), 9.8)
        self.assertEqual(_nuclei_severity_to_cvss("High"), 7.5)
        self.assertEqual(_nuclei_severity_to_cvss("Info"), 0.0)
        self.assertEqual(_nuclei_severity_to_cvss("bogus"), 0.0)

    def test_tool_proxy_flag_only_no_env(self):
        with patch.dict("os.environ", {"ALL_PROXY": "http://env:1"}):
            self.assertIsNone(_tool_proxy(None))       # env must NOT leak in
            self.assertEqual(_tool_proxy("socks5://p:1"), "socks5://p:1")


class TestRunGau(unittest.TestCase):
    def test_stdout_lines_parsed_and_sorted(self):
        stdout = "https://a.example.com/1\nhttps://b.example.com/2#frag\nnot-a-url\n"
        with patch("core.external_tools._run_tool", return_value=(0, stdout, "")):
            urls = run_gau("example.com")
        self.assertEqual(urls, ["https://a.example.com/1", "https://b.example.com/2"])

    def test_missing_tool_returns_empty(self):
        with patch("core.external_tools._run_tool", side_effect=FileNotFoundError):
            self.assertEqual(run_gau("example.com"), [])


class TestRunNuclei(unittest.TestCase):
    def _stdout(self):
        lines = [
            json.dumps({"template-id": "cve-2024-1234", "matched-at": "https://x.com/a",
                        "info": {"name": "RCE thing", "severity": "high",
                                 "description": "bad"}}),
            "banner junk",
            json.dumps({"template-id": "info-leak", "matched-at": "https://x.com/b",
                        "info": {"severity": "info"}}),
        ]
        return "\n".join(lines)

    def test_jsonl_parsed_to_findings_with_cvss(self):
        with patch("core.external_tools._run_tool",
                   return_value=(0, self._stdout(), '"requests":"42"')):
            findings = run_nuclei(["https://x.com"])
        self.assertEqual(len(findings), 2)
        high = next(f for f in findings if f["nuclei_template"] == "cve-2024-1234")
        self.assertEqual(high["cvss_score"], 7.5)
        self.assertEqual(high["cvss_severity"], "High")
        self.assertEqual(high["confidence"], "confirmed")

    def test_policy_charge_debits_real_request_count(self):
        policy = MagicMock()
        policy.filter_urls.side_effect = lambda urls: list(urls)
        policy.allows_url.return_value = True
        policy.max_requests = 100
        policy.requests_remaining = 500
        policy.mode = "active"
        policy.charge.return_value = 42
        with patch("core.external_tools._run_tool",
                   return_value=(0, self._stdout(), '"requests":"42"')):
            run_nuclei(["https://x.com"], policy=policy)
        policy.charge.assert_called_once_with(42, reason="nuclei")

    def test_empty_targets_short_circuits(self):
        with patch("core.external_tools._run_tool") as rt:
            self.assertEqual(run_nuclei([]), [])
        rt.assert_not_called()

    def test_nonzero_rc_reports_but_keeps_findings(self):
        with patch("core.external_tools._run_tool",
                   return_value=(1, self._stdout(), "fatal: something")), patch("core.external_tools.w") as mock_w:
            findings = run_nuclei(["https://x.com"])
        self.assertEqual(len(findings), 2)
        self.assertTrue(any("rc=1" in str(c) for c in mock_w.call_args_list))


class TestRunDalfox(unittest.TestCase):
    def test_jsonl_findings_parsed(self):
        stdout = json.dumps({
            "type": "Verified", "param": "q", "payload": "<svg/onload=alert(1)>",
            "poc": "https://x.com/?q=1", "severity": "high",
        })
        with patch("core.external_tools._run_tool", return_value=(0, stdout, "")):
            findings = run_dalfox(["https://x.com/?q=1"])
        self.assertTrue(findings)
        self.assertIn("Param: q", findings[0]["detail"])
        self.assertEqual(findings[0]["type"], "reflected_xss")
        self.assertIn("q=1", findings[0]["url"])


class TestAPIProfilerHelpers(unittest.TestCase):
    def setUp(self):
        self.profiler = APIProfiler(["https://api.example.com/users"])

    def _resp(self, status=200, body="", content_type="application/json"):
        return HTTPResponse(status, {"content-type": content_type},
                            body, body.encode(), "https://api.example.com/users")

    def test_allowed_methods_from_headers(self):
        resp = self._resp()
        resp.headers = {"allow": "get, post ,DELETE"}
        self.assertEqual(self.profiler._allowed_methods(resp), ["GET", "POST", "DELETE"])
        self.assertEqual(self.profiler._allowed_methods(None), [])

    def test_parse_json_gated_by_content_type(self):
        self.assertEqual(self.profiler._parse_json('{"a":1}', "text/html"), {"a": 1})
        self.assertIsNone(self.profiler._parse_json("plain", "text/html"))
        self.assertIsNone(self.profiler._parse_json("{broken", "application/json"))

    def test_json_keys_handles_dicts_and_lists(self):
        self.assertEqual(self.profiler._json_keys({"b": 1, "a": 2}), ["a", "b"])
        self.assertEqual(self.profiler._json_keys([{"x": 1}]), ["x"])
        self.assertEqual(self.profiler._json_keys("scalar"), [])

    def test_similarity_bounds(self):
        self.assertEqual(self.profiler._response_similarity("", ""), 1.0)
        self.assertEqual(self.profiler._response_similarity("a", ""), 0.0)

    def test_classify_sensitive_json(self):
        body = json.dumps({"users": [{"email": "a@b.com", "password": "x"}]})
        evidence = self.profiler._classify_response(self._resp(body=body))
        self.assertEqual(evidence["kind"], "json_sensitive")
        self.assertGreaterEqual(evidence["sensitivity"], 2)
        self.assertTrue(self.profiler._is_real_public_data(evidence))

    def test_classify_auth_denied(self):
        evidence = self.profiler._classify_response(
            self._resp(status=403, body='{"error":"unauthorized"}'))
        self.assertTrue(evidence["auth_denied"])
        self.assertFalse(self.profiler._is_real_public_data(evidence))


if __name__ == "__main__":
    unittest.main()
