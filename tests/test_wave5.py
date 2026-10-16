"""Wave 5: DOM-XSS static taint analysis + runners/shared pipeline helpers.

DOMXSSScanner's source/sink/taint engine (previously ~40% of 350 stmts
uncovered) and the shared runner utilities that mode 2-5 pipelines all
flow through. Pure-string analysis runs for real; fetches are mocked.
"""
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from modules.web.client_side.dom_xss import DOMXSSScanner
from runners.shared import (
    build_param_scan_targets,
    build_param_url,
    collect_js_assets,
    concrete_js_findings,
    inject_query_payload,
    merge_params,
    normalize_takeover_findings,
    normalize_urls,
    run_waf_origin_phase,
    validate_recon_urls,
)

VULN_JS = """
function render() {
    var q = location.hash.substring(1);
    var el = document.getElementById("out");
    el.innerHTML = q;
}
"""

SAFE_JS = """
function render() {
    var q = location.hash.substring(1);
    document.getElementById("out").textContent = DOMPurify.sanitize(q);
}
"""


class TestDOMXSSFiltering(unittest.TestCase):
    def test_vendor_and_bundle_libraries_skipped(self):
        scanner = DOMXSSScanner([
            "https://x.com/js/app.js",
            "https://x.com/js/jquery-3.6.min.js",
            "https://x.com/js/app-bundle.js",
            "https://x.com/vendor/lib.js",
            "https://x.com/page.html",
        ])
        self.assertEqual(scanner.js_urls, ["https://x.com/js/app.js"])


class TestDOMXSSTaint(unittest.TestCase):
    def setUp(self):
        self.scanner = DOMXSSScanner(["https://x.com/js/app.js"])

    def test_direct_source_to_sink_flow(self):
        flows = self.scanner._analyze_js_content(VULN_JS)
        self.assertTrue(flows)
        flow = flows[0]
        # source is reported as the tainted var + its source pattern (regex)
        self.assertIn("location", flow["source"])
        self.assertIn("'q'", flow["source"])
        self.assertIn("innerHTML", flow["sink"])
        self.assertEqual(flow["sink_line"], 5)

    def test_sanitized_sink_not_reported(self):
        flows = self.scanner._analyze_js_content(SAFE_JS)
        dom_flows = [f for f in flows if f.get("sink") == "innerHTML"]
        self.assertEqual(dom_flows, [])

    def test_prototype_pollution_via_object_assign(self):
        js = """
function merge() {
    var opts = JSON.parse(location.search.slice(1));
    Object.assign({}, opts);
}
"""
        flows = self.scanner._analyze_js_content(js)
        self.assertTrue(any("pollution" in f.get("type", "") or
                            "assign" in f.get("sink", "").lower() or
                            "Object.assign" in f.get("detail", "")
                            for f in flows))

    def test_inline_scripts_in_html(self):
        html = "<html><script>var x=location.hash;el.innerHTML=x;</script></html>"
        flows = self.scanner._analyze_inline_scripts(html)
        self.assertTrue(flows)

    def test_tiny_inline_script_skipped(self):
        flows = self.scanner._analyze_inline_scripts("<script>var a=1;</script>")
        self.assertEqual(flows, [])

    async def test_scan_url_wraps_flows_into_findings(self):
        eng = MagicMock()
        eng.ahttp_send = AsyncMock(
            return_value={"status": 200, "body": VULN_JS, "time": 0.2})
        scanner = DOMXSSScanner([], network_engine=eng)

        findings = await scanner._scan_url("https://x.com/js/app.js")

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "dom_xss")
        self.assertEqual(findings[0]["confidence"], "suspected")
        self.assertIn("innerHTML", findings[0]["title"])


class TestNormalizeHelpers(unittest.TestCase):
    def test_takeover_findings_get_cvss_wrapper(self):
        raw = [{"sub": "dev.example.com", "service": "AWS/S3",
                "cname": "dev.s3.amazonaws.com"}]
        out = normalize_takeover_findings(raw)
        self.assertEqual(out[0]["type"], "subdomain_takeover")
        self.assertEqual(out[0]["cvss_score"], 3.1)
        self.assertEqual(out[0]["url"], "https://dev.example.com")
        self.assertEqual(normalize_takeover_findings(None), [])

    def test_normalize_urls_filters_and_sorts(self):
        out = normalize_urls(["https://b.com/x#frag", "https://a.com/", "",
                              "ftp://skip.com/", "https://a.com/"])
        self.assertEqual(out, ["https://a.com/", "https://b.com/x"])

    def test_normalize_urls_delegates_to_scope_guard(self):
        guard = MagicMock()
        guard.filter_urls.return_value = ["kept"]
        self.assertEqual(normalize_urls(["x"], scope_guard=guard,
                                        keep_static=False), ["kept"])
        guard.filter_urls.assert_called_once_with(["x"], keep_static=False)

    def test_collect_js_assets_from_urls_and_script_tags(self):
        services = [{"url": "https://x.com/",
                     "body": '<script src="/static/vendor-free.js"></script>'}]
        out = collect_js_assets(["https://x.com/direct.js", "https://x.com/page"], services)
        self.assertIn("https://x.com/direct.js", out)
        self.assertIn("https://x.com/static/vendor-free.js", out)

    def test_build_param_url_appends_and_replaces(self):
        self.assertEqual(build_param_url("https://x.com", "/api", "id"),
                         "https://x.com/api?id=FUZZ")
        self.assertEqual(build_param_url("https://x.com", "/api?a=1", "a"),
                         "https://x.com/api?a=1&a=FUZZ")

    def test_build_param_scan_targets_prioritizes_query_params(self):
        targets = build_param_scan_targets(
            ["https://x.com/a?uid=1"],
            {"/a": ["sort", "uid"]},
            max_params_per_url=10, max_targets=10)
        # uid (query-observed) must come before sort (path guess)
        self.assertEqual(targets[0], ("https://x.com/a?uid=1", "uid"))
        self.assertEqual(targets[1], ("https://x.com/a?uid=1", "sort"))

    def test_build_param_scan_targets_cap_is_deterministic(self):
        many = {f"/p{i}": [f"x{j}" for j in range(10)] for i in range(50)}
        urls = [f"https://x.com/p{i}" for i in range(50)]
        capped = build_param_scan_targets(urls, many, max_targets=25)
        self.assertEqual(len(capped), 25)

    def test_merge_params_dedupes(self):
        params = {"/a": ["x"]}
        merge_params(params, "/a", ["x", "y"])
        self.assertEqual(params["/a"], ["x", "y"])
        merge_params(params, None, ["z"])
        self.assertEqual(params["/"], ["z"])

    def test_inject_query_payload_replaces_first_match_only(self):
        out = inject_query_payload("https://x.com/?id=1&id=2", "id", "P")
        self.assertIn("id=P", out)
        self.assertIn("id=2", out)
        out2 = inject_query_payload("https://x.com/", "new", "P")
        self.assertIn("new=P", out2)


class TestConcreteJsFindings(unittest.TestCase):
    def test_js_secret_always_confirmed(self):
        out = concrete_js_findings(
            [{"type": "js_secret_aws", "url": "u"}], [], [], MagicMock())
        self.assertEqual(out[0]["confidence"], "confirmed")

    def test_js_endpoint_validated_when_seen_in_scan_urls(self):
        guard = MagicMock()
        guard.filter_urls.side_effect = lambda urls: list(urls)
        finding = {"type": "js_endpoint", "url": "u",
                   "detail": "Endpoint matched: /api/v1/users"}
        out = concrete_js_findings([finding], [{"url": "https://x.com"}],
                                   ["https://x.com/api/v1/users"], guard)
        self.assertEqual(out[0]["confidence"], "confirmed")

    def test_js_endpoint_unseen_downgraded(self):
        guard = MagicMock()
        guard.filter_urls.side_effect = lambda urls: list(urls)
        finding = {"type": "js_endpoint", "url": "u",
                   "detail": "Endpoint matched: /never-seen"}
        out = concrete_js_findings([finding], [{"url": "https://x.com"}], [], guard)
        self.assertEqual(out[0]["confidence"], "suspected")


class TestValidateReconUrls(unittest.IsolatedAsyncioTestCase):
    def _guard(self):
        guard = MagicMock()
        guard.filter_urls.side_effect = lambda urls, **kw: list(urls)
        return guard

    async def test_python_probe_fallback_when_go_unavailable(self):
        go = MagicMock()
        go.is_available.return_value = False
        with patch("core.go_bridge.go_bridge", go):
            eng = MagicMock()

            async def respond(url, **kw):
                # 500 is dropped (200 <= st < 500 keeps even 404)
                status = 500 if "dead" in url else 200
                return {"status": status}

            eng.ahttp_send = AsyncMock(side_effect=respond)
            live = await validate_recon_urls(
                ["https://x.com/alive", "https://x.com/dead"],
                self._guard(), eng)

        self.assertEqual(live, ["https://x.com/alive"])

    async def test_go_bridge_results_prefered(self):
        go = MagicMock()
        go.is_available.return_value = True
        go.probe_batch = MagicMock(return_value=[
            {"status_code": 200, "url": "https://x.com/a"},
            {"status_code": 0, "url": "https://x.com/b"},
        ])
        eng = MagicMock()
        eng.ahttp_send = AsyncMock()
        with patch("core.go_bridge.go_bridge", go):
            live = await validate_recon_urls(
                ["https://x.com/a", "https://x.com/b"], self._guard(), eng)
        self.assertEqual(live, ["https://x.com/a"])
        eng.ahttp_send.assert_not_awaited()


class TestWafOriginPhase(unittest.IsolatedAsyncioTestCase):
    async def test_no_waf_is_noop(self):
        result = await run_waf_origin_phase(
            "example.com", [{"url": "https://example.com/", "waf": []}])
        self.assertIsNone(result)

    async def test_origin_ip_authorized_and_propagated(self):
        services = [{"url": "https://example.com/", "waf": ["cloudflare"]}]
        policy = MagicMock()

        async def fake_hunt(target, hosts, proxy=None):
            return {"origin_ip": "9.9.9.9", "protocol": "https"}

        with patch("modules.waf.origin_hunter.hunt_origin", fake_hunt):
            origin_ip = await run_waf_origin_phase(
                "example.com", services, subs=["mail.example.com"],
                policy=policy)

        self.assertEqual(origin_ip, "9.9.9.9")
        policy.authorize_host.assert_called_once_with("9.9.9.9")
        self.assertEqual(services[0]["origin_ip"], "9.9.9.9")

    async def test_failed_hunt_keeps_scanning(self):
        services = [{"url": "https://example.com/", "waf": ["cloudflare"]}]

        async def boom(target, hosts, proxy=None):
            raise RuntimeError("no intel")

        with patch("modules.waf.origin_hunter.hunt_origin", boom):
            result = await run_waf_origin_phase("example.com", services)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
