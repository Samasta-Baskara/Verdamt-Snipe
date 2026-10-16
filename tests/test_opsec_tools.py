"""Behavioral tests for the OPSEC/tooling layer.

curl_send, doh_resolve and opsec_check shell out to curl; the raw-socket
codec helpers deal with wire bytes. All were at ~0-9% coverage — these
tests pin the command construction, result parsing and leak-detection
logic with mocked subprocess boundaries.
"""
import json
import unittest
from unittest.mock import MagicMock, patch

from core import opsec_check
from core.curl_send import curl_send
from core.doh_resolve import doh_resolve
from core.http_codec import _dechunk


class TestDechunk(unittest.TestCase):
    def test_valid_chunked_body(self):
        wire = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        self.assertEqual(_dechunk(wire), b"hello world")

    def test_malformed_framing_returned_untouched(self):
        junk = b"zz-not-chunked"
        self.assertEqual(_dechunk(junk), junk)

    def test_chunk_extensions_ignored(self):
        wire = b"5;ext=1\r\nhello\r\n0\r\n"
        self.assertEqual(_dechunk(wire), b"hello")


def _fake_popen(stdout="200:0.5:42", returncode=0, stderr="", body=""):
    """Fake Popen: captures cmd, writes requested -o body file."""
    calls = {}

    class _Proc:
        def __init__(self, rc):
            self.returncode = rc

        def communicate(self, timeout=None):
            # curl -o <file>: write the canned body there
            if "-o" in calls["cmd"]:
                idx = calls["cmd"].index("-o")
                with open(calls["cmd"][idx + 1], "w") as fh:
                    fh.write(body)
            return stdout, stderr

        def kill(self):
            pass

    def factory(cmd, **kw):
        calls["cmd"] = cmd
        return _Proc(returncode)

    factory.calls = calls
    return factory


class TestCurlSend(unittest.TestCase):
    def test_resolve_flag_routes_to_origin_ip_with_sni(self):
        factory = _fake_popen(body="origin content")
        with patch("core.curl_send.subprocess.Popen", factory), \
             patch("core.external_tools.track_proc"), \
             patch("core.external_tools.untrack_proc"):
            r = curl_send("https://example.com/path", resolve_domain="example.com",
                          resolve_ip="1.2.3.4")
        cmd = factory.calls["cmd"]
        self.assertIn("--resolve", cmd)
        self.assertIn("example.com:443:1.2.3.4", cmd)
        self.assertIn("-k", cmd)
        self.assertEqual(cmd[-1], "https://example.com/path")
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["body"], "origin content")
        self.assertEqual(r["time"], 0.5)

    def test_method_and_headers_and_data_built_into_cmd(self):
        factory = _fake_popen()
        with patch("core.curl_send.subprocess.Popen", factory), \
             patch("core.external_tools.track_proc"), \
             patch("core.external_tools.untrack_proc"):
            curl_send("https://x.com/", method="POST",
                      headers={"X-Test": "1"}, data="a=b", proxy="socks5://p:1080")
        cmd = factory.calls["cmd"]
        self.assertIn("-X", cmd)
        self.assertIn("POST", cmd)
        self.assertIn("X-Test: 1", cmd)
        self.assertIn("a=b", cmd)
        self.assertIn("--proxy", cmd)

    def test_nonzero_exit_reports_error(self):
        factory = _fake_popen(stdout="", returncode=7, stderr="connect refused")
        with patch("core.curl_send.subprocess.Popen", factory), \
             patch("core.external_tools.track_proc"), \
             patch("core.external_tools.untrack_proc"):
            r = curl_send("https://x.com/")
        self.assertEqual(r["status"], 0)
        self.assertIn("connect refused", r["error"])

    def test_policy_denial_never_touches_network(self):
        policy = MagicMock()
        policy.authorize_request.return_value = MagicMock(allowed=False, reason="scope_denied")
        r = curl_send("https://evil.com/", policy=policy)
        self.assertEqual(r["status"], 0)
        self.assertIn("policy_denied:scope_denied", r["error"])

    def test_dry_run_refunds_and_short_circuits(self):
        policy = MagicMock()
        policy.authorize_request.return_value = MagicMock(allowed=True, reason="")
        policy.dry_run = True
        r = curl_send("https://x.com/", policy=policy)
        self.assertEqual(r["status"], 200)
        self.assertIn("DRY RUN", r["body"])
        policy.refund_request.assert_called_once()


class TestDoHResolve(unittest.TestCase):
    def test_cloudflare_answer_parsed(self):
        payload = json.dumps({"Answer": [
            {"type": 1, "data": "93.184.216.34"},
            {"type": 28, "data": "2606:2800::1"},
        ]})
        runner = MagicMock(return_value=MagicMock(returncode=0, stdout=payload))
        with patch("core.doh_resolve.subprocess.run", runner):
            ips = doh_resolve("example.com")
        self.assertEqual(ips, ["93.184.216.34"])  # A records only
        cmd = runner.call_args[0][0]
        self.assertIn("1.1.1.1", " ".join(cmd))
        self.assertIn("name=example.com", " ".join(cmd))

    def test_falls_through_to_next_provider(self):
        ok = json.dumps({"Answer": [{"type": 1, "data": "10.0.0.1"}]})
        runner = MagicMock(side_effect=[
            MagicMock(returncode=1, stdout=""),                       # cloudflare fails
            MagicMock(returncode=0, stdout=ok),                       # google works
        ])
        with patch("core.doh_resolve.subprocess.run", runner):
            ips = doh_resolve("example.com")
        self.assertEqual(ips, ["10.0.0.1"])
        self.assertEqual(runner.call_count, 2)

    def test_all_providers_fail_falls_back_to_local_dns(self):
        runner = MagicMock(return_value=MagicMock(returncode=1, stdout=""))
        with patch("core.doh_resolve.subprocess.run", runner), \
             patch("core.doh_resolve.socket.gethostbyname_ex",
                   return_value=("x", [], ["192.0.2.1"])):
            ips = doh_resolve("example.com")
        self.assertEqual(ips, ["192.0.2.1"])

    def test_total_failure_returns_empty(self):
        runner = MagicMock(side_effect=OSError("no network"))
        with patch("core.doh_resolve.subprocess.run", runner), \
             patch("core.doh_resolve.socket.gethostbyname_ex",
                   side_effect=OSError("no dns")):
            self.assertEqual(doh_resolve("example.com"), [])


class TestOpsecChecks(unittest.TestCase):
    def test_check_ip_direct_vs_proxy_leak(self):
        runner = MagicMock(side_effect=[
            MagicMock(returncode=0, stdout="1.1.1.1\n"),  # direct
            MagicMock(returncode=0, stdout="2.2.2.2\n"),  # proxy
        ])
        with patch("core.opsec_check.subprocess.run", runner):
            result = opsec_check.check_ip(proxy="socks5://p:9050")
        self.assertEqual(result["direct_ip"], "1.1.1.1")
        self.assertEqual(result["proxy_ip"], "2.2.2.2")
        self.assertFalse(result["ip_leak"])  # different IPs = no leak

    def test_check_ip_same_ip_flagged_as_leak(self):
        same = MagicMock(returncode=0, stdout="1.1.1.1\n")
        with patch("core.opsec_check.subprocess.run", same):
            result = opsec_check.check_ip(proxy="socks5://p:9050")
        self.assertTrue(result["ip_leak"])

    def test_check_dns_local_vs_doh(self):
        # Patch doh at the function level: check_dns re-imports it per call,
        # and socket/subprocess are shared module objects (nested attribute
        # patches on both modules would collide on the same target).
        with patch("core.opsec_check.socket.gethostbyname_ex",
                   return_value=("x", [], ["192.0.2.5"])), \
             patch("core.doh_resolve.doh_resolve",
                   return_value=["198.51.100.9"]):
            result = opsec_check.check_dns()
        self.assertEqual(result["local_dns"], ["192.0.2.5"])
        self.assertEqual(result["doh_dns"], ["198.51.100.9"])
        self.assertTrue(result["dns_leak"])  # resolver answered differently than DoH

    def test_check_env_leak_reports_set_vars(self):
        with patch.dict("os.environ", {"VERDAMT_PROXY": "socks5://p:9050"}, clear=True):
            result = opsec_check.check_env_leak()
        self.assertTrue(result["env_set"])
        self.assertEqual(result["vars"]["VERDAMT_PROXY"], "socks5://p:9050")

    def test_check_env_leak_clean_env(self):
        with patch.dict("os.environ", {}, clear=True):
            result = opsec_check.check_env_leak()
        self.assertFalse(result["env_set"])

    def test_check_websocket_webrtc_disabled_in_firefox_profile(self, ):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            profile = os.path.join(tmp, "abc.default")
            os.makedirs(profile)
            with open(os.path.join(profile, "prefs.js"), "w") as fh:
                fh.write('user_pref("media.peerconnection.enabled", false);\n')
            with patch("os.path.expanduser", return_value=tmp):
                result = opsec_check.check_websocket_leak()
        self.assertFalse(result["webRTC_risk"])
        self.assertIn("WebRTC disabled", result["note"])

    def test_run_full_check_aggregates_all_sections(self):
        with patch("core.opsec_check.subprocess.run",
                   return_value=MagicMock(returncode=1, stdout="")), \
             patch("core.opsec_check.socket.gethostbyname_ex", side_effect=OSError), \
             patch("core.doh_resolve.doh_resolve", return_value=[]), \
             patch("os.path.expanduser", return_value="/nonexistent"), \
             patch.dict("os.environ", {}, clear=True):
            results = opsec_check.run_full_check()
        for key in ("ip", "dns", "webrtc", "env", "issues", "safe",
                    "proxy_reachable", "active_proxy"):
            self.assertIn(key, results)

    def test_run_full_check_flags_dead_proxy(self):
        """Proxy set tapi mati -> issue PROXY DOWN (fail-closed, bukan leak)."""
        with patch("core.opsec_check.subprocess.run",
                   return_value=MagicMock(returncode=1, stdout="")), \
             patch("core.opsec_check.socket.gethostbyname_ex", side_effect=OSError), \
             patch("core.doh_resolve.doh_resolve", return_value=[]), \
             patch("os.path.expanduser", return_value="/nonexistent"), \
             patch("core.proxy_manager.verify_proxy_reachable", return_value=False), \
             patch.dict("os.environ", {"VERDAMT_PROXY": "socks5h://203.0.113.1:9050"}):
            results = opsec_check.run_full_check()
        self.assertFalse(results["proxy_reachable"])
        self.assertTrue(any("PROXY DOWN" in i for i in results["issues"]))


class TestVerifyProxyReachable(unittest.TestCase):
    """Pre-flight proxy health-check — TCP probe sekali, bukan per-request."""

    def test_no_proxy_configured_is_ok(self):
        with patch("core.proxy_manager.resolve_proxy", return_value=None):
            from core.proxy_manager import verify_proxy_reachable
            self.assertTrue(verify_proxy_reachable(None))

    def test_reachable_proxy_connect_succeeds(self):
        from core.proxy_manager import verify_proxy_reachable
        with patch("core.proxy_manager.socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = lambda s: s
            mock_conn.return_value.__exit__ = lambda s, *a: False
            self.assertTrue(verify_proxy_reachable("socks5h://127.0.0.1:9050"))

    def test_dead_proxy_returns_false(self):
        from core.proxy_manager import verify_proxy_reachable
        with patch("core.proxy_manager.socket.create_connection",
                   side_effect=OSError("refused")):
            self.assertFalse(verify_proxy_reachable("socks5h://203.0.113.1:9050", timeout=1))

    def test_default_port_inferred_from_scheme(self):
        from core.proxy_manager import verify_proxy_reachable
        with patch("core.proxy_manager.socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = lambda s: s
            mock_conn.return_value.__exit__ = lambda s, *a: False
            verify_proxy_reachable("socks5://1.2.3.4")
            self.assertEqual(mock_conn.call_args[0][0], ("1.2.3.4", 1080))
            verify_proxy_reachable("https://1.2.3.4")
            self.assertEqual(mock_conn.call_args[0][0], ("1.2.3.4", 443))


if __name__ == "__main__":
    unittest.main()
