"""Behavioral tests for the sync HTTP stack in core/http_client.py.

The biggest uncovered block left after the async refactor (305 of 390
statements): GhostMode, HTTPClient's raw-socket codec, and both
http_send transports. Network boundaries are mocked; wire parsing and
policy integration run for real.
"""
import gzip
import socket
import unittest
import zlib
from unittest.mock import MagicMock, patch

from core.http_client import (
    GhostMode,
    HTTPClient,
    _audit_body,
    _warn_policy_deny,
    dns_resolve,
    http_send,
    thttp,
)


class TestAuditBody(unittest.TestCase):
    def test_json_body_dumps(self):
        self.assertEqual(_audit_body(json_body={"a": 1}), '{"a": 1}')

    def test_dict_body_urlencoded(self):
        self.assertEqual(_audit_body(data={"a": "1 2"}), "a=1+2")

    def test_bytes_decoded_with_replace(self):
        self.assertEqual(_audit_body(data=b"\xffx"), "\ufffdx")

    def test_none_when_no_body(self):
        self.assertIsNone(_audit_body())

    def test_str_passthrough(self):
        self.assertEqual(_audit_body(data="raw"), "raw")


class TestWarnPolicyDeny(unittest.TestCase):
    def setUp(self):
        from core import http_client
        http_client._POLICY_DENY_WARNED.clear()

    def test_warns_once_per_reason_with_budget_hint(self):
        with patch("core.ui.w") as mock_w:
            _warn_policy_deny("request_budget_exhausted")
            _warn_policy_deny("request_budget_exhausted")
            _warn_policy_deny("scope_denied")
        self.assertEqual(mock_w.call_count, 2)
        joined = " ".join(str(c) for c in mock_w.call_args_list)
        self.assertIn("--max-requests", joined)


class TestGhostMode(unittest.TestCase):
    def tearDown(self):
        GhostMode.ENABLED = False
        GhostMode._rate_limiter = None

    def test_global_enable_forces_stealth(self):
        GhostMode.ENABLED = True
        self.assertTrue(GhostMode.should_stealth("any.host"))

    def test_auto_stealth_from_rate_limiter(self):
        rl = MagicMock()
        rl.is_auto_stealth.return_value = True
        GhostMode.set_rate_limiter(rl)
        self.assertTrue(GhostMode.should_stealth("pressed.host"))
        rl.is_auto_stealth.assert_called_once_with("pressed.host")

    def test_quiet_host_gets_no_stealth(self):
        self.assertFalse(GhostMode.should_stealth("calm.host"))

    def test_stealth_headers_use_central_ua_pool(self):
        from core import ua
        headers = GhostMode.get_stealth_headers("h.test")
        self.assertEqual(headers["Host"], "h.test")
        self.assertIn(headers["User-Agent"], ua.STEALTH_UAS)
        self.assertEqual(headers["Connection"], "close")


class TestHTTPClientCodec(unittest.TestCase):
    def setUp(self):
        self.client = HTTPClient()

    def test_gzip_body_decoded(self):
        wire = gzip.compress(b"hello gz")
        self.assertEqual(self.client._decode_content(
            wire, {"content-encoding": "gzip"}), b"hello gz")

    def test_deflate_body_decoded(self):
        wire = zlib.compress(b"hello zlib")
        self.assertEqual(self.client._decode_content(
            wire, {"content-encoding": "deflate"}), b"hello zlib")

    def test_chunked_transfer_dechunked(self):
        self.assertEqual(self.client._decode_content(
            b"5\r\nhello\r\n0\r\n", {"transfer-encoding": "chunked"}), b"hello")

    def test_unknown_encoding_returned_as_is(self):
        self.assertEqual(self.client._decode_content(b"data", {}), b"data")

    def test_to_text_prefers_declared_encoding(self):
        self.assertEqual(self.client._to_text("ä".encode("latin-1"), "latin-1"), "ä")

    def test_parse_raw_response_status_and_headers(self):
        raw = (b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\n"
               b"Content-Length: 3\r\n\r\nnope")
        status, headers, body = self.client._parse_raw_response(raw)
        self.assertEqual(status, 404)
        self.assertEqual(headers["server"], "nginx")
        self.assertEqual(body, b"nope")

    def test_decode_chunked_wire(self):
        self.assertEqual(
            self.client._decode_chunked(b"3\r\nabc\r\n2\r\nde\r\n0\r\n"), b"abcde")

    def test_close_idempotent(self):
        self.client.session = MagicMock()
        self.client.close()
        self.client.close()  # second close with session=None must not raise


def _fake_socket(response_bytes: bytes):
    sock = MagicMock()
    sock.recv_side_effects = [response_bytes[i:i + 4096]
                              for i in range(0, len(response_bytes), 4096)] or [b""]

    def recv(_n):
        if sock.recv_side_effects:
            return sock.recv_side_effects.pop(0)
        return b""

    sock.recv.side_effect = recv
    return sock


class TestRawSocketTransport(unittest.IsolatedAsyncioTestCase):
    def _run(self, sock, url="https://target.test/path"):
        with patch("core.curl_cffi_transport.CURL_CFFI_AVAILABLE", False), \
             patch("core.http_client.socket.create_connection", return_value=sock), \
             patch("core.http_client.ssl.create_default_context") as ctx_cls, \
             patch("core.audit.AuditLogger.get_instance") as aud, \
             patch("core.proxy_manager.resolve_proxy", return_value=None), \
             patch("core.ui.count_request"):
            ctx = MagicMock()
            ctx.wrap_socket.return_value = sock
            ctx_cls.return_value = ctx
            aud.return_value = MagicMock()
            return http_send(url, timeout=3)

    def test_raw_https_response_parsed(self):
        sock = _fake_socket(b"HTTP/1.1 200 OK\r\nServer: t\r\n\r\n" + b"<html>ok</html>")
        result = self._run(sock)
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["body"], "<html>ok</html>")
        self.assertEqual(result["headers"]["server"], "t")

    def test_connection_error_becomes_status_zero(self):
        fake = MagicMock()
        fake.connect.side_effect = ConnectionRefusedError("nope")
        with patch("core.curl_cffi_transport.CURL_CFFI_AVAILABLE", False), \
             patch("core.http_client.socket.socket", return_value=fake), \
             patch("core.http_client.ssl.create_default_context") as ctx_cls, \
             patch("core.proxy_manager.resolve_proxy", return_value=None), \
             patch("core.audit.AuditLogger.get_instance") as aud, \
             patch("core.ui.count_request"):
            ctx_cls.return_value = MagicMock(wrap_socket=MagicMock(return_value=fake))
            aud.return_value = MagicMock()
            result = http_send("https://down.test/", timeout=1)
        self.assertEqual(result["status"], 0)
        self.assertIn("nope", result["error"])


class TestCurlCffiTransport(unittest.TestCase):
    def tearDown(self):
        GhostMode.ENABLED = False
        GhostMode._rate_limiter = None

    def _send(self, session_result, **kw):
        sess = MagicMock()
        sess.request.return_value = session_result
        with patch("core.curl_cffi_transport.CURL_CFFI_AVAILABLE", True), \
             patch("core.curl_cffi_transport.CurlCffiSession", return_value=sess), \
             patch("core.audit.AuditLogger.get_instance") as aud, \
             patch("core.ui.count_request"):
            aud.return_value = MagicMock()
            result = http_send("https://ok.test/x", timeout=3, **kw)
        return result, sess

    def test_success_result_passthrough_with_audit(self):
        result, sess = self._send({
            "status": 200, "headers": {"server": "s"}, "body": "hi",
            "url": "https://ok.test/x", "time": 0.1})
        self.assertEqual(result["status"], 200)
        sess.request.assert_called_once()

    def test_stealth_headers_injected_when_enabled(self):
        GhostMode.ENABLED = True
        with patch("core.http_client.time.sleep"):  # GhostMode jitter
            _result, sess = self._send({
                "status": 200, "headers": {}, "body": "", "url": "", "time": 0})
        sent_headers = sess.request.call_args.kwargs["headers"]
        self.assertIn("User-Agent", sent_headers)
        self.assertEqual(sent_headers["Host"], "ok.test")

    def test_bypass_headers_override(self):
        _result, sess = self._send({
            "status": 200, "headers": {}, "body": "", "url": "", "time": 0},
            bypass=True)
        sent_headers = sess.request.call_args.kwargs["headers"]
        self.assertTrue(sent_headers)  # WAFBypass headers applied

    def test_redirect_out_of_scope_denied_by_policy(self):
        policy = MagicMock()
        policy.dry_run = False
        policy.allows_url.return_value = False
        result, _ = self._send(
            {"status": 200, "headers": {}, "body": "x",
             "url": "https://evil.test/landing", "time": 0},
            policy=policy)
        self.assertEqual(result["status"], 0)
        self.assertIn("policy_denied:redirect_out_of_scope", result["error"])


class TestPolicyGateSync(unittest.TestCase):
    def test_denied_request_never_touches_transport(self):
        policy = MagicMock()
        policy.authorize_request.return_value = MagicMock(allowed=False, reason="budget")
        with patch("core.curl_cffi_transport.CurlCffiSession") as sess_cls:
            result = http_send("https://x.test/", policy=policy)
        self.assertEqual(result["status"], 0)
        sess_cls.assert_not_called()

    def test_dry_run_refunds_without_network(self):
        policy = MagicMock()
        policy.authorize_request.return_value = MagicMock(allowed=True, reason="")
        policy.dry_run = True
        result = http_send("https://x.test/", policy=policy)
        self.assertEqual(result["status"], 200)
        self.assertIn("DRY RUN", result["body"])
        policy.refund_request.assert_called_once()


class TestThttpAndDns(unittest.TestCase):
    def test_thttp_swallows_exceptions_into_error_dict(self):
        with patch("core.http_client.http_send", side_effect=RuntimeError("boom")):
            result = thttp("https://x.test/")
        self.assertEqual(result["status"], 0)
        self.assertIn("boom", result["error"])

    def test_dns_resolve_dedupes_v4_and_v6(self):
        infos = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800::1", 80, 0, 0)),
        ]
        with patch("core.http_client.socket.getaddrinfo", return_value=infos):
            ips = dns_resolve("example.com")
        self.assertEqual(sorted(ips), ["2606:2800::1", "93.184.216.34"])

    def test_dns_resolve_swallows_gaierror(self):
        with patch("core.http_client.socket.getaddrinfo",
                   side_effect=socket.gaierror("NXDOMAIN")):
            self.assertEqual(dns_resolve("nope.invalid"), [])


if __name__ == "__main__":
    unittest.main()
