"""
Async HTTP engine — AsyncNetworkEngine (HTTP/2, curl_cffi TLS
impersonation, circuit breaker, adaptive pacing).

The sync stack (http_send, HTTPClient, GhostMode) lives in
core.http_client.
"""
import asyncio
import time
import uuid

import httpx

from core.audit import AuditLogger
from core.resilience import AdaptivePacingSystem, CircuitBreaker

from .http_client import _audit_body, _warn_policy_deny


class AsyncNetworkEngine:
    """High-performance, multiplexed HTTP/2 asynchronous network engine.
    
    Supports curl_cffi impersonation for TLS fingerprint spoofing.
    Circuit breaker + adaptive pacing integrated for smart throttling.
    Integrates dynamically with ProxyManager for per-request proxy rotation.
    """

    def __init__(self, max_connections: int = 100, impersonate: str | None = None,
                 browser: str | None = None, policy=None):
        self.impersonate = impersonate
        self.browser = browser
        self.policy = policy
        # Optional callback(latency_seconds) invoked once per successful
        # response. Poison mode wires it to PoisonState.track_request_latency
        # so adaptive concurrency reacts to real request latency instead of
        # whole-phase durations. None = no overhead, no behavior change.
        self.latency_observer = None
        policy_limit = getattr(policy, "max_concurrency", None)
        self.max_connections = min(max_connections, policy_limit) if policy_limit else max_connections
        self._use_curl_cffi = False
        self._curl_cffi_session = None
        self._active_proxy = None
        self.client = None
        self._rebuild_lock = asyncio.Lock()
        self._request_semaphore = asyncio.Semaphore(self.max_connections)
        # Origin-IP passthrough (diisi runners/vuln_assault saat WAF-bypass):
        # URL sudah ber-IP tapi vhost asli tetap dibutuhkan. Overrides per-URL
        # presisi; map per-IP fallback untuk URL yang tak terdaftar.
        self.origin_host_overrides: dict = {}
        self.origin_host_map: dict = {}

        # Check if curl_cffi is available to set the default _use_curl_cffi flag
        try:
            from core.curl_cffi_transport import CURL_CFFI_AVAILABLE
            if CURL_CFFI_AVAILABLE:
                self._use_curl_cffi = True
        except ImportError:
            pass

        # Build initial client synchronously (no old session to close yet)
        self._build_client(None)

        # Per-host rate limiter (primary) + legacy global pacing (fallback)
        from core.host_ratelimit import HostRateLimiter
        self.host_limiter = HostRateLimiter(default_max_concurrent=max_connections)
        self.rate_limiter = AdaptivePacingSystem()
        self.circuit_breaker = CircuitBreaker()

    def _build_client(self, proxy: str | None):
        """Builds a new HTTP client with the given proxy (no old session closing).

        All three transport fields are swapped together at the end (single
        synchronous block, no awaits) so a concurrent reader on the event
        loop never observes a half-built state — previously the curl path
        left a stale httpx client behind and vice versa.
        """
        use_curl = False
        curl_session = None
        httpx_client = None

        try:
            from core.curl_cffi_transport import CURL_CFFI_AVAILABLE, CurlCffiAsyncSession
            if CURL_CFFI_AVAILABLE:
                curl_session = CurlCffiAsyncSession(
                    impersonate=self.impersonate,
                    browser=self.browser or "chrome",
                    timeout=30,
                    verify=False,
                    # Redirects are disabled when policy enforcement is active:
                    # a transport client must never silently follow an
                    # out-of-scope Location header.
                    follow_redirects=self.policy is None,
                    proxy=proxy,
                )
                use_curl = True
        except ImportError:
            pass

        if not use_curl:
            self.limits = httpx.Limits(
                max_keepalive_connections=self.max_connections,
                max_connections=self.max_connections,
            )
            httpx_client = httpx.AsyncClient(
                http2=True, verify=False, follow_redirects=self.policy is None,
                limits=self.limits, timeout=httpx.Timeout(10.0),
                proxy=proxy,
            )

        self._active_proxy = proxy
        self._use_curl_cffi = use_curl
        self._curl_cffi_session = curl_session
        self.client = httpx_client

    async def _rebuild_client_with_proxy(self, proxy: str | None):
        """Swaps in a new client for the proxy, then closes the old one.

        Order matters: the old implementation nulled self.client /
        _curl_cffi_session BEFORE building the replacement, opening a window
        where concurrent ahttp_send readers hit None.request → AttributeError
        → request silently lost as status 0. Build-and-swap first, close after.
        """
        old_curl = self._curl_cffi_session
        old_httpx = self.client
        self._build_client(proxy)
        if old_curl is not None and old_curl is not self._curl_cffi_session:
            try:
                await old_curl.close()
            except Exception:
                pass
        if old_httpx is not None and old_httpx is not self.client:
            try:
                await old_httpx.aclose()
            except Exception:
                pass

    async def ahttp_send(self, url: str, method: str = "GET", headers: dict | None = None,
                          data=None, json=None, bypass: bool = False,
                          state_context=None,
                          timeout: float | None = None) -> dict:
        """Async HTTP request with per-host rate limiting + circuit breaker."""
        from urllib.parse import urlparse as _urlparse

        from core.proxy_manager import get_global_proxy_manager
        from core.ui import count_request
        from modules.auth.bypass import WAFBypass

        trace = uuid.uuid4().hex[:12]
        if self.policy:
            decision = self.policy.authorize_request(url, method,
                                                     headers=headers,
                                                     body=_audit_body(data, json),
                                                     trace_id=trace)
            if not decision.allowed:
                _warn_policy_deny(decision.reason)
                return {
                    "status": 0,
                    "error": f"policy_denied:{decision.reason}",
                    "time": 0,
                    "waf": [],
                    "body": "",
                    "headers": {},
                    "url": url,
                }
            if getattr(self.policy, "dry_run", False):
                self.policy.refund_request(reason="dry_run", url=url,
                                           trace_id=trace)
                return {
                    "status": 200,
                    "error": None,
                    "body": "[DRY RUN] Request authorized but not dispatched to network.",
                    "headers": {"content-type": "text/html; charset=utf-8", "x-verdamt-dry-run": "1"},
                    "url": url,
                    "time": 0.001,
                    "waf": [],
                }
            timeout = self.policy.clamp_timeout(timeout)

        # Dynamic Proxy Check: Re-build client if active proxy has changed in manager
        proxy_mgr = get_global_proxy_manager()
        if proxy_mgr and proxy_mgr.get_current() != self._active_proxy:
            async with self._rebuild_lock:
                # Double-check after acquiring lock
                if proxy_mgr.get_current() != self._active_proxy:
                    await self._rebuild_client_with_proxy(proxy_mgr.get_current())

        hostname = _urlparse(url).hostname or "unknown"

        # Per-host rate limit acquire (with timeout = request timeout + 5s)
        acquire_timeout = min(timeout + 5, 30) if timeout else 15
        if not await self.host_limiter.acquire(hostname, timeout=acquire_timeout):
            if self.policy:
                self.policy.refund_request(reason=f"rate_limited:host {hostname}",
                                           url=url, trace_id=trace)
            return {
                "status": 0, "error": f"rate_limited: host {hostname} backoff active",
                "time": 0, "waf": [], "body": "", "headers": {},
            }

        global_acquired = False
        try:
            await asyncio.wait_for(self._request_semaphore.acquire(), timeout=acquire_timeout)
            global_acquired = True
        except TimeoutError:
            self.host_limiter.release(hostname, 0)
            if self.policy:
                self.policy.refund_request(reason="concurrency_budget_exhausted",
                                           url=url, trace_id=trace)
            return {
                "status": 0, "error": "concurrency_budget_exhausted",
                "time": 0, "waf": [], "body": "", "headers": {},
            }
        except BaseException:
            # Cancellation/crash while queueing: without this the host slot
            # acquired above leaks permanently — every later request to this
            # host queues behind a phantom slot (module _bounded timeouts
            # cancel tasks exactly here).
            self.host_limiter.release(hostname, 0)
            raise

        status = 0
        start_time = time.time()
        try:
            # Circuit breaker check — block if OPEN
            if not self.circuit_breaker.allow_request(hostname):
                cooldown = self.circuit_breaker.get_cooldown_remaining(hostname)
                if proxy_mgr:
                    proxy_mgr.record_request(error=True)
                if self.policy:
                    self.policy.refund_request(reason="circuit_open",
                                               url=url, trace_id=trace)
                return {
                    "status": 0, "error": f"circuit_open: cooling down ({cooldown:.0f}s remaining)",
                    "time": 0, "waf": [], "body": "", "headers": {},
                }

            count_request()  # actual dispatch point (post policy/limiter/circuit)

            req_headers = dict(headers or {})

            if state_context:
                state_context.inject_auth(url, req_headers)

            # Origin-IP override: semua modul async (injection, jwt, crlf,
            # host, idor, stored_xss, oob) otomatis dapat Host vhost asli —
            # dulu hanya nuclei/dalfox yang dipasangi Host manual, sisanya
            # menembak default vhost (Host: <IP>) = false negative senyap.
            origin_host = (self.origin_host_overrides.get(url)
                           or self.origin_host_map.get(hostname))
            if origin_host and not any(k.lower() == "host" for k in req_headers):
                req_headers["Host"] = origin_host

            if bypass:
                req_headers.update(WAFBypass.get_bypass_headers())

            # NOTE: rate_limiter.wait() removed — host_limiter already handles
            # per-host pacing. Keeping record_latency/trigger_backoff for metrics.

            is_error = False

            if self._use_curl_cffi:
                response = await self._curl_cffi_session.request(
                    method, url, headers=req_headers,
                    data=data, json=json,
                    timeout=int(timeout) if timeout else None,
                )
            else:
                response = await self.client.request(
                    method, url, headers=req_headers,
                    data=data, json=json, timeout=timeout,
                )
                waf = WAFBypass.detect_waf(dict(response.headers), response.text)
                response = {
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                    "url": str(response.url),
                    "time": time.time() - start_time,
                    "error": None,
                    "waf": waf,
                }

            AuditLogger.get_instance().log_response(
                url, method, status_code=response.get("status") or 0,
                elapsed=response.get("time") or (time.time() - start_time),
                error=response.get("error"), trace_id=trace)
            if self.policy and response.get("url") and not self.policy.allows_url(response["url"]):
                return {
                    "status": 0,
                    "error": "policy_denied:redirect_out_of_scope",
                    "time": time.time() - start_time,
                    "waf": [],
                    "body": "",
                    "headers": {},
                    "url": response.get("url", url),
                }

            latency = response.get("time", time.time() - start_time)
            if self.latency_observer is not None:
                try:
                    self.latency_observer(latency)
                except Exception:
                    pass
            status = response.get("status", 0)

            # Update circuit breaker + pacing based on response.
            # HANYA 429 = rate limit nyata. 403 adalah respons aplikasi
            # normal saat scanner menyentuh path terproteksi (/admin, payload
            # diblokir WAF) — dulu tiap 403 ikut record_failure + pacing
            # backoff, sehingga 5x 403 membuka circuit 30-300s dan SELURUH
            # request host itu jadi status:0 "circuit_open" (scan macet
            # total di target ber-WAF/auth).
            if status == 429:
                self.circuit_breaker.record_failure(hostname, status)
                self.rate_limiter.trigger_backoff()
                is_error = True
            elif status > 0:
                self.circuit_breaker.record_success(hostname)

            if proxy_mgr:
                proxy_mgr.record_request(error=is_error)

            # Passive Secret Scanning
            if response.get("body") and response.get("status") == 200:
                try:
                    from core.secret_scanner import SecretScanner
                    sec_findings = SecretScanner.scan_response(url, response["body"])
                    if sec_findings:
                        for sf in sec_findings:
                            AuditLogger.get_instance().log_finding(
                                sf["title"], sf["severity"], sf["url"], sf["detail"],
                                evidence=response["body"], trace_id=trace
                            )
                except Exception:
                    pass

            return response
        except Exception as e:
            self.rate_limiter.record_error()
            # Transport-level errors (DNS/connect/TLS/timeout) are NOT server
            # rejections — counting them opened the circuit after 5 flaky
            # packets and stalled the scan for the cooldown.
            if proxy_mgr:
                proxy_mgr.record_request(error=True)
            status = 0
            AuditLogger.get_instance().log_response(
                url, method, status_code=0,
                elapsed=time.time() - start_time, error=str(e),
                trace_id=trace)
            return {"status": 0, "error": str(e), "time": time.time() - start_time,
                    "waf": [], "body": "", "headers": {}}
        finally:
            # Always release per-host semaphore + update backoff state
            self.host_limiter.release(hostname, status)
            if global_acquired:
                self._request_semaphore.release()

    async def close(self):
        if self._use_curl_cffi and self._curl_cffi_session:
            try:
                await self._curl_cffi_session.close()
            except Exception:
                pass
            self._curl_cffi_session = None
        elif self.client:
            try:
                await self.client.aclose()
            except Exception:
                pass
            self.client = None
