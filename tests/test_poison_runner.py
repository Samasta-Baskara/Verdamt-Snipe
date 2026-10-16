import asyncio
import time
import unittest
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from runners.poison import (
    PoisonState,
    _BACKUP_EXTS,
    EXT_PASS_MAX,
    _adaptive_wave_loop,
    _budget_ok,
    _budget_warning,
    _brute_login_form,
    _classify_login_attempt,
    _cookie_names,
    _cred_list,
    _edge_shields_origin,
    _exhaust_finding,
    _fetch_login_form,
    _ffuf_timeout,
    _get_header,
    _hold_for_backoff,
    _parse_finding_param,
    _post_payload_pass,
    _rot_slice,
    _run_ffuf,
    phase_bruteforce,
    phase_connection_exhaust,
    phase_oob,
    phase_param_flood,
    phase_payload_flood,
    phase_smuggling,
    run_poison_assault,
    verify_sensitive_files,
)


def setUpModule():
    """Hermetic CI: never let orchestrator tests hit the network.

    auto_setup_wordlists() downloads SecLists/Assetnote files on machines
    without ~/.wordlists (fresh CI runners) — 403/404 noise, extra network
    latency, zero test signal. Patch the downloader off for this module;
    the embedded fallback lists keep the runs deterministic.
    """
    patcher = patch("modules.wordlists.download_wordlist", return_value=None)
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)


class TestPoisonRunnerState(unittest.TestCase):
    def _create_state(self):
        return PoisonState(
            target="example.com",
            seed_url="https://example.com",
            services=[],
            subs=[],
            scan_urls=["https://example.com/"],
            scope_guard=MagicMock(),
            session_manager=MagicMock(),
            async_engine=MagicMock(),
            is_turbo=False,
        )

    def test_poison_state_sync_and_async_locks(self):
        state = self._create_state()

        # Synchronous concurrent mutations protected by _sync_lock
        f1 = {"type": "Sync XSS", "severity": "High", "url": "http://example.com/a", "detail": "detail1"}
        f2 = {"type": "Sync SQLi", "severity": "Critical", "url": "http://example.com/b", "detail": "detail2"}
        state.add_finding(f1)
        state.extend_findings([f2])

        self.assertEqual(len(state.findings), 2)

    def test_async_poison_state_dedup(self):
        async def run_async_test():
            state = self._create_state()
            f1 = {"type": "Async XSS", "severity": "High", "url": "http://example.com/c", "detail": "detail3"}
            await state.add_finding_async(f1)
            # Duplicate call
            await state.add_finding_async(f1)
            self.assertEqual(len(state.findings), 1)

        asyncio.run(run_async_test())


class TestCookieParsing(unittest.TestCase):
    def test_expires_date_is_not_a_cookie(self):
        raw = "sid=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT, csrf=abc"
        self.assertEqual(_cookie_names(raw), {"sid", "csrf"})

    def test_single_cookie(self):
        self.assertEqual(_cookie_names("session=xyz"), {"session"})

    def test_header_lookup_is_case_insensitive(self):
        self.assertEqual(_get_header({"Location": "/a"}, "location"), "/a")
        self.assertEqual(_get_header({"location": "/b"}, "Location"), "/b")
        self.assertEqual(_get_header({}, "location"), "")
        self.assertEqual(_get_header(None, "location"), "")


class TestLoginClassification(unittest.TestCase):
    REDIR_BASE = {"status": 302, "loc_path": "/login",
                  "cookies": {"sid"}, "body": "invalid credentials"}
    OK_BASE = {"status": 200, "loc_path": "",
               "cookies": {"sid"}, "body": "invalid credentials"}

    def test_same_redirect_as_failed_login_is_not_a_hit(self):
        # Endpoint that always 302s — the old code reported "confirmed" here.
        self.assertIsNone(
            _classify_login_attempt(302, {"location": "/login?e=1"},
                                    "", self.REDIR_BASE))

    def test_new_redirect_destination_is_confirmed(self):
        conf, _ = _classify_login_attempt(
            302, {"location": "/dashboard"}, "", self.REDIR_BASE)
        self.assertEqual(conf, "confirmed")

    def test_redirect_after_non_redirect_baseline_is_confirmed(self):
        conf, _ = _classify_login_attempt(
            307, {"location": "/home"}, "", self.OK_BASE)
        self.assertEqual(conf, "confirmed")

    def test_redirect_without_baseline_is_only_suspected(self):
        no_base = {"status": 0, "loc_path": "", "cookies": set(), "body": ""}
        conf, detail = _classify_login_attempt(
            302, {"location": "/dashboard"}, "", no_base)
        self.assertEqual(conf, "suspected")
        self.assertIn("no failed-login baseline", detail)

    def test_new_cookie_is_suspected(self):
        conf, detail = _classify_login_attempt(
            200, {"set-cookie": "auth=abc"}, "welcome back", self.OK_BASE)
        self.assertEqual(conf, "suspected")
        self.assertIn("auth", detail)

    def test_body_difference_is_suspected(self):
        conf, _ = _classify_login_attempt(
            200, {}, "dashboard home " * 50, self.OK_BASE)
        self.assertEqual(conf, "suspected")

    def test_failure_keywords_and_no_diff_yield_nothing(self):
        self.assertIsNone(
            _classify_login_attempt(200, {}, "invalid password", self.OK_BASE))
        self.assertIsNone(_classify_login_attempt(404, {}, "not found", self.OK_BASE))


class TestFindingIndex(unittest.TestCase):
    def _state(self):
        return PoisonState(target="example.com", seed_url="https://example.com",
                           services=[], subs=[], scan_urls=["https://example.com/"],
                           scope_guard=MagicMock(), session_manager=MagicMock(),
                           async_engine=MagicMock(), is_turbo=False)

    def test_index_stays_consistent_and_order_is_kept(self):
        state = self._state()
        for i in range(500):
            state.add_finding({"type": "t", "url": f"https://e/{i % 100}",
                               "detail": "d"})
        state.extend_findings([{"type": "t", "url": "https://e/1", "detail": "d"},
                               {"type": "t", "url": "https://e/999", "detail": "d"}])
        self.assertEqual(len(state.findings), 101)
        self.assertEqual(len({state._finding_key(f) for f in state.findings}),
                         len(state.findings))
        self.assertEqual(state._finding_keys,
                         {state._finding_key(f) for f in state.findings})
        # first occurrence keeps its position
        self.assertEqual(state.findings[0]["url"], "https://e/0")
        self.assertEqual(state.findings[-1]["url"], "https://e/999")

    def test_async_and_sync_helpers_share_the_index(self):
        state = self._state()
        state.add_finding({"type": "x", "url": "u", "detail": "d"})
        asyncio.run(state.add_finding_async({"type": "x", "url": "u", "detail": "d"}))
        self.assertEqual(len(state.findings), 1)


class _StubPolicy:
    def __init__(self, remaining):
        self._remaining = remaining

    @property
    def requests_remaining(self):
        return self._remaining


class TestBudgetGate(unittest.TestCase):
    def _state(self):
        return PoisonState(target="example.com", seed_url="https://example.com",
                           services=[{"url": "https://example.com/"}], subs=[],
                           scan_urls=["https://example.com/"],
                           scope_guard=MagicMock(), session_manager=MagicMock(),
                           async_engine=MagicMock(), is_turbo=False)

    def test_gate_opens_without_policy_or_with_budget(self):
        state = self._state()
        self.assertTrue(_budget_ok(state))          # policy is None
        state.policy = _StubPolicy(5000)
        self.assertTrue(_budget_ok(state))
        state.policy = _StubPolicy(None)            # unlimited
        self.assertTrue(_budget_ok(state))

    def test_gate_closes_when_budget_spent(self):
        state = self._state()
        state.policy = _StubPolicy(0)
        self.assertFalse(_budget_ok(state))

    def test_ffuf_not_dispatched_after_budget_spent(self):
        state = self._state()
        state.policy = _StubPolicy(0)
        result = asyncio.run(_run_ffuf("https://example.com/", ["admin"], "",
                                       100, policy=state.policy))
        self.assertEqual(result, [])   # returns before _find_tool / subprocess

    def test_summary_budget_line(self):
        # budget reporting must not blow up on unlimited policies
        state = self._state()
        state.policy = _StubPolicy(None)
        self.assertIsNone(state.policy.requests_remaining)


class TestDeadline(unittest.TestCase):
    def _state(self):
        return PoisonState(target="example.com", seed_url="https://example.com",
                           services=[{"url": "https://example.com/"}], subs=[],
                           scan_urls=["https://example.com/"],
                           scope_guard=MagicMock(), session_manager=MagicMock(),
                           async_engine=MagicMock(), is_turbo=False)

    def test_ffuf_timeout_never_exceeds_time_left(self):
        state = self._state()
        state.max_duration = 120
        self.assertLessEqual(_ffuf_timeout(state), 120)
        state.max_duration = 0
        self.assertEqual(_ffuf_timeout(state), 1)
        state.max_duration = 10_000
        self.assertEqual(_ffuf_timeout(state), 120)  # Paket 3 cap (was 45)

    def test_wave_loop_is_noop_when_time_is_up(self):
        state = self._state()
        state.max_duration = 0
        asyncio.run(_adaptive_wave_loop(state))
        self.assertEqual(state.async_engine.ahttp_send.call_count, 0)
        self.assertEqual(state.findings, [])


class TestParamDiscoveryDedup(unittest.TestCase):
    def _state(self):
        # scope_guard=None: a MagicMock would swallow add_urls() results
        return PoisonState(target="example.com", seed_url="https://example.com",
                           services=[], subs=[],
                           scan_urls=["https://example.com/", "https://example.com/a"],
                           scope_guard=None, session_manager=MagicMock(),
                           async_engine=MagicMock(), is_turbo=False)

    def test_same_url_is_not_fuzzed_twice(self):
        from unittest.mock import patch
        state = self._state()
        with patch("modules.extras.arjun.AsyncParamBruteforcer") as mock_bf:
            mock_bf.return_value.run = AsyncMock(return_value=["q"])
            asyncio.run(phase_param_flood(state))   # A1
            after_first = mock_bf.call_count        # one construction per target
            asyncio.run(phase_param_flood(state))   # A3 / next wave
        self.assertEqual(after_first, 2)                     # both top targets
        self.assertEqual(mock_bf.call_count, after_first)    # nothing re-fuzzed
        self.assertEqual(state._param_scanned,
                         {"https://example.com/", "https://example.com/a"})

    def test_new_url_still_gets_scanned(self):
        from unittest.mock import patch
        state = self._state()
        with patch("modules.extras.arjun.AsyncParamBruteforcer") as mock_bf:
            mock_bf.return_value.run = AsyncMock(return_value=["q"])
            asyncio.run(phase_param_flood(state))
            self.assertEqual(mock_bf.call_count, 2)
            state.add_urls(["https://example.com/new"])
            asyncio.run(phase_param_flood(state))
        self.assertEqual(mock_bf.call_count, 3)
        self.assertIn("https://example.com/new", state._param_scanned)


class TestCancellationClosesSockets(unittest.TestCase):
    """Wave-deadline cancellation must not leak raw-socket FDs."""

    def test_cancelled_slowloris_still_closes_writer(self):
        from unittest.mock import patch
        from modules.web.server_side.connection_exhaust import ConnectionExhaust

        ex = ConnectionExhaust("https://example.com", timeout=30)
        fake_writer = MagicMock()
        fake_writer.drain = AsyncMock()

        async def fake_open():
            return None, fake_writer

        async def run():
            with patch.object(ex, "_open_connection", fake_open):
                task = asyncio.create_task(ex._slowloris_async(1))
                await asyncio.sleep(0.05)   # parked in the keep-alive sleep
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        asyncio.run(run())
        fake_writer.close.assert_called()

    def test_cancelled_smuggle_request_still_closes_writer(self):
        from unittest.mock import patch
        from modules.web.server_side import smuggling

        fake_writer = MagicMock()
        fake_writer.drain = AsyncMock()
        fake_reader = MagicMock()

        async def slow_read(n):
            await asyncio.sleep(30)
            return b""

        fake_reader.read = slow_read

        async def fake_tunnel(host, port, **kwargs):
            return fake_reader, fake_writer

        async def run():
            # smuggling imports open_proxied_connection at call time
            with patch("core.proxy_manager.open_proxied_connection", fake_tunnel):
                task = asyncio.create_task(
                    smuggling._async_raw_request("example.com", 443, False,
                                                 "GET / HTTP/1.1\r\n\r\n"))
                await asyncio.sleep(0.05)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        asyncio.run(run())
        fake_writer.close.assert_called()


class TestPhase0Budget(unittest.IsolatedAsyncioTestCase):
    """Phase 0 (WAF pipeline) must have its own time slice — it used to burn
    the wave clock, so --max-time runs ended with a single wave."""

    def _args(self, max_duration: int) -> dict[str, Any]:
        return dict(
            target="example.com", seed_url="https://example.com/",
            services=[{"url": "https://example.com/"}], subs=[],
            scan_urls=["https://example.com/"], scope_guard=None,
            session_manager=MagicMock(), async_engine=MagicMock(),
            is_turbo=False, max_duration=max_duration, policy=None,
        )

    async def test_phase0_time_does_not_eat_wave_budget(self):
        from unittest.mock import patch
        first_wave_elapsed = []
        wave_calls = []

        async def fast_phase0(*args, **kwargs):
            await asyncio.sleep(1.5)
            return {}

        async def recorder(state):
            wave_calls.append(state.elapsed)

        with patch("modules.waf.bypass_engine.waf_bypass_pipeline", fast_phase0), \
             patch("runners.poison.orchestrator._adaptive_wave_loop", recorder), \
             patch("modules.wordlists.WordlistProvider") as wl:
            wl.return_value._local = {"dir": "x"}
            wl.return_value.summary.return_value = ""
            start = time.time()
            result = await run_poison_assault(**self._args(max_duration=2))
            wall = time.time() - start

        self.assertEqual(len(result), 4)
        # Phase 0 really ran (1.5s) …
        self.assertGreaterEqual(wall, 1.5)
        # … but the wave clock restarted after it: without the reset the
        # first wave would see elapsed >= 1.5.
        self.assertLess(min(wave_calls), 1.0,
                        "wave budget must not include Phase 0 time")
        self.assertGreaterEqual(len(wave_calls), 1)

    async def test_phase0_slice_is_enforced(self):
        from unittest.mock import patch
        wave_calls = []

        async def hung_phase0(*args, **kwargs):
            await asyncio.sleep(30)
            return {}

        async def recorder(state):
            wave_calls.append(state.elapsed)

        with patch("modules.waf.bypass_engine.waf_bypass_pipeline", hung_phase0), \
             patch("runners.poison.orchestrator._adaptive_wave_loop", recorder), \
             patch("modules.wordlists.WordlistProvider") as wl:
            wl.return_value._local = {"dir": "x"}
            wl.return_value.summary.return_value = ""
            start = time.time()
            result = await run_poison_assault(**self._args(max_duration=2))
            wall = time.time() - start

        self.assertEqual(len(result), 4)
        # slice = min(max_duration, cap) = 2s → pipeline cancelled, no hang
        self.assertLess(wall, 10, "Phase 0 must be cancelled at its slice")
        self.assertGreaterEqual(len(wave_calls), 1,
                                "waves must still run after a cancelled Phase 0")


class TestAdaptiveController(unittest.TestCase):
    """The controller must react to real request latency, not phase length."""

    def _state(self, concurrency=100):
        st = PoisonState(target="example.com", seed_url="https://example.com/",
                         services=[], subs=[], scan_urls=["https://example.com/"],
                         scope_guard=None, session_manager=MagicMock(),
                         async_engine=MagicMock(), is_turbo=False)
        st.current_concurrency = concurrency
        return st

    def test_phase_duration_no_longer_changes_concurrency(self):
        # old bug: a 45s ffuf phase was treated as request latency, halving
        # concurrency and flagging a perfectly healthy server as strained
        st = self._state(100)
        st.track_latency(time.time() - 45)
        self.assertEqual(st.current_concurrency, 100)
        self.assertFalse(st.server_strained)
        self.assertEqual(st.baseline_time, 0.0)
        self.assertGreater(st.last_phase_duration, 40)

    def test_baseline_is_median_not_first_sample(self):
        st = self._state()
        st.track_request_latency(0.5)          # outlier as the very first sample
        for _ in range(15):
            st.track_request_latency(0.1)
        self.assertAlmostEqual(st.baseline_time, 0.1, places=3)

    def test_no_decision_before_warmup_and_bad_samples_ignored(self):
        st = self._state(100)
        for _ in range(15):
            st.track_request_latency(0.1)
        self.assertEqual(st.baseline_time, 0.0)
        self.assertEqual(st.current_concurrency, 100)
        st.track_request_latency(0)
        st.track_request_latency(-1)
        self.assertEqual(len(st.latency_window), 15)

    def test_slow_period_throttles_stepwise_not_endlessly(self):
        st = self._state(100)
        for _ in range(16):
            st.track_request_latency(0.1)          # baseline locked at 0.1
        self.assertAlmostEqual(st.baseline_time, 0.1, places=3)

        for _ in range(3):                         # samples 17-19: no tick yet
            st.track_request_latency(1.0)
        self.assertEqual(st.current_concurrency, 100)
        self.assertFalse(st.server_strained)

        for _ in range(5):                         # sample 24 → first tick
            st.track_request_latency(1.0)
        self.assertEqual(st.current_concurrency, 50)
        self.assertTrue(st.server_strained)
        self.assertAlmostEqual(st.baseline_time, 0.1, places=3)   # not re-armed

        for _ in range(8):                         # sample 32 → second tick
            st.track_request_latency(1.0)
        self.assertEqual(st.current_concurrency, 25)
        self.assertAlmostEqual(st.baseline_time, 1.0, places=3)   # confirmed

        for _ in range(16):                        # samples 33-48: stable slow
            st.track_request_latency(1.0)
        self.assertEqual(st.current_concurrency, 25)   # no endless halving
        self.assertFalse(st.server_strained)

    def test_recovery_lets_baseline_follow_improvement(self):
        st = self._state(100)
        for _ in range(16):
            st.track_request_latency(0.1)
        for _ in range(32):                        # strain → re-arm to 1.0
            st.track_request_latency(1.0)
        self.assertAlmostEqual(st.baseline_time, 1.0, places=3)
        for _ in range(64):                        # server recovers
            st.track_request_latency(0.1)
        self.assertLess(st.baseline_time, 0.6)
        self.assertFalse(st.server_strained)

    def test_start_wave_escalation_is_earned(self):
        st = self._state(100)
        st.start_wave()                            # wave 2, healthy → +50
        self.assertEqual(st.current_concurrency, 150)

        st.server_strained = True
        st.start_wave()
        self.assertEqual(st.current_concurrency, 150)

        st.server_strained = False
        st._last_reduce_ts = time.time()           # cooldown active
        st.start_wave()
        self.assertEqual(st.current_concurrency, 150)

        st._last_reduce_ts = time.time() - 100     # cooldown elapsed
        st.start_wave()
        self.assertEqual(st.current_concurrency, 200)

        # still-slow window blocks escalation even if the flag was cleared
        slow = self._state(100)
        for _ in range(16):
            slow.track_request_latency(0.1)
        for _ in range(8):
            slow.track_request_latency(1.0)        # tick 24 → 50 + strained
        self.assertEqual(slow.current_concurrency, 50)
        slow.server_strained = False
        slow._last_reduce_ts = time.time() - 100
        slow.start_wave()
        self.assertEqual(slow.current_concurrency, 50)

        # escalation is capped
        capped = self._state(480)
        capped.start_wave()
        self.assertEqual(capped.current_concurrency, 500)


class TestLatencyObserverWiring(unittest.IsolatedAsyncioTestCase):
    async def test_observer_is_wired_during_run_and_cleared_after(self):
        from unittest.mock import patch
        engine = MagicMock()
        captured = {}

        async def recorder(state):
            captured.setdefault("state", state)
            captured.setdefault("observer", state.async_engine.latency_observer)

        with patch("modules.waf.bypass_engine.waf_bypass_pipeline",
                   new=AsyncMock(return_value={})), \
             patch("runners.poison.orchestrator._adaptive_wave_loop", recorder), \
             patch("modules.wordlists.WordlistProvider") as wl:
            wl.return_value._local = {"dir": "x"}
            wl.return_value.summary.return_value = ""
            await run_poison_assault(
                target="example.com", seed_url="https://example.com/",
                services=[{"url": "https://example.com/"}], subs=[],
                scan_urls=["https://example.com/"], scope_guard=None,
                session_manager=MagicMock(), async_engine=engine,
                is_turbo=False, max_duration=2, policy=None)

        state = captured["state"]
        wired = captured["observer"]           # captured while the run was live
        self.assertIsNone(engine.latency_observer,
                          "observer must be cleared before returning")
        self.assertIsNotNone(wired)
        self.assertIs(wired.__func__, PoisonState.track_request_latency)

    async def test_observer_callback_feeds_the_controller(self):
        state = PoisonState(target="example.com", seed_url="https://example.com/",
                            services=[], subs=[], scan_urls=["https://example.com/"],
                            scope_guard=None, session_manager=MagicMock(),
                            async_engine=MagicMock(), is_turbo=False)
        for _ in range(16):
            state.track_request_latency(0.1)
        self.assertAlmostEqual(state.baseline_time, 0.1, places=3)


class TestBackoffGate(unittest.IsolatedAsyncioTestCase):
    """429/403 backoff must also hold the generators that bypass the engine."""

    def _state(self):
        return PoisonState(target="example.com", seed_url="https://example.com/",
                           services=[{"url": "https://example.com/"}], subs=[],
                           scan_urls=["https://example.com/"], scope_guard=None,
                           session_manager=MagicMock(), async_engine=MagicMock(),
                           is_turbo=False)

    def test_limiter_reports_backoff_window(self):
        from core.host_ratelimit import HostRateLimiter
        lim = HostRateLimiter(default_max_concurrent=5)
        self.assertFalse(lim.is_backing_off("example.com"))   # unknown host

        lim._get_or_create("example.com")
        self.assertFalse(lim.is_backing_off("example.com"))   # no incident yet
        lim.release("example.com", 429)                       # rate limited
        self.assertTrue(lim.is_backing_off("example.com"))
        # window expires
        st = lim._hosts["example.com"]
        st.backoff_until = time.time() - 1
        self.assertFalse(lim.is_backing_off("example.com"))

    def test_helper_never_false_positives_on_mock_engines(self):
        state = self._state()          # engine is a bare MagicMock
        self.assertFalse(_hold_for_backoff(state, "x"))
        self.assertEqual(state._backoff_notice_wave, -1)

    async def test_bruteforce_holds_and_notices_once(self):
        from core.host_ratelimit import HostRateLimiter
        from unittest.mock import patch

        state = self._state()
        lim = HostRateLimiter(default_max_concurrent=5)
        lim._get_or_create("example.com")
        lim.release("example.com", 429)
        state.async_engine = MagicMock()
        state.async_engine.host_limiter = lim

        with patch("runners.poison.flood._run_ffuf", new=AsyncMock(return_value=[])) as ffuf:
            await phase_bruteforce(state)
            await phase_bruteforce(state)

        ffuf.assert_not_called()        # ffuf never dispatched during backoff
        self.assertEqual(state._backoff_notice_wave, state.wave)   # logged once/wave

        # backoff expired → generator runs again
        lim._hosts["example.com"].backoff_until = time.time() - 1
        with patch("runners.poison.flood._run_ffuf", new=AsyncMock(return_value=[])) as ffuf2:
            await phase_bruteforce(state)
        self.assertGreaterEqual(ffuf2.call_count, 1)


class TestBudgetAccounting(unittest.IsolatedAsyncioTestCase):
    """Generators that bypass ahttp_send must debit max_requests."""

    def _state(self, policy):
        return PoisonState(target="example.com", seed_url="https://example.com/",
                           services=[{"url": "https://example.com/"}], subs=[],
                           scan_urls=["https://example.com/"], scope_guard=None,
                           session_manager=MagicMock(), async_engine=MagicMock(),
                           is_turbo=False, policy=policy)

    def test_charge_is_exact_and_clamped(self):
        from core.policy import ScanPolicy
        p = ScanPolicy("example.com", max_requests=100, max_concurrency=50)
        self.assertEqual(p.charge(40, reason="ffuf:x"), 40)
        self.assertEqual(p.requests_sent, 40)
        self.assertEqual(p.charge(90, reason="ffuf:x"), 60)   # clamped to room
        self.assertEqual(p.requests_sent, 100)
        self.assertEqual(p.charge(10, reason="ffuf:x"), 0)    # empty budget
        unlimited = ScanPolicy("example.com", max_requests=None)
        self.assertEqual(unlimited.charge(5000, reason="x"), 5000)

    def test_run_ffuf_debits_and_truncates_to_budget(self):
        from core.policy import ScanPolicy
        from unittest.mock import patch
        p = ScanPolicy("example.com", max_requests=120, max_concurrency=50)
        words = [f"w{i}" for i in range(1000)]
        with patch("runners.poison.flood._find_tool", return_value="/usr/bin/true"):
            out = asyncio.run(_run_ffuf("https://example.com/", words, "",
                                        10, timeout=5, policy=p))
        # 120 room - 10 calibration allowance = 110 words, charge 110+10
        self.assertEqual(p.requests_sent, 120)
        self.assertEqual(out, [])

    def test_run_ffuf_charges_nothing_below_overhead(self):
        from core.policy import ScanPolicy
        from unittest.mock import patch
        p = ScanPolicy("example.com", max_requests=5, max_concurrency=50)
        with patch("runners.poison.flood._find_tool", return_value="/usr/bin/true"):
            out = asyncio.run(_run_ffuf("https://example.com/", ["a"] * 50,
                                        "", 10, timeout=5, policy=p))
        self.assertEqual(out, [])
        self.assertEqual(p.requests_sent, 0)

    async def test_exhaust_blocked_when_budget_cannot_cover_sockets(self):
        from core.policy import ScanPolicy
        from unittest.mock import patch
        p = ScanPolicy("example.com", max_requests=700, max_concurrency=50)
        state = self._state(p)
        with patch("modules.web.server_side.connection_exhaust.ConnectionExhaust.run",
                   new=AsyncMock(return_value={})) as run_mock:
            await phase_connection_exhaust(state)
        run_mock.assert_not_called()
        self.assertEqual(p.requests_sent, 0)

    async def test_exhaust_debits_750_when_it_runs(self):
        from core.policy import ScanPolicy
        from unittest.mock import patch
        p = ScanPolicy("example.com", max_requests=5000, max_concurrency=50)
        state = self._state(p)
        with patch("modules.web.server_side.connection_exhaust.ConnectionExhaust.run",
                   new=AsyncMock(return_value={})) as run_mock:
            await phase_connection_exhaust(state)
        run_mock.assert_called_once()
        self.assertEqual(p.requests_sent, 750)

    def test_smuggle_bound_is_documented_not_invented(self):
        from modules.web.server_side.smuggling import SMUGGLE_REQUEST_BOUND, TE_TE_OBFUSCATIONS
        self.assertEqual(SMUGGLE_REQUEST_BOUND, 6 + 2 * len(TE_TE_OBFUSCATIONS) + 8)
        self.assertGreater(SMUGGLE_REQUEST_BOUND, 10)

    def test_uncounted_tool_is_gated_not_debited(self):
        from core.policy import ScanPolicy
        from core.external_tools import (_uncounted_tool_allowed,
                                         UNCOUNTED_TOOL_FLOOR, run_dalfox)
        p = ScanPolicy("example.com", max_requests=UNCOUNTED_TOOL_FLOOR - 1,
                       max_concurrency=50)
        self.assertFalse(_uncounted_tool_allowed(p, "dalfox"))
        self.assertTrue(_uncounted_tool_allowed(None, "dalfox"))
        # gate fires before any subprocess is spawned
        self.assertEqual(run_dalfox(["https://example.com/?q=1"], policy=p), [])
        self.assertEqual(p.requests_sent, 0)


class TestPostPayloadPass(unittest.IsolatedAsyncioTestCase):
    """GET-only flood misses reflected sinks in form bodies."""

    def _state(self):
        st = PoisonState(target="example.com", seed_url="https://example.com/",
                         services=[{"url": "https://example.com/"}], subs=[],
                         scan_urls=["https://example.com/search"],
                         scope_guard=None, session_manager=MagicMock(),
                         async_engine=MagicMock(), is_turbo=False)
        st.max_duration = 600
        st.params = {"/search": ["q"]}
        return st

    async def test_reflector_is_fuzzed_and_detected(self):
        from modules.scanners.scanner import SmartPayloadGenerator
        from urllib.parse import parse_qs
        state = self._state()
        post_bodies = []

        async def fake(url, method="GET", data=None, headers=None, **kw):
            if method != "POST":
                return {"status": 200, "body": "", "headers": {}, "waf": []}
            post_bodies.append(data)
            if len(post_bodies) == 1:
                value = parse_qs(data)["q"][0]
                return {"status": 200, "body": f"echo {value}",
                        "headers": {}, "waf": ["cloudflare"]}
            return {"status": 200,
                    "body": 'echo <img src=x onerror=alert(1)>',
                    "headers": {}, "waf": ["cloudflare"]}

        state.async_engine.ahttp_send = fake
        found = await _post_payload_pass(
            state, ["https://example.com/search"], ["xss"], False,
            SmartPayloadGenerator.generate)

        # 1 canary + 1 param x 1 type x 3 payloads (test uses ["xss"] only)
        self.assertEqual(len(post_bodies), 4)
        self.assertGreaterEqual(found, 1)
        hits = [f for f in state.findings if f["detail"].startswith("POST q |")]
        self.assertTrue(hits, "POST finding must be labelled with its method/param")
        self.assertEqual(hits[0]["waf"], "cloudflare")

    async def test_non_reflector_costs_one_request_only(self):
        from modules.scanners.scanner import SmartPayloadGenerator
        state = self._state()
        calls = []

        async def fake(url, method="GET", **kw):
            if method == "POST":
                calls.append(url)
                return {"status": 200, "body": "nothing echoed",
                        "headers": {}, "waf": []}
            return {"status": 200, "body": "", "headers": {}, "waf": []}

        state.async_engine.ahttp_send = fake
        found = await _post_payload_pass(
            state, ["https://example.com/search"], ["xss"], False,
            SmartPayloadGenerator.generate)
        self.assertEqual(len(calls), 1)      # canary only, no fuzzing
        self.assertEqual(found, 0)

    async def test_method_not_allowed_is_skipped(self):
        from modules.scanners.scanner import SmartPayloadGenerator
        state = self._state()
        calls = []

        async def fake(url, method="GET", **kw):
            if method == "POST":
                calls.append(url)
                return {"status": 405, "body": "", "headers": {}, "waf": []}
            return {"status": 200, "body": "", "headers": {}, "waf": []}

        state.async_engine.ahttp_send = fake
        found = await _post_payload_pass(
            state, ["https://example.com/search"], ["xss"], False,
            SmartPayloadGenerator.generate)
        self.assertEqual(len(calls), 1)
        self.assertEqual(found, 0)


class TestPayloadFloodBaselineGuard(unittest.IsolatedAsyncioTestCase):
    """Regression (2026-10-05): empty baselines must never make the guarded
    markers fire. The wave tail (5-10s left) reuses the per-URL cache
    instead of blanking it; URLs with no baseline at all are skipped."""

    def _state(self, time_left: float) -> PoisonState:
        st = PoisonState(
            target="example.com", seed_url="https://example.com/page",
            services=[], subs=[], scan_urls=["https://example.com/page"],
            scope_guard=None, session_manager=MagicMock(),
            async_engine=MagicMock(), is_turbo=False,
        )
        # time_left is a property: max_duration - elapsed
        st.start_time = time.time() - (st.max_duration - time_left)
        st.params = {"/page": ["q"]}
        return st

    async def test_no_baseline_no_cache_never_fires(self):
        st = self._state(time_left=7.0)  # inside the old FP window (5-10s)
        st.async_engine.ahttp_send = AsyncMock(
            return_value={"status": 200, "headers": {}, "waf": [],
                          "body": "Order 49 confirmed"})
        await phase_payload_flood(st)
        self.assertEqual(
            st.findings, [],
            "marker matched with no baseline -> must be skipped, not reported")

    async def test_cached_baseline_keeps_detection_alive(self):
        st = self._state(time_left=7.0)
        st._url_baselines = {"https://example.com/page": "static index page"}
        st.async_engine.ahttp_send = AsyncMock(
            return_value={"status": 200, "headers": {}, "waf": [],
                          "body": "value: 49"})
        await phase_payload_flood(st)
        self.assertTrue(
            any(f["type"] == "ssti" for f in st.findings),
            "a cached baseline must keep tail detection working")


class TestSSRFAutoChainParam(unittest.IsolatedAsyncioTestCase):
    """N1 regression (bedah 2026-10-14).

    OOB finding detail format is 'Param: x, Intercepted via <domain>' —
    the old split("|") kept the whole suffix, so SSRFScanner._inject got
    ``x, Intercepted via ...`` as the param name, never matched a query
    key, and the auto-chain silently probed garbage forever.
    """

    OOB_DETAIL = "Param: next, Intercepted via x9k2.oast.pro"

    def test_parse_oob_detail_format(self):
        self.assertEqual(_parse_finding_param(self.OOB_DETAIL), "next")

    def test_parse_flood_detail_format(self):
        self.assertEqual(
            _parse_finding_param("Param: id | Error: mysql syntax"), "id")

    def test_parse_missing_param_returns_empty(self):
        self.assertEqual(_parse_finding_param("Header: X — reflected"), "")
        self.assertEqual(_parse_finding_param(""), "")
        self.assertEqual(_parse_finding_param(None), "")

    async def test_phase_oob_passes_clean_param_to_scanner(self):
        import modules.extras.oob_detector as oob_mod
        import modules.web.server_side.ssrf_scanner as ssrf_mod

        captured = []

        class FakeOOB:
            def __init__(self, *a, **kw):
                self.interactsh = type("D", (), {"domain": ""})()

            async def run(self):
                return [
                    {   # old-format finding: no structured "param" key
                        "type": "blind_ssrf",
                        "title": "Blind SSRF (OOB Confirmed)",
                        "url": "https://target.example/view",
                        "detail": self_oob_detail,
                    },
                    {   # structured field present, detail WITHOUT "Param:"
                        "type": "blind_ssrf",
                        "title": "Blind SSRF (OOB Confirmed)",
                        "url": "https://target.example/view",
                        "param": "uid",
                        "detail": "Intercepted via x9k2.oast.pro",
                    },
                ]

        self_oob_detail = self.OOB_DETAIL

        class FakeScanner:
            def __init__(self, *a, **kw):
                pass

            async def scan(self, url, param):
                captured.append((url, param))
                return []

        state = PoisonState(
            target="target.example",
            seed_url="https://target.example",
            services=[{"url": "https://target.example"}],
            subs=[],
            scan_urls=["https://target.example/"],
            scope_guard=None,
            session_manager=MagicMock(),
            async_engine=MagicMock(),
            is_turbo=False,
        )
        state.params = {"view": ["next", "uid"]}

        with patch.object(oob_mod, "OOBDetector", FakeOOB), \
                patch.object(ssrf_mod, "SSRFScanner", FakeScanner):
            await phase_oob(state)

        self.assertEqual(
            captured,
            [("https://target.example/view", "next"),
             ("https://target.example/view", "uid")],
            "SSRFScanner must receive the bare param name, never the "
            "'..., Intercepted via ...' suffix")

    async def test_ssrp_scan_deduped_across_waves(self):
        import modules.extras.oob_detector as oob_mod
        import modules.web.server_side.ssrf_scanner as ssrf_mod

        calls = []

        class FakeOOB:
            def __init__(self, *a, **kw):
                self.interactsh = type("D", (), {"domain": ""})()

            async def run(self):
                # Fresh marker every wave -> a fresh finding object each call
                return [{"type": "blind_ssrf",
                         "url": "https://target.example/view",
                         "param": "next",
                         "detail": "Param: next, Intercepted via x.oast.pro"}]

        class FakeScanner:
            def __init__(self, *a, **kw):
                pass

            async def scan(self, url, param):
                calls.append((url, param))
                return []

        state = PoisonState(
            target="target.example",
            seed_url="https://target.example",
            services=[{"url": "https://target.example"}],
            subs=[],
            scan_urls=["https://target.example/"],
            scope_guard=None,
            session_manager=MagicMock(),
            async_engine=MagicMock(),
            is_turbo=False,
        )
        state.params = {"view": ["next"]}

        with patch.object(oob_mod, "OOBDetector", FakeOOB), \
                patch.object(ssrf_mod, "SSRFScanner", FakeScanner):
            await phase_oob(state)   # wave 1
            state.wave += 1
            await phase_oob(state)   # wave 2 — same (url, param)

        self.assertEqual(
            len(calls), 1,
            "second wave must not re-run the whole SSRF probe series")


class TestExhaustClassification(unittest.TestCase):
    """N2 regression (bedah 2026-10-14): the refused bucket must hold only
    hard ECONNREFUSED — TimeoutError and generic OSError (proxy/DNS) were
    counted as "refused" and reported confidence "confirmed" (FP)."""

    @staticmethod
    def _results(refused=0, timeouts=0, errors=0, attempted=250, total_time=30.0):
        # Signal counts live in slowloris only; attempted is spread over the
        # 3 modes (3 x 250 = 750 aggregate) so totals read naturally.
        slow = {"attempted": attempted, "opened": 0, "refused": refused,
                "timeouts": timeouts, "errors": errors}
        pool = {"attempted": attempted, "completed": 0, "refused": 0,
                "timeouts": 0, "errors": 0}
        chunk = {"attempted": attempted, "opened": 0, "refused": 0,
                 "timeouts": 0, "errors": 0}
        return {"slowloris": slow, "pool_flood": pool, "chunked_bomb": chunk,
                "total_time": total_time}

    def test_hard_refusal_is_confirmed(self):
        f = _exhaust_finding(self._results(refused=51), "https://x.example/")
        assert f is not None
        self.assertEqual(f["confidence"], "confirmed")
        self.assertEqual(f["type"], "conn_exhaust_pressure")
        # N3: denominator is attempted, not the skewed open/refused sum
        self.assertIn("51/750", f["detail"])

    def test_timeouts_only_are_suspected(self):
        f = _exhaust_finding(self._results(timeouts=51), "https://x.example/")
        assert f is not None
        self.assertEqual(f["confidence"], "suspected")
        self.assertEqual(f["type"], "conn_exhaust_timeout")
        self.assertIn("not proven", f["detail"])

    def test_no_signal_no_finding(self):
        self.assertIsNone(_exhaust_finding(self._results(timeouts=10, refused=5), "u"))
        self.assertIsNone(_exhaust_finding({"total_time": 0}, "u"))
        self.assertIsNone(_exhaust_finding({}, "u"))

    def test_old_results_shape_without_timeouts_key(self):
        r = self._results(refused=51)
        for m in ("slowloris", "pool_flood", "chunked_bomb"):
            del r[m]["timeouts"]
        f = _exhaust_finding(r, "u")
        assert f is not None
        self.assertEqual(f["confidence"], "confirmed")

    def test_counter_split_by_exception_class(self):
        from modules.web.server_side.connection_exhaust import ConnectionExhaust

        async def run_one(exc):
            ex = ConnectionExhaust("https://example.com", timeout=30)

            async def boom():
                raise exc
            ex._open_connection = boom
            await ex._slowloris_async(1)
            return ex.results["slowloris"]

        for exc, bucket in [
            (ConnectionRefusedError(), "refused"),
            (TimeoutError(), "timeouts"),
            (OSError("socks proxy dead"), "errors"),  # old code: counted as refused
        ]:
            r = asyncio.run(run_one(exc))
            self.assertEqual(r[bucket], 1,
                             f"{type(exc).__name__} must land in {bucket}")
            for other in ({"refused", "timeouts", "errors"} - {bucket}):
                self.assertEqual(r[other], 0,
                                 f"{type(exc).__name__} leaked into {other}")


class TestK5RedirectPass(unittest.IsolatedAsyncioTestCase):
    """K5 (2026-10-14): main -fc 404,301,302 dropped redirect-only routes.
    Empiris: demo.testfire.net /admin is 3xx-only and was missed; a separate
    -mc 301,302,303,307,308 pass finds it, with -ac killing catch-all noise."""

    async def test_run_ffuf_flag_construction(self):
        captured = {}

        class FakeProc:
            async def communicate(self):
                return (b"", b"")

            def kill(self):
                pass

            async def wait(self):
                pass

        async def fake_exec(*args, **kw):
            captured.setdefault("runs", []).append(args)
            return FakeProc()

        with patch("runners.poison.flood._find_tool",
                   return_value="/usr/bin/ffuf"), \
                patch("runners.poison.flood.asyncio.create_subprocess_exec",
                      side_effect=fake_exec):
            await _run_ffuf("https://example.com/", ["a"] * 5, "", 10)
            await _run_ffuf("https://example.com/", ["a"] * 5, "", 10,
                            match_codes="301,302,303,307,308",
                            filter_codes="404")
        main, redir = captured["runs"]
        self.assertNotIn("-mc", main)          # main pass byte-identical
        self.assertEqual(main[main.index("-fc") + 1], "404,301,302")
        self.assertEqual(redir[redir.index("-mc") + 1], "301,302,303,307,308")
        self.assertEqual(redir[redir.index("-fc") + 1], "404")

    async def test_phase_bruteforce_dispatches_3xx_pass(self):
        state = PoisonState(
            target="example.com", seed_url="https://example.com",
            services=[{"url": "https://example.com"}], subs=[],
            scan_urls=["https://example.com/"], scope_guard=None,
            session_manager=MagicMock(), async_engine=MagicMock(),
            is_turbo=False)
        with patch("runners.poison.flood._run_ffuf",
                   new=AsyncMock(return_value=[])) as ffuf:
            await phase_bruteforce(state)
        kws = [c.kwargs for c in ffuf.call_args_list]
        self.assertTrue(
            any(k.get("match_codes") == "301,302,303,307,308" for k in kws),
            f"3xx pass missing from phase_bruteforce calls: {kws}")


class TestObserverCleanup(unittest.IsolatedAsyncioTestCase):
    """N6 (2026-10-14): latency_observer must not outlive the run when an
    unexpected exception escapes the wave loop."""

    async def test_observer_cleared_on_unexpected_exception(self):
        import runners.poison.orchestrator as orch
        engine = MagicMock()   # hasattr(engine, "latency_observer") == True

        async def fake_loop(state):
            raise RuntimeError("boom")

        with patch.object(orch, "WordlistProvider") as WProv, \
                patch.object(orch, "_adaptive_wave_loop", new=fake_loop), \
                patch("modules.waf.bypass_engine.waf_bypass_pipeline",
                      new=AsyncMock(return_value={})):
            WProv.return_value._local = True
            with self.assertRaises(RuntimeError):
                await run_poison_assault(
                    "example.com", "https://example.com",
                    [], [], ["https://example.com/"], None,
                    MagicMock(), engine, max_duration=5)

        self.assertIsNone(engine.latency_observer,
                          "observer leaked past an unexpected exception")


class TestSSRFScanParallel(unittest.TestCase):
    """N7: cloud probes must gather, not walk the list one-by-one."""

    def test_cloud_probes_gather_not_sequential(self):
        import time as _time
        from modules.web.server_side.ssrf_scanner import SSRFScanner

        scanner = SSRFScanner(MagicMock())

        async def slow_probe(url, param, target, timeout=5):
            await asyncio.sleep(0.15)
            return {"status": 404, "headers": {}, "body": "", "time": 0.15}

        scanner._send_probe = slow_probe
        t0 = _time.monotonic()
        out = asyncio.run(scanner.scan_cloud_metadata("https://t.example/", "q"))
        wall = _time.monotonic() - t0
        # Sequential: baseline + 9 probes = 10 x 0.15 = 1.5s+;
        # parallel: baseline + slowest probe ~0.3-0.6s.
        self.assertLess(wall, 1.0)
        self.assertEqual(out, [])


class TestSensitiveFileVerifier(unittest.IsolatedAsyncioTestCase):
    """Package 1 (bedah 2026-10-14): ffuf sensitive-file discoveries must
    become verified findings — body evidence required, soft-404-proof."""

    SOFT404 = ("<html><head><title>Welcome to nginx!</title></head>"
               "<body><center>404 custom page</center></body></html>")

    @staticmethod
    def _resp(status=200, body="", headers=None):
        return {"status": status, "body": body, "headers": headers or {},
                "waf": [], "time": 0.1}

    @staticmethod
    def _state():
        return PoisonState(
            target="t.example", seed_url="https://t.example",
            services=[{"url": "https://t.example"}], subs=[],
            scan_urls=["https://t.example/"], scope_guard=None,
            session_manager=MagicMock(), async_engine=MagicMock(),
            is_turbo=False)

    @staticmethod
    def _engine(pages):
        """Exact-URL pages; every other path answers the soft-404 page."""
        calls = []

        async def ahttp_send(url, timeout=5, state_context=None, **kw):
            calls.append(url)
            return dict(pages.get(
                url, TestSensitiveFileVerifier._resp(
                    200, TestSensitiveFileVerifier.SOFT404)))
        eng = MagicMock()
        eng.ahttp_send = ahttp_send
        eng.calls = calls
        return eng

    async def test_git_head_verified(self):
        st = self._state()
        eng = self._engine({"https://t.example/.git/HEAD":
                            self._resp(200, "ref: refs/heads/main\n")})
        st.async_engine = eng
        n = await verify_sensitive_files(st, ["https://t.example/.git/HEAD"])
        self.assertEqual(n, 1)
        self.assertEqual(st.findings[0]["type"], "git_exposure")
        self.assertEqual(st.findings[0]["confidence"], "confirmed")
        self.assertIn("ref: refs/heads", st.findings[0]["detail"])

    async def test_env_verified(self):
        env_body = "APP_KEY=base64:xxxx\nDB_PASSWORD=hunter2\nAPP_DEBUG=true\n"
        st = self._state()
        eng = self._engine({"https://t.example/.env": self._resp(200, env_body)})
        st.async_engine = eng
        await verify_sensitive_files(st, ["https://t.example/.env"])
        self.assertEqual(st.findings[0]["type"], "env_exposure")

    async def test_soft404_never_reported(self):
        st = self._state()
        eng = self._engine({})   # every path = custom 200 page
        st.async_engine = eng
        n = await verify_sensitive_files(
            st, ["https://t.example/dump.sql", "https://t.example/.env",
                 "https://t.example/wp-config.php.bak",
                 "https://t.example/files/", "https://t.example/"])
        self.assertEqual(n, 0)
        self.assertEqual(st.findings, [])

    async def test_private_key_verified(self):
        st = self._state()
        eng = self._engine({"https://t.example/.ssh/id_rsa":
                            self._resp(200, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl")})
        st.async_engine = eng
        await verify_sensitive_files(st, ["https://t.example/.ssh/id_rsa"])
        self.assertEqual(st.findings[0]["type"], "private_key_exposure")

    async def test_directory_listing_verified(self):
        listing = ("<html><head><title>Index of /files</title></head>"
                   "<a href=\"backup.zip\">backup.zip</a></html>")
        st = self._state()
        eng = self._engine({"https://t.example/files/": self._resp(200, listing)})
        st.async_engine = eng
        await verify_sensitive_files(st, ["https://t.example/files/"])
        self.assertEqual(st.findings[0]["type"], "directory_listing")
        self.assertEqual(st.findings[0]["confidence"], "confirmed")

    async def test_redirect_slash_retry(self):
        listing = "<title>Index of /backup/</title><a href=\"x\">x</a>"
        st = self._state()
        eng = self._engine({
            "https://t.example/backup":
                self._resp(301, "", {"Location": "/backup/"}),
            "https://t.example/backup/": self._resp(200, listing)})
        st.async_engine = eng
        n = await verify_sensitive_files(st, ["https://t.example/backup"])
        self.assertEqual(n, 1)
        self.assertIn("https://t.example/backup/", eng.calls)
        # slash-form marked: if ffuf also found it, no double report
        self.assertIn("https://t.example/backup/", st._verified_paths)

    async def test_archive_size_only_suspected(self):
        st = self._state()
        big = "PK\x03\x04fakezip" + "A" * 25000
        eng = self._engine({"https://t.example/site-backup.zip":
                            self._resp(200, big)})
        st.async_engine = eng
        await verify_sensitive_files(st, ["https://t.example/site-backup.zip"])
        self.assertEqual(st.findings[0]["type"], "backup_archive")
        self.assertEqual(st.findings[0]["confidence"], "suspected")

    async def test_verify_cap_bounded(self):
        import runners.poison.flood as flood_mod
        urls = [f"https://t.example/f{i}.sql" for i in range(10)]
        pages = {u: self._resp(200, "CREATE TABLE t (id int);") for u in urls[:3]}
        st = self._state()
        eng = self._engine(pages)
        st.async_engine = eng
        with patch.object(flood_mod, "MAX_SENSITIVE_VERIFY", 3):
            n = await verify_sensitive_files(st, urls)
        self.assertEqual(n, 3)
        self.assertEqual(len(eng.calls), 4)   # 1 baseline + 3 verifies

    async def test_budget_exhausted_sends_nothing(self):
        from core.policy import ScanPolicy
        pol = ScanPolicy("t.example", max_requests=2, max_concurrency=10)
        pol.charge(2, reason="test")
        st = self._state()
        eng = self._engine({})
        st.async_engine = eng
        st.policy = pol
        n = await verify_sensitive_files(st, ["https://t.example/.env"])
        self.assertEqual(n, 0)
        self.assertEqual(eng.calls, [])

    async def test_verified_urls_not_rechecked_next_wave(self):
        st = self._state()
        eng = self._engine({"https://t.example/.env":
                            self._resp(200, "A=1\nB=2\n")})
        st.async_engine = eng
        await verify_sensitive_files(st, ["https://t.example/.env"])
        calls_after_wave1 = len(eng.calls)
        n2 = await verify_sensitive_files(st, ["https://t.example/.env"])
        self.assertEqual(n2, 0)
        self.assertEqual(len(eng.calls), calls_after_wave1)

    async def test_extension_urls_cost_zero_requests(self):
        st = self._state()
        eng = self._engine({})
        st.async_engine = eng
        n = await verify_sensitive_files(
            st, ["https://t.example/index.html", "https://t.example/a.bak~"])
        self.assertEqual(n, 0)
        self.assertEqual(eng.calls, [])

    async def test_phase_bruteforce_reports_sensitive_hits(self):
        st = self._state()
        eng = self._engine({"https://t.example/.git/HEAD":
                            self._resp(200, "ref: refs/heads/master\n")})
        st.async_engine = eng
        with patch("runners.poison.flood._run_ffuf",
                   new=AsyncMock(return_value=["https://t.example/.git/HEAD"])):
            await phase_bruteforce(st)
        types = [f["type"] for f in st.findings]
        self.assertIn("git_exposure", types)


class TestLoginFormBrute(unittest.IsolatedAsyncioTestCase):
    """Package 2 (bedah 2026-10-14): brute the REAL parsed form — field
    names, hidden-token replay, action URL, cap, token refresh. The old
    hard-coded username/password block produced zero signal on user/pass
    and ASP.NET forms."""

    FORM_PHP = ("<html><body><form action=\"/do_login\" method=\"post\">"
                "<input type=\"hidden\" name=\"csrf_token\" value=\"tok123\">"
                "<input type=\"text\" name=\"user\">"
                "<input type=\"password\" name=\"pass\">"
                "<input type=\"submit\" value=\"Login\">"
                "</form></body></html>")

    FORM_ASPX = ("<html><body><form action=\"/login.aspx\" method=\"post\">"
                 "<input type=\"hidden\" name=\"__VIEWSTATE\" value=\"VSBLOB\">"
                 "<input type=\"hidden\" name=\"__EVENTVALIDATION\" value=\"EV\">"
                 "<input id=\"txtUser\" name=\"txtUser\" type=\"text\">"
                 "<input id=\"txtpwd\" name=\"txtpwd\" type=\"password\">"
                 "</form></body></html>")

    FORM_EMAIL = ("<form method=\"post\">"
                  "<input type=\"email\" name=\"email\">"
                  "<input type=\"password\" name=\"password\">"
                  "</form>")

    @staticmethod
    def _resp(status=200, body="", headers=None):
        return {"status": status, "body": body, "headers": headers or {},
                "waf": [], "time": 0.1}

    def _state(self):
        return PoisonState(
            target="t.example", seed_url="https://t.example",
            services=[{"url": "https://t.example"}], subs=[],
            scan_urls=["https://t.example/login"], scope_guard=None,
            session_manager=MagicMock(), async_engine=MagicMock(),
            is_turbo=False)

    @staticmethod
    def _engine(handler):
        """handler(url, method, data) -> response dict."""
        calls = []

        async def ahttp_send(url, method="GET", headers=None, data=None,
                             timeout=5, state_context=None, **kw):
            calls.append((url, method, data))
            return handler(url, method, data)
        eng = MagicMock()
        eng.ahttp_send = ahttp_send
        eng.calls = calls
        return eng

    async def test_parser_extracts_php_form(self):
        st = self._state()
        st.async_engine = self._engine(
            lambda u, m, d: self._resp(200, self.FORM_PHP))
        form = await _fetch_login_form(st, "https://t.example/login")
        self.assertEqual(form["action"], "https://t.example/do_login")
        self.assertEqual(form["method"], "POST")
        self.assertEqual(form["user_field"], "user")
        self.assertEqual(form["pass_field"], "pass")
        self.assertEqual(form["hidden"], {"csrf_token": "tok123"})

    async def test_parser_aspx_fields_and_hidden(self):
        st = self._state()
        st.async_engine = self._engine(
            lambda u, m, d: self._resp(200, self.FORM_ASPX))
        form = await _fetch_login_form(st, "https://t.example/login")
        self.assertEqual(form["user_field"], "txtUser")
        self.assertEqual(form["pass_field"], "txtpwd")
        self.assertEqual(form["hidden"]["__VIEWSTATE"], "VSBLOB")

    async def test_email_field_is_user_field(self):
        st = self._state()
        st.async_engine = self._engine(
            lambda u, m, d: self._resp(200, self.FORM_EMAIL))
        form = await _fetch_login_form(st, "https://t.example/login")
        self.assertEqual(form["user_field"], "email")

    async def test_true_positive_via_real_fields(self):
        from urllib.parse import parse_qs
        st = self._state()

        def handler(url, method, data):
            if method == "GET":
                return self._resp(200, self.FORM_PHP)
            fields = parse_qs(data or "")
            if fields.get("user") == ["admin"] and fields.get("pass") == ["admin123"]:
                return self._resp(302, "", {"Location": "/dashboard"})
            return self._resp(200, "invalid credentials")

        st.async_engine = self._engine(handler)
        await _brute_login_form(st, "https://t.example/login")
        self.assertEqual(st.findings[0]["type"], "weak_credentials")
        self.assertEqual(st.findings[0]["confidence"], "confirmed")
        self.assertIn("form user/pass", st.findings[0]["detail"])
        self.assertEqual(
            st.session_cookies["https://t.example/login"]["password"],
            "admin123")

    async def test_false_positive_guard_identical_redirect(self):
        from urllib.parse import parse_qs
        st = self._state()

        def handler(url, method, data):
            if method == "GET":
                return self._resp(200, self.FORM_PHP)
            fields = parse_qs(data or "")
            # identical redirect for baseline AND every cred — classic FP trap
            if fields.get("user") == ["admin"]:
                return self._resp(302, "", {"Location": "/login?e=1"})
            return self._resp(302, "", {"Location": "/login?e=1"})

        st.async_engine = self._engine(handler)
        await _brute_login_form(st, "https://t.example/login")
        self.assertEqual(st.findings, [])

    async def test_aspx_viewstate_replayed(self):
        import runners.poison.flood as flood_mod
        from urllib.parse import parse_qs
        st = self._state()
        posts = []

        def handler(url, method, data):
            if method == "GET":
                return self._resp(200, self.FORM_ASPX)
            posts.append(parse_qs(data or ""))
            return self._resp(200, "login failed")

        st.async_engine = self._engine(handler)
        with patch.object(flood_mod, "MAX_LOGIN_ATTEMPTS", 2):
            await _brute_login_form(st, "https://t.example/login")
        self.assertTrue(posts)
        for fields in posts:
            self.assertEqual(fields["__VIEWSTATE"], ["VSBLOB"])
            self.assertEqual(fields["__EVENTVALIDATION"], ["EV"])
            self.assertIn("txtUser", fields)

    async def test_cap_bounds_attempts(self):
        import runners.poison.flood as flood_mod
        from urllib.parse import parse_qs
        st = self._state()
        posts = []

        def handler(url, method, data):
            if method == "GET":
                return self._resp(200, self.FORM_EMAIL)
            posts.append(parse_qs(data or ""))
            return self._resp(200, "invalid")

        st.async_engine = self._engine(handler)
        with patch.object(flood_mod, "MAX_LOGIN_ATTEMPTS", 5):
            await _brute_login_form(st, "https://t.example/login")
        # cap 5: baseline + 5 attempts; GET = 1 form fetch (email form: no token)
        self.assertEqual(len(posts), 6)
        gets = [c for c in st.async_engine.calls if c[1] == "GET"]
        self.assertEqual(len(gets), 1)

    async def test_token_refresh_every_n(self):
        import runners.poison.flood as flood_mod
        st = self._state()

        def handler(url, method, data):
            if method == "GET":
                return self._resp(200, self.FORM_PHP)
            return self._resp(200, "invalid")

        st.async_engine = self._engine(handler)
        with patch.object(flood_mod, "MAX_LOGIN_ATTEMPTS", 6), \
                patch.object(flood_mod, "TOKEN_REFRESH_EVERY", 3):
            await _brute_login_form(st, "https://t.example/login")
        gets = [c for c in st.async_engine.calls if c[1] == "GET"]
        # initial fetch + refresh at attempts==3 (cap hits before attempts==6 refresh)
        self.assertEqual(len(gets), 2)

    async def test_get_method_form_uses_query(self):
        form_get = ("<form method=\"get\">"
                    "<input type=\"text\" name=\"u\">"
                    "<input type=\"password\" name=\"p\">"
                    "</form>")
        st = self._state()

        def handler(url, method, data):
            if method == "GET":
                return self._resp(200, form_get)
            return self._resp(200, "invalid")

        st.async_engine = self._engine(handler)
        import runners.poison.flood as flood_mod
        with patch.object(flood_mod, "MAX_LOGIN_ATTEMPTS", 1):
            await _brute_login_form(st, "https://t.example/login")
        queries = [c[0] for c in st.async_engine.calls
                   if c[0].startswith("https://t.example/login?")]
        self.assertTrue(queries, "GET form must send creds via query string")
        self.assertIn("u=___nonexistent___", queries[0])

    async def test_no_form_single_fetch_only(self):
        st = self._state()
        st.async_engine = self._engine(
            lambda u, m, d: self._resp(200, "<html>nothing here</html>"))
        await _brute_login_form(st, "https://t.example/login")
        self.assertEqual(len(st.async_engine.calls), 1)   # fetch, no attempts

    async def test_form_fetch_follows_slash_redirect(self):
        """nginx /login -> 301 /login/ : the form lives behind the hop."""
        st = self._state()

        def handler(u, m, d):
            if u == "https://t.example/login":
                return self._resp(301, "", {"Location": "/login/"})
            return self._resp(200, self.FORM_PHP)

        st.async_engine = self._engine(handler)
        form = await _fetch_login_form(st, "https://t.example/login")
        self.assertIsNotNone(form)
        self.assertEqual(form["user_field"], "user")
        self.assertEqual(form["action"], "https://t.example/do_login")

    async def test_form_fetch_refuses_off_host_redirect(self):
        st = self._state()
        st.async_engine = self._engine(
            lambda u, m, d: self._resp(
                301, "", {"Location": "https://evil.example/login/"}))
        form = await _fetch_login_form(st, "https://t.example/login")
        self.assertIsNone(form)
        self.assertEqual(len(st.async_engine.calls), 1)   # no off-host follow

    async def test_cred_list_has_extra_pairs(self):
        creds = _cred_list()
        self.assertGreater(len(creds), 60)          # 21 COMMON + 40 EXTRA
        self.assertIn(("dinas", "dinas"), creds)
        self.assertIn(("admin", "admin123"), creds)  # from COMMON_CREDS

    async def test_phase_bruteforce_dispatches_smart_brute(self):
        st = self._state()
        with patch("runners.poison.flood._run_ffuf",
                   new=AsyncMock(return_value=[])), \
                patch("runners.poison.flood._brute_login_form",
                      new=AsyncMock()) as brute:
            await phase_bruteforce(st)
        brute.assert_called_once_with(st, "https://t.example/login")


class TestP3Gating(unittest.IsolatedAsyncioTestCase):
    """Paket 3 (bedah 2026-10-14): uncap ffuf, CDN gating, budget warning,
    Phase 0 early-exit."""

    @staticmethod
    def _state(**kw):
        return PoisonState(
            target="example.com", seed_url="https://example.com",
            services=[{"url": "https://example.com"}], subs=[],
            scan_urls=["https://example.com/"], scope_guard=None,
            session_manager=MagicMock(), async_engine=MagicMock(),
            is_turbo=False, **kw)

    def test_ffuf_timeout_new_cap(self):
        st = self._state()
        st.max_duration = 500
        st.start_time = time.time()          # time_left ~500 -> capped 120
        self.assertEqual(_ffuf_timeout(st), 120)
        st.start_time = time.time() - 440    # time_left ~60 (epsilon below)
        self.assertIn(_ffuf_timeout(st), (59, 60))
        st.start_time = time.time() - 497    # time_left ~3 (epsilon below)
        self.assertIn(_ffuf_timeout(st), (2, 3))

    def test_edge_helper_case_insensitive(self):
        st = self._state()
        st.target_wafs = {"CloudFlare"}
        self.assertTrue(_edge_shields_origin(st))
        st.target_wafs = {"nginx", "headers"}
        self.assertFalse(_edge_shields_origin(st))
        st.target_wafs = set()
        self.assertFalse(_edge_shields_origin(st))

    async def test_exhaust_skipped_on_cdn(self):
        from core.policy import ScanPolicy
        p = ScanPolicy("example.com", max_requests=5000, max_concurrency=50)
        st = self._state(policy=p)
        st.target_wafs = {"cloudflare"}
        with patch("modules.web.server_side.connection_exhaust"
                   ".ConnectionExhaust.run",
                   new=AsyncMock(return_value={})) as run_mock:
            await phase_connection_exhaust(st)
        run_mock.assert_not_called()
        self.assertEqual(p.requests_sent, 0)   # no 750-socket debit either

    async def test_smuggling_skipped_on_cdn(self):
        st = self._state()
        st.target_wafs = {"Akamai"}
        with patch("modules.web.server_side.smuggling.scan_smuggling",
                   new=AsyncMock(return_value=[])) as sm:
            await phase_smuggling(st)
        sm.assert_not_called()

    async def test_exhaust_still_runs_without_cdn(self):
        st = self._state()
        st.target_wafs = set()
        with patch("modules.web.server_side.connection_exhaust"
                   ".ConnectionExhaust.run",
                   new=AsyncMock(return_value={
                       "total_time": 1.0,
                       "slowloris": {"attempted": 0, "opened": 0, "refused": 0,
                                     "timeouts": 0, "errors": 0},
                       "pool_flood": {"attempted": 0, "completed": 0, "refused": 0,
                                      "timeouts": 0, "errors": 0},
                       "chunked_bomb": {"attempted": 0, "opened": 0, "refused": 0,
                                        "timeouts": 0, "errors": 0},
                   })) as run_mock:
            await phase_connection_exhaust(st)
        run_mock.assert_called_once()

    def test_budget_warning_threshold(self):
        from core.policy import ScanPolicy
        p = ScanPolicy("example.com", max_requests=100, max_concurrency=10)
        st = self._state(policy=p)
        self.assertIsNone(_budget_warning(st))          # fresh budget: silent
        p.charge(85, reason="test")
        msg = _budget_warning(st)
        self.assertIsNotNone(msg)
        self.assertIn("Budget running low", msg)
        self.assertIn("15/100", msg)

    async def test_phase0_skipped_without_waf(self):
        import runners.poison.orchestrator as orch
        engine = MagicMock()

        async def fake_loop(state):
            pass

        pipe = AsyncMock(return_value={})
        with patch.object(orch, "WordlistProvider") as WProv, \
                patch.object(orch, "_adaptive_wave_loop", new=fake_loop), \
                patch("modules.waf.bypass_engine.waf_bypass_pipeline",
                      new=pipe):
            WProv.return_value._local = True
            await run_poison_assault(
                "example.com", "https://example.com",
                [], [], ["https://example.com/"], None,
                MagicMock(), engine, max_duration=2)
        pipe.assert_not_called()

    async def test_phase0_runs_with_waf(self):
        import runners.poison.orchestrator as orch
        engine = MagicMock()

        async def fake_loop(state):
            pass

        pipe = AsyncMock(return_value={})
        with patch.object(orch, "WordlistProvider") as WProv, \
                patch.object(orch, "_adaptive_wave_loop", new=fake_loop), \
                patch("modules.waf.bypass_engine.waf_bypass_pipeline",
                      new=pipe), \
                patch("modules.waf.origin_hunter.hunt_origin",
                      new=AsyncMock(return_value=None)):
            WProv.return_value._local = True
            await run_poison_assault(
                "example.com", "https://example.com",
                [{"url": "https://example.com", "waf": ["cloudflare"]}],
                [], ["https://example.com/"], None,
                MagicMock(), engine, max_duration=2)
        pipe.assert_called_once()


class TestP4Magazine(unittest.IsolatedAsyncioTestCase):
    """Paket 4 (bedah 2026-10-14): backup exts first, payload rotation."""

    @staticmethod
    def _state():
        return PoisonState(
            target="t.example", seed_url="https://t.example",
            services=[{"url": "https://t.example"}], subs=[],
            scan_urls=["https://t.example/"], scope_guard=None,
            session_manager=MagicMock(), async_engine=MagicMock(),
            is_turbo=False)

    def test_rot_slice_rotation_and_wrap(self):
        pl = [f"p{i}" for i in range(8)]
        self.assertEqual(_rot_slice(pl, 1), ["p0", "p1", "p2"])
        self.assertEqual(_rot_slice(pl, 2), ["p3", "p4", "p5"])
        self.assertEqual(_rot_slice(pl, 3), ["p6", "p7", "p0"])   # wraps
        self.assertEqual(_rot_slice([], 1), [])

    def test_rot_slice_covers_full_list_over_waves(self):
        pl = [f"p{i}" for i in range(10)]
        seen = set()
        for wave in range(1, 5):     # off 0,3,6,9 -> full coverage
            seen.update(_rot_slice(pl, wave))
        self.assertEqual(seen, set(pl))

    async def test_ext_pass_backup_exts_first_capped(self):
        import modules.wordlists as wl
        st = self._state()
        with patch.object(wl.PROVIDER, "get_extension_wordlist",
                          return_value=[".jpg", ".png"]), \
                patch("runners.poison.flood._run_ffuf",
                      new=AsyncMock(return_value=[])) as ffuf:
            await phase_bruteforce(st)
        exts_used = [c.args[2] for c in ffuf.call_args_list if c.args[2]]
        self.assertEqual(exts_used[:3], ["~", ".bak", ".old"])
        self.assertEqual(exts_used[-2:], [".jpg", ".png"])
        self.assertEqual(len(exts_used),
                         min(EXT_PASS_MAX, len(_BACKUP_EXTS) + 2))

    async def test_payload_flood_rotates_by_wave(self):
        import modules.scanners.scanner as scanner_mod
        st = self._state()
        st.wave = 2      # rot offset = 3 -> payloads pl3,pl4,pl5
        calls = []

        async def send(url, **kw):
            calls.append(url)
            return {"status": 200, "body": "", "headers": {}, "waf": [],
                    "time": 0.1}
        st.async_engine = MagicMock()
        st.async_engine.ahttp_send = send
        gen = lambda ptype, bypass=False: [f"pl{i}" for i in range(10)]
        with patch.object(scanner_mod.SmartPayloadGenerator, "generate",
                          staticmethod(gen)):
            await phase_payload_flood(st)
        joined = " ".join(calls)
        self.assertIn("pl3", joined)
        self.assertIn("pl5", joined)
        self.assertNotIn("pl0", joined)   # wave 1 slice must not appear


class TestIntegratedPipeline(unittest.IsolatedAsyncioTestCase):
    """Compile check (Paket 1+2 dalam satu panggilan phase_bruteforce)."""

    async def test_bruteforce_reports_files_and_creds_together(self):
        from urllib.parse import parse_qs

        FORM = ("<form action=\"/do_login\" method=\"post\">"
                "<input type=\"text\" name=\"user\">"
                "<input type=\"password\" name=\"pass\"></form>")

        async def handler(url, method="GET", headers=None, data=None, **kw):
            if "git" in url:
                return {"status": 200, "body": "ref: refs/heads/main\n",
                        "headers": {}, "waf": [], "time": 0.1}
            if url.endswith("/login"):
                return {"status": 200, "body": FORM, "headers": {},
                        "waf": [], "time": 0.1}
            if method == "POST":
                f = parse_qs(data or "")
                if f.get("user") == ["admin"] and f.get("pass") == ["admin123"]:
                    return {"status": 302, "body": "",
                            "headers": {"Location": "/dashboard"},
                            "waf": [], "time": 0.1}
                return {"status": 200, "body": "invalid",
                        "headers": {}, "waf": [], "time": 0.1}
            return {"status": 200, "body": "", "headers": {}, "waf": [],
                    "time": 0.1}

        st = PoisonState(
            target="t.example", seed_url="https://t.example",
            services=[{"url": "https://t.example"}], subs=[],
            scan_urls=["https://t.example/login"], scope_guard=None,
            session_manager=MagicMock(), async_engine=MagicMock(),
            is_turbo=False)
        st.async_engine.ahttp_send = handler
        with patch("runners.poison.flood._run_ffuf",
                   new=AsyncMock(return_value=["https://t.example/.git/HEAD"])):
            await phase_bruteforce(st)
        types = {f["type"] for f in st.findings}
        self.assertIn("git_exposure", types)          # Paket 1
        self.assertIn("weak_credentials", types)      # Paket 2
        creds = [f for f in st.findings
                 if f["type"] == "weak_credentials"][0]
        self.assertEqual(creds["confidence"], "confirmed")


if __name__ == "__main__":
    unittest.main()
