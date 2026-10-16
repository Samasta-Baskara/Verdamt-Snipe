"""Behavioral tests for the second uncovered wave.

Covers the SQLi extractor's timing/union/error/blind chains, the IDOR
mass-enumeration detector, the example JWT analyzer (weak-secret crack +
none-alg) and the custom plugin manager — all previously ~6-30%.
"""
import base64
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from modules.custom.example_jwt import JWTTokenAnalyzer
from modules.plugin import PluginManager, run_plugins
from modules.web.server_side.idor import scan_idor
from modules.web.server_side.sqli_extractor import SQLiExtractor


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _jwt(header: dict, payload: dict, secret: str) -> str:
    h, p = _b64(header), _b64(payload)
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


def _engine_with_times(times):
    """Fake engine whose ahttp_send returns time= next(times)."""
    eng = MagicMock()

    async def send(url, **kw):
        t = times.pop(0) if times else 0.1
        return {"status": 200, "body": "x" * 60, "headers": {}, "time": t}

    eng.ahttp_send = AsyncMock(side_effect=send)
    return eng


class TestSQLiCalibration(unittest.IsolatedAsyncioTestCase):
    async def test_calibration_sets_sleep_and_threshold(self):
        ex = SQLiExtractor(engine=_engine_with_times([0.5, 0.6, 0.4]))
        with patch("modules.web.server_side.sqli_extractor.asyncio.sleep",
                   new=AsyncMock()):
            await ex._calibrate_baseline("https://x.com/?id=1", "id")
        self.assertTrue(ex._calibrated)
        # avg 0.5 -> sleep = max(5, int(0.5*2+3)) = 5
        self.assertEqual(ex._sleep_duration, 5)
        # threshold = max 0.6 + 5*0.6 = 3.6
        self.assertAlmostEqual(ex._detection_threshold, 3.6, places=5)

    async def test_calibration_runs_once(self):
        eng = _engine_with_times([0.1] * 10)
        ex = SQLiExtractor(engine=eng)
        with patch("modules.web.server_side.sqli_extractor.asyncio.sleep",
                   new=AsyncMock()):
            await ex._calibrate_baseline("https://x.com/?id=1", "id")
            calls = eng.ahttp_send.await_count
            await ex._calibrate_baseline("https://x.com/?id=1", "id")
        self.assertEqual(eng.ahttp_send.await_count, calls)  # no extra pings


class TestSQLiDetectDb(unittest.IsolatedAsyncioTestCase):
    async def test_delayed_response_fingerprints_dbms(self):
        ex = SQLiExtractor(engine=None)
        ex._calibrated = True
        ex._detection_threshold = 3.0
        ex._sleep_duration = 5
        eng = _engine_with_times([10.0])  # mysql probe delays past threshold
        ex.engine = eng

        db = await ex.detect_db("https://x.com/?id=1", "id")
        self.assertEqual(db, "mysql")
        self.assertEqual(ex.db_type, "mysql")

    async def test_no_delay_defaults_to_mysql(self):
        ex = SQLiExtractor(engine=None)
        ex._calibrated = True
        ex._detection_threshold = 99.0
        ex._sleep_duration = 5
        ex.engine = _engine_with_times([0.1] * 20)

        self.assertEqual(await ex.detect_db("https://x.com/?id=1", "id"), "mysql")


class TestSQLiUnion(unittest.IsolatedAsyncioTestCase):
    async def test_detect_columns_counts_until_error(self):
        async def send(url, **kw):
            if "ORDER+BY+4" in url:  # payload is urlencoded by _inject
                return {"status": 500, "body": "out of range", "headers": {}}
            return {"status": 200, "body": "ok", "headers": {}}

        eng = MagicMock()
        eng.ahttp_send = AsyncMock(side_effect=send)
        ex = SQLiExtractor(engine=eng)
        with patch("modules.web.server_side.sqli_extractor.random.random",
                   return_value=0.0):  # deterministic: no obfuscation
            result = await ex._detect_columns("https://x.com/?id=1", "id")
        self.assertEqual(result, 3)

    async def test_union_value_extracted_from_body(self):
        eng = MagicMock()
        eng.ahttp_send = AsyncMock(
            return_value={"status": 200, "body": "prefix 8.0.36-log suffix", "headers": {}})
        ex = SQLiExtractor(engine=eng)
        ex.db_type = "mysql"

        findings = await ex.union_extract("https://x.com/?id=1", "id", columns=2)
        self.assertTrue(findings)
        self.assertIn("8.0.36", findings[0]["detail"])
        self.assertEqual(findings[0]["method"], "UNION")

    async def test_union_none_without_columns(self):
        ex = SQLiExtractor(engine=MagicMock())
        self.assertIsNone(await ex.union_extract("https://x.com/?id=1", "id", columns=0))


class TestSQLiErrorBased(unittest.IsolatedAsyncioTestCase):
    async def test_tilde_markers_extracted(self):
        eng = MagicMock()
        eng.ahttp_send = AsyncMock(
            return_value={"status": 200,
                          "body": "XPATH syntax error: '~root@localhost~'", "headers": {}})
        ex = SQLiExtractor(engine=eng)
        ex.db_type = "mysql"

        findings = await ex.error_extract("https://x.com/?id=1", "id")
        self.assertTrue(findings)
        self.assertIn("root@localhost", findings[0]["detail"])
        self.assertEqual(findings[0]["method"], "error-based")

    async def test_no_markers_no_findings(self):
        eng = MagicMock()
        eng.ahttp_send = AsyncMock(
            return_value={"status": 200, "body": "normal page", "headers": {}})
        ex = SQLiExtractor(engine=eng)
        ex.db_type = "mysql"
        self.assertIsNone(await ex.error_extract("https://x.com/?id=1", "id"))


class TestSQLiBlind(unittest.IsolatedAsyncioTestCase):
    async def test_blind_binary_search_reconstructs_string(self):
        """Pin the binary-search extraction: length loop + per-char search."""
        target = "ab"

        async def fake_test(url, param, condition):
            if "LENGTH(" in condition:
                return int(condition.split(">=")[1].strip()) <= len(target)
            import re as _re
            m = _re.search(r",(\d+),1\)\) > (\d+)", condition)
            pos, mid = int(m.group(1)), int(m.group(2))
            return ord(target[pos - 1]) > mid

        ex = SQLiExtractor(engine=None)
        ex._sleep_duration = 5
        ex._detection_threshold = 3.0
        with patch.object(ex, "_blind_test", side_effect=fake_test):
            value = await ex._blind_extract_one("https://x.com/?id=1", "id", "VERSION()")
        self.assertEqual(value, "ab")

    async def test_blind_test_uses_calibrated_threshold(self):
        ex = SQLiExtractor(engine=None)
        ex.db_type = "mysql"
        ex._sleep_duration = 5
        ex._detection_threshold = 6.0
        eng = _engine_with_times([7.0])
        ex.engine = eng

        with patch("modules.web.server_side.sqli_extractor.random.random",
                   return_value=0.0):
            self.assertTrue(await ex._blind_test("https://x.com/?id=1", "id", "1=1"))
        from urllib.parse import unquote
        sent_url = unquote(eng.ahttp_send.call_args[0][0])
        self.assertIn("SLEEP(5)", sent_url)


class TestExtractChain(unittest.IsolatedAsyncioTestCase):
    async def test_empty_inputs_short_circuit(self):
        ex = SQLiExtractor(engine=MagicMock())
        self.assertEqual(await ex.extract("", "id"), [])
        self.assertEqual(await ex.extract("https://x.com/", ""), [])


class TestIDOR(unittest.IsolatedAsyncioTestCase):
    async def test_no_numeric_id_returns_empty(self):
        eng = MagicMock()
        eng.ahttp_send = AsyncMock()
        result = await scan_idor("https://x.com/profile", eng)
        self.assertEqual(result, [])
        eng.ahttp_send.assert_not_awaited()

    async def test_accessible_neighbor_ids_flagged(self):
        async def send(url, **kw):
            if "/users/100/" in url:  # baseline URL keeps the real id
                return {"status": 200, "body": "A" * 300, "headers": {}}
            return {"status": 200, "body": "B" * 500, "headers": {}}

        eng = MagicMock()
        eng.ahttp_send = AsyncMock(side_effect=send)
        findings = await scan_idor("https://x.com/users/100/profile", eng)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "idor_mass")
        self.assertGreater(findings[0]["accessible_count"], 0)
        # base id excluded from the probe set
        ids_part = findings[0]["detail"].split("Accessible IDs: ")[1].split("]")[0].lstrip("[")
        probed = [int(x) for x in ids_part.split(", ")]
        self.assertNotIn(100, probed)

    async def test_denied_responses_not_counted(self):
        async def send(url, **kw):
            if "/users/100/" in url:
                return {"status": 200, "body": "user data " + "A" * 290, "headers": {}}
            return {"status": 200, "body": "Access denied — unauthorized", "headers": {}}

        eng = MagicMock()
        eng.ahttp_send = AsyncMock(side_effect=send)
        findings = await scan_idor("https://x.com/users/100/profile", eng)
        self.assertEqual(findings, [])


class TestJWTAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = JWTTokenAnalyzer()

    def test_none_alg_confirmed(self):
        token = _b64({"alg": "none", "typ": "JWT"}) + "." + _b64({"sub": "x"}) + "."
        findings = self.analyzer._analyze_token(token, "https://x.com/", "query")
        self.assertEqual(findings[0]["type"], "jwt_none_alg")

    def test_weak_secret_cracked(self):
        token = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user"}, "secret")
        findings = self.analyzer._analyze_token(token, "https://x.com/", "body")
        weak = [f for f in findings if f["type"] == "jwt_weak_secret"]
        self.assertTrue(weak)
        self.assertIn("'secret'", weak[0]["detail"])

    def test_strong_secret_not_cracked(self):
        token = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user"}, "n0t-1n-1ist-x9")
        findings = self.analyzer._analyze_token(token, "https://x.com/", "body")
        self.assertFalse([f for f in findings if f["type"] == "jwt_weak_secret"])

    def test_sensitive_claims_flagged(self):
        token = _jwt({"alg": "HS256"},
                     {"role": "admin", "sub": "a@b.com", "password": "p"}, "secret")
        findings = self.analyzer._analyze_token(token, "https://x.com/", "query")
        claims = [f for f in findings if f["type"] == "jwt_sensitive_claims"]
        self.assertTrue(claims)
        self.assertIn("admin role", claims[0]["detail"])

    def test_malformed_token_ignored(self):
        self.assertEqual(self.analyzer._analyze_token("not-a-jwt", "u", "q"), [])
        self.assertEqual(
            self.analyzer._analyze_token("aGVhZGVy.cGF5bG9hZA.bad.sig", "u", "q"), [])


class TestPluginManager(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        PluginManager._instance = None
        PluginManager._plugins = []

    def tearDown(self):
        PluginManager._instance = None
        PluginManager._plugins = []

    @staticmethod
    def _fake_import(tmp):
        """PluginManager imports via modules.custom.<name> — map that to tmp files."""
        import importlib.util

        def _import(name):
            modname = name.rsplit(".", 1)[-1]
            path = os.path.join(tmp, modname + ".py")
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        return _import

    def test_discover_loads_runnable_classes_sorted_by_priority(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "zplug.py"), "w") as fh:
                fh.write("class Slow:\n    priority = 90\n"
                         "    async def run(self, state): return []\n")
            with open(os.path.join(tmp, "aplug.py"), "w") as fh:
                fh.write("class Fast:\n    priority = 10\n"
                         "    async def run(self, state): return [{'t': 1}]\n")
            with open(os.path.join(tmp, "_skip.py"), "w") as fh:
                fh.write("class Hidden:\n    async def run(self, state): return []\n")
            with open(os.path.join(tmp, "notplug.py"), "w") as fh:
                fh.write("class NoRun:\n    pass\n")

            with patch("modules.plugin.importlib.import_module",
                       side_effect=self._fake_import(tmp)):
                plugins = PluginManager().discover(tmp)

        names = [type(p).__name__ for p in plugins]
        self.assertEqual(names, ["Fast", "Slow"])  # priority-sorted, filtered

    def test_discover_caches_and_handles_missing_dir(self):
        pm = PluginManager()
        self.assertEqual(pm.discover("/nonexistent/dir"), [])
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "one.py"), "w") as fh:
                fh.write("class One:\n    async def run(self, state): return []\n")
            with patch("modules.plugin.importlib.import_module",
                       side_effect=self._fake_import(tmp)):
                first = pm.discover(tmp)
            # non-empty cache returned on second call even for other dir
            self.assertIs(pm.discover("/other"), first)

    async def test_run_plugins_executes_and_survives_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "boom.py"), "w") as fh:  # noqa: ASYNC230
                fh.write("class Boom:\n    name = 'Boom'\n"
                         "    async def run(self, state): raise RuntimeError('x')\n")
            with open(os.path.join(tmp, "ok.py"), "w") as fh:  # noqa: ASYNC230
                fh.write("class Ok:\n    name = 'Ok'\n"
                         "    async def run(self, state): return [{'type': 'from_plugin'}]\n")
            with patch("modules.plugin.importlib.import_module",
                       side_effect=self._fake_import(tmp)):
                PluginManager().discover(tmp)
            findings = await run_plugins(MagicMock())

        self.assertEqual(findings, [{"type": "from_plugin"}])


if __name__ == "__main__":
    unittest.main()
