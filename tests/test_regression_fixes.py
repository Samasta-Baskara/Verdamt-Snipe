"""Regression tests for the "scan never finishes" bug chain:

1. run_nuclei/run_dalfox warned via w() on paths where the local
   ``from core.ui import w`` had not executed yet → UnboundLocalError
   ("module nuclei crashed — results skipped") that discarded every nuclei
   finding (or killed mode 7 outright, skipping the report).
2. A mid-mode crash used to ``raise`` inline in async_main's BaseException
   handler, skipping verify/report + cleanup entirely: no report artifacts,
   engine/browser left open, resume re-ran the pipeline from the top
   ("back to WAF risk assessment").
3. GoogleDorker used to burn through the dork list behind a captcha and
   spam per-dork warnings; it must fast-bail, export the query list, and
   stay quiet. A budget cap must stop it even when engines answer 200.
4. finding_cvss must coerce non-numeric scores so the Phase 5 sort can
   never kill the report right before it is generated.
"""
import inspect
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch


class TestNucleiDalfoxWarningPaths(unittest.TestCase):
    """These paths raise UnboundLocalError before the external_tools fix."""

    @staticmethod
    def _policy(filter_fn, charge_fn=None):
        p = MagicMock()
        p.requests_remaining = 100_000
        p.filter_urls = filter_fn
        if charge_fn:
            p.charge = charge_fn
        return p

    def test_charge_overflow_warning_does_not_raise(self):
        from core import external_tools as et
        policy = self._policy(lambda u: list(u), lambda n, reason=None: 5)
        with patch.object(et, "_run_tool", return_value=(0, "", '{"requests":"421"}')):
            findings = et.run_nuclei(["https://example.com"], policy=policy)
        self.assertEqual(findings, [])

    def test_filter_all_targets_warning_does_not_raise(self):
        from core import external_tools as et
        policy = self._policy(lambda u: [])
        with patch.object(et, "_run_tool", return_value=(0, "", "")):
            findings = et.run_nuclei(["https://example.com"], policy=policy)
        self.assertEqual(findings, [])

    def test_stats_unavailable_warning_does_not_raise(self):
        from core import external_tools as et
        policy = self._policy(lambda u: list(u), lambda n, reason=None: 1)
        with patch.object(et, "_run_tool", return_value=(0, "", "no stats")):
            findings = et.run_nuclei(["https://example.com"], policy=policy)
        self.assertEqual(findings, [])

    def test_dalfox_filter_all_warning_does_not_raise(self):
        from core import external_tools as et
        policy = self._policy(lambda u: [])
        with patch.object(et, "_run_tool", return_value=(0, "", "")):
            findings = et.run_dalfox(["https://example.com/?q=1"], policy=policy)
        self.assertEqual(findings, [])


class TestCrashStillReports(unittest.TestCase):
    """Static contract of async_main's crash path."""

    def test_exception_is_held_until_after_verify_report(self):
        from core import cli_parser
        src = inspect.getsource(cli_parser.async_main)
        self.assertIn("mode_error = e", src,
                      "crash handler must hold the exception, not merge it")
        idx_report = src.index("await phase_verify_report")
        idx_reraise = src.index("raise mode_error")
        self.assertLess(idx_report, idx_reraise,
                        "verify/report must run BEFORE the crash is re-raised")
        # The BaseException handler must not raise inline (that is the bug
        # that skipped reporting); the only raise after it is the held one.
        handler = src.split("except BaseException as e:")[1].split("finally:")[0]
        self.assertNotIn("raise\n", handler)

    def test_execute_mode_accepts_new_knobs(self):
        from core.cli_parser import _execute_mode
        params = inspect.signature(_execute_mode).parameters
        self.assertIn("no_dork", params)
        self.assertFalse(params["no_dork"].default)
        self.assertIn("archive_timeout", params)
        self.assertIsNone(params["archive_timeout"].default)

    def test_recon_intel_accepts_new_knobs(self):
        from runners.recon_intel import run_recon_intel
        params = inspect.signature(run_recon_intel).parameters
        self.assertIn("no_dork", params)
        self.assertIn("archive_timeout", params)


class TestNewFlagsParse(unittest.TestCase):
    def test_archive_timeout_is_a_value_flag(self):
        from core.cli_parser import _VALUE_FLAGS, _flag_value, parse_scan_args
        self.assertIn("--archive-timeout", _VALUE_FLAGS)
        argv = ["verd.py", "x.com", "--archive-timeout", "120", "--no-dork"]
        target, flags, resume = parse_scan_args(argv)
        self.assertEqual(target, "x.com")
        self.assertIsNone(resume)
        self.assertEqual(_flag_value(flags, "--archive-timeout"), "120")
        self.assertIn("--no-dork", flags)


class TestDorkerFastBail(unittest.TestCase):
    def test_captcha_block_detected_and_queries_exported(self):
        from modules.recon import dorking as dk
        captcha = {"status": 429,
                   "body": "unusual traffic from your network — captcha",
                   "headers": {}}
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                with patch.object(dk, "thttp", return_value=captcha):
                    r = dk.GoogleDorker("example.com").run()
                self.assertTrue(r["scrape_failed"])
                self.assertTrue(r["manual_dork_path"])
                self.assertTrue(os.path.exists(r["manual_dork_path"]))
                with open(r["manual_dork_path"], encoding="utf-8") as fh:
                    content = fh.read()
                self.assertIn("site:example.com filetype:sql", content)
            finally:
                os.chdir(cwd)

    def test_budget_stops_run_even_without_blocks(self):
        from modules.recon import dorking as dk
        empty_page = {"status": 200, "body": "<html>nothing</html>",
                      "headers": {}}
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                dorker = dk.GoogleDorker("example.com", budget_seconds=0.0)
                with patch.object(dk, "thttp", return_value=empty_page) as m:
                    r = dorker.run()
                self.assertTrue(r["scrape_failed"])
                m.assert_not_called()  # budget checked before first request
            finally:
                os.chdir(cwd)


class TestFindingCvssCoercion(unittest.TestCase):
    def test_none_score_falls_back_to_default(self):
        from reports.engine import finding_cvss
        out = finding_cvss({"type": "reflected_xss", "cvss_score": None})
        self.assertIsInstance(out["s"], float)

    def test_string_score_is_coerced(self):
        from reports.engine import finding_cvss
        out = finding_cvss({"type": "reflected_xss", "cvss_score": "8.8"})
        self.assertAlmostEqual(out["s"], 8.8)


if __name__ == "__main__":
    unittest.main()
