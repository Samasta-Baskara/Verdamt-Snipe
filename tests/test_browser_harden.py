"""Behavioral tests for core/browser_harden.py (was 17% covered).

Pins the Firefox hardening contract: profile generation writes every
pref with correct types, and the leak checker maps prefs.js contents
to risk flags correctly.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.browser_harden import (
    FIREFOX_HARDENING,
    check_firefox_leaks,
    generate_profile,
    get_profile_dir,
)


class TestHardeningTable(unittest.TestCase):
    def test_no_duplicate_keys_and_sane_types(self):
        # Regression: "privacy.resistFingerprinting" used to appear twice
        # in the dict literal (F601) — the second silently overwrote the
        # first, and both were identical by luck.
        self.assertTrue(all(isinstance(v, (bool, int, str))
                            for v in FIREFOX_HARDENING.values()))
        self.assertIs(FIREFOX_HARDENING["privacy.resistFingerprinting"], True)
        self.assertIs(FIREFOX_HARDENING["media.peerconnection.enabled"], False)


class TestProfileDir(unittest.TestCase):
    def test_linux_path(self):
        with patch("core.browser_harden.platform.system", return_value="Linux"), \
             patch.object(Path, "home", return_value=Path("/home/u")):
            self.assertEqual(get_profile_dir(), Path("/home/u/.mozilla/firefox"))

    def test_windows_path_uses_appdata(self):
        with patch("core.browser_harden.platform.system", return_value="Windows"), \
             patch.dict("os.environ", {"APPDATA": "C:/Users/u/AppData/Roaming"}):
            self.assertEqual(
                get_profile_dir(),
                Path("C:/Users/u/AppData/Roaming") / "Mozilla" / "Firefox" / "Profiles")

    def test_unknown_os_fallback(self):
        with patch("core.browser_harden.platform.system", return_value="Plan9"), \
             patch.object(Path, "home", return_value=Path("/home/u")):
            self.assertEqual(get_profile_dir(), Path("/home/u/.firefox-hardened"))


class TestGenerateProfile(unittest.TestCase):
    def test_writes_every_pref_with_correct_type(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch("core.browser_harden.get_profile_dir", return_value=Path(tmp)), \
             patch("builtins.print"):
            profile = generate_profile("t-hardened")

            user_js = (profile / "user.js").read_text()
            for key, value in FIREFOX_HARDENING.items():
                self.assertIn(f'user_pref("{key}"', user_js)
                if isinstance(value, bool):
                    self.assertIn(f'"{key}", {"true" if value else "false"}', user_js)
            self.assertTrue((profile / "chrome" / "userChrome.css").exists())


class TestLeakCheck(unittest.TestCase):
    def _prefs_dir(self, tmp, content):
        profile = Path(tmp) / "abc.default"
        profile.mkdir(parents=True)
        (profile / "prefs.js").write_text(content)
        return Path(tmp)

    def test_missing_profile_dir_reported(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch("core.browser_harden.get_profile_dir",
                   return_value=Path(tmp) / "missing"):
            results = check_firefox_leaks()
        self.assertIn("Firefox profile directory not found", results["issues"])
        self.assertTrue(results["webRTC_leak"])

    def test_fully_hardened_profile_passes(self):
        hardened = "\n".join(
            f'user_pref("{k}", {"true" if v else "false"});'
            for k, v in FIREFOX_HARDENING.items())
        with tempfile.TemporaryDirectory() as tmp, \
             patch("core.browser_harden.get_profile_dir",
                   return_value=self._prefs_dir(tmp, hardened)):
            results = check_firefox_leaks()
        self.assertEqual(results["issues"], ["All checks passed — browser is hardened"])
        self.assertFalse(results["webRTC_leak"])
        self.assertFalse(results["dns_prefetch"])
        self.assertFalse(results["telemetry"])
        self.assertFalse(results["fingerprinting"])

    def test_unhardened_profile_lists_each_risk(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch("core.browser_harden.get_profile_dir",
                   return_value=self._prefs_dir(tmp, 'user_pref("x",1);\n')):
            results = check_firefox_leaks()
        self.assertTrue(results["webRTC_leak"])
        self.assertEqual(len(results["issues"]), 4)  # all four risks flagged


if __name__ == "__main__":
    unittest.main()
