"""--help must describe the flags the CLI actually consumes.

`core/ui/banner.py::_HELP_*` is the single source of truth the help screen
renders from.  These tests cross-check it against `core/cli_parser.py` (and
the `snipe` launcher) so the published grammar cannot drift from the real one
again — that is exactly how the old screen ended up listing a partial,
inconsistent flag set.
"""
import contextlib
import io
import pathlib
import re
import unittest

from rich.console import Console

from core.ui import menu
from core.ui.banner import (_HELP_GROUPS, _HELP_LAUNCHER, _HELP_USAGE,
                            _MODES, mode_flag, print_banner)

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI_SRC = (ROOT / "core" / "cli_parser.py").read_text()
LAUNCHER_SRC = (ROOT / "snipe").read_text()

# `--flag` is the placeholder used in _flag_value's docstring, not a real flag.
_DOC_PLACEHOLDERS = {"--flag"}


def _cli_flags():
    return {f for f in re.findall(r"--[a-z][a-z0-9-]*", CLI_SRC)
            if f not in _DOC_PLACEHOLDERS}


def _catalogue_flags():
    """Every long flag the help catalogue advertises."""
    blob = " ".join(flag for _title, rows in _HELP_GROUPS for flag, _ in rows)
    blob += " " + " ".join(flag for flag, _ in _HELP_LAUNCHER)
    blob += " " + " ".join(cmd for cmd, _ in _HELP_USAGE)
    blob += " " + " ".join(mode_flag(mode_id) for mode_id, _, _ in _MODES.values())
    return {f for f in re.findall(r"--[a-z][a-z0-9-]*", blob)}


def render_help(width: int = 100) -> str:
    """Render `draw_help_screen()` to plain text (no ANSI)."""
    buf = io.StringIO()
    previous = menu.console
    menu.console = Console(file=buf, width=width, force_terminal=False,
                           highlight=False, legacy_windows=False)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            menu.draw_help_screen()
    finally:
        menu.console = previous
    text = buf.getvalue()
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)


def render_banner(width: int = 100) -> str:
    buf = io.StringIO()
    previous = menu.console
    import core.ui.banner as banner_mod
    menu.console = Console(file=buf, width=width, force_terminal=False,
                           highlight=False, legacy_windows=False)
    banner_mod.console = menu.console
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            print_banner("1.4.5", "Verdammt")
    finally:
        menu.console = previous
        banner_mod.console = previous
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", buf.getvalue())


class TestHelpMatchesRealGrammar(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.help_text = render_help()

    def test_every_cli_flag_is_documented(self):
        missing = sorted(f for f in _cli_flags() if f not in self.help_text)
        self.assertEqual(
            missing, [],
            "flags core/cli_parser.py consumes but --help never mentions:\n  "
            + "\n  ".join(missing))

    def test_no_phantom_flags_are_documented(self):
        undocumented = sorted(
            f for f in _catalogue_flags()
            if f not in _cli_flags() and f not in LAUNCHER_SRC)
        self.assertEqual(
            undocumented, [],
            "--help documents flags the CLI does not accept:\n  "
            + "\n  ".join(undocumented))

    def test_every_short_alias_is_documented(self):
        for short in ("-h", "-p", "-i", "-s", "-t", "-r", "-H", "-H2"):
            self.assertIn(short, self.help_text, f"missing short alias {short}")

    def test_documented_short_aliases_are_recognised(self):
        # -h/-v-style spellings the entry point really accepts
        for token in ('"-h"', '"--help"', '"/h"', '"--version"', '"/v"'):
            self.assertIn(token, CLI_SRC, f"{token} is documented but not parsed")

    def test_help_mentions_auth_secret_forms(self):
        for token in ("env:VAR", "file:PATH"):
            self.assertIn(token, self.help_text)


class TestModeFlags(unittest.TestCase):
    def test_mode_flag_derivation_matches_parser(self):
        from core.cli_parser import parse_mode
        for mode_id, _label, _desc in _MODES.values():
            derived = mode_flag(mode_id)
            self.assertEqual(
                parse_mode([derived]), mode_id,
                f"{derived} does not select mode {mode_id}")

    def test_every_mode_is_listed(self):
        text = render_help()
        for key, (mode_id, _label, _desc) in _MODES.items():
            self.assertIn(f"[{key}]", text)
            self.assertIn(mode_flag(mode_id), text)

    def test_launcher_mode_keys_match_modes(self):
        keys = re.findall(r'([1-7])\)', LAUNCHER_SRC)
        self.assertEqual(sorted(set(keys)), sorted(_MODES))


class TestHelpPresentation(unittest.TestCase):
    def test_branding_is_exact(self):
        text = render_help()
        self.assertIn("VERDAMT-SNIPE", text)
        self.assertIn("RECON · SCAN · EXPLOIT", text)
        self.assertNotIn("VERDAMMT", text)

    def test_banner_has_no_stale_flag_list(self):
        text = render_banner()
        self.assertNotIn("VERDAMMT", text)
        # whatever the banner advertises must also be real
        for flag in re.findall(r"--[a-z][a-z0-9-]*", text):
            self.assertIn(flag, _cli_flags(),
                          f"banner advertises unknown flag {flag}")

    def test_sections_render(self):
        text = render_help()
        for title in ("USAGE", "MODES", "SCAN CONTROL", "PROXY & IMPERSONATION",
                      "SAFETY & SCOPE", "AUTH & HEADERS", "MODULE FOCUS",
                      "OUTPUT & TOOLING", "SNIPER LAUNCHER", "EXAMPLES"):
            self.assertIn(title, text, f"missing section {title}")

    def test_authorization_note_present(self):
        text = render_help()
        self.assertIn("Authorized targets only", text)
        self.assertIn("--allowed-hosts", text)

    def test_examples_reference_real_modes(self):
        text = render_help()
        self.assertNotIn("target.com --nuclei", text)  # old example order
        self.assertIn("snipe 6 example.com", text)
        self.assertIn("--dry-run", text)


if __name__ == "__main__":
    unittest.main()
