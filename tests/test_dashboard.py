"""Dashboard redesign QA — layout geometry, branding and semantic colours.

The live dashboard is pure presentation over ScanDashboard state, so these
tests render `_build_layout()` at several terminal geometries and assert:

  * every line is exactly the terminal width (no horizontal overflow) and the
    compose is exactly the terminal height (Rich Live crops, never scrolls);
  * the Verdamt-Snipe brand lock-up is spelled exactly as the project name;
  * Recent Activity carries the semantic palette (emerald / red / gold /
    informational blue / muted grey timestamps);
  * Pipeline uses restrained status colours and never invents counters;
  * Tooling / Metrics shows only values derived from real scan state;
  * the metallic-gold SCALING strip is present.
"""
import io
import sys
import time
import unittest

from rich.cells import cell_len
from rich.console import Console

from core.ui import tables
from core.ui.banner import _PIPELINE_STAGES_BY_MODE
from core.ui.tables import ScanDashboard
from core.ui.styles import (D_BG, D_EMERALD, D_GOLD, D_INFO, D_TEXT, D_DIM,
                            D_WARN, D_CRIT, D_BORDER, D_PANEL, D_ELEV)


def _segments(dash, width, height):
    con = Console(width=width, height=height, force_terminal=True,
                  highlight=False, legacy_windows=False)
    previous = tables.console
    tables.console = con
    try:
        return con.render_lines(dash._build_layout(), con.options)
    finally:
        tables.console = previous


def _palette(lines):
    """Lower-cased join of every style string Rich emitted (hex colours)."""
    return " ".join(_styles(lines)).lower()


def _plain(lines):
    return ["".join(seg.text for seg in ln) for ln in lines]


def _styles(lines):
    out = set()
    for ln in lines:
        for seg in ln:
            if seg.control or not seg.style:
                continue
            out.add(str(seg.style))
    return out


def _build(target="demo.testfire.net", mode="FULL", status="SCANNING"):
    ScanDashboard._instance = None
    dash = ScanDashboard.get_instance()
    dash.target = target
    dash.mode = mode
    dash.status = status
    dash.start_time = time.time() - 18
    dash.pipeline = [dict(s) for s in _PIPELINE_STAGES_BY_MODE[mode]]
    dash.recent_events.clear()
    dash._event_seq = 0
    dash._view_anchor = None
    dash.metrics = {"Requests": 0, "Subdomains": 0, "Live Hosts": 0,
                    "Endpoints": 0, "Parameters": 0}
    dash._rps_history.clear()
    dash._display_pct = 0.0
    return dash


class TestDashboardGeometry(unittest.TestCase):
    def tearDown(self):
        ScanDashboard._instance = None

    def test_fills_terminal_exactly_no_overflow(self):
        """Lines must be exactly `width` cells and the compose exactly `height`."""
        from rich.cells import cell_len
        for width, height in ((150, 50), (132, 44), (118, 30),
                              (96, 40), (72, 30), (48, 32), (40, 18)):
            dash = _build()
            lines = _plain(_segments(dash, width, height))
            self.assertEqual(len(lines), height, f"{width}x{height} line count")
            for idx, line in enumerate(lines):
                self.assertEqual(
                    cell_len(line), width,
                    f"{width}x{height} line {idx} is {cell_len(line)} cells")

    def test_empty_scan_renders(self):
        """Fresh scan (no events, all stages pending) must not blow up."""
        dash = _build()
        dash.status = "STARTING"
        lines = _plain(_segments(dash, 120, 40))
        self.assertEqual(len(lines), 40)
        self.assertTrue(any("RECENT ACTIVITY" in ln for ln in lines))
        self.assertTrue(any("PIPELINE" in ln for ln in lines))


class TestBranding(unittest.TestCase):
    def tearDown(self):
        ScanDashboard._instance = None

    def test_wordmark_and_subtitle_exact(self):
        text = "\n".join(_plain(_segments(_build(), 150, 50)))
        self.assertIn("VERDAMT-SNIPE", text)
        self.assertIn("RECON · SCAN · EXPLOIT", text)
        for bad in ("VERDAMMT", "Verd am", "VERDAMT SNIPE", "Verdammt-Snipe"):
            self.assertNotIn(bad, text)

    def test_v_emblem_sits_left_of_wordmark(self):
        lines = _plain(_segments(_build(), 150, 50))
        wordmark_row = next(i for i, ln in enumerate(lines) if "VERDAMT-SNIPE" in ln)
        head = lines[wordmark_row]
        self.assertLess(head.index("╲"), head.index("VERDAMT-SNIPE"))
        self.assertIn("╱", head)

    def test_status_target_mode_elapsed_in_header(self):
        text = "\n".join(_plain(_segments(_build(), 150, 50)))
        for token in ("RUNNING", "Target", "demo.testfire.net", "Mode",
                      "FULL", "Elapsed"):
            self.assertIn(token, text)


class TestRecentActivityColours(unittest.TestCase):
    def tearDown(self):
        ScanDashboard._instance = None

    def _dash_with_events(self):
        dash = _build()
        base = time.time() - 5
        dash.log_event("Initializing modules...", "cyan", kind="info")
        dash.log_event("Subfinder completed - 0 subdomains found", "green", kind="ok")
        dash.log_event("Cache poisoning test - 35.0%", "green", kind="ok")
        dash.log_event("Scanning for cache poisoning (stage 4/10)", "cyan", kind="info")
        dash.log_warning("WAF detected: Cloudflare")
        dash.log_error("connection refused")
        dash.log_finding("Critical", "SQL Injection", "https://t/x")
        dash.log_finding("Medium", "CORS Wildcard", "https://t/y")
        with dash._lock:
            for i, ev in enumerate(list(dash.recent_events)):
                lst = list(dash.recent_events)
                lst[i] = (ev[0], ev[1], base + i, ev[3])
                dash.recent_events.clear()
                dash.recent_events.extend(lst)
        return dash

    def test_semantic_palette_present(self):
        joined = _palette(_segments(self._dash_with_events(), 150, 50))
        self.assertIn(D_INFO.lower(), joined)      # ordinary informational messages
        self.assertIn(D_EMERALD.lower(), joined)   # successful / positive results
        self.assertIn(D_CRIT.lower(), joined)      # errors and critical findings
        self.assertIn(D_WARN.lower(), joined)      # warnings
        self.assertIn(D_GOLD.lower(), joined)      # milestones & progress tokens
        self.assertIn(D_DIM.lower(), joined)       # timestamps / secondary metadata

    def test_severity_labels_and_timestamps(self):
        text = "\n".join(_plain(_segments(self._dash_with_events(), 150, 50)))
        for label in ("[INFO]", "[ OK ]", "[WARN]", "[FAIL]", "[CRIT]", "[FIND]"):
            self.assertIn(label, text)
        self.assertRegex(text, r"\[\d{2}:\d{2}:\d{2}\]")

    def test_scroll_window_follows_newest_and_reports_hidden(self):
        dash = _build()
        with dash._lock:
            for i in range(60):
                dash.recent_events.append((f"event {i}", "cyan", time.time(), "info"))
                dash._event_seq += 1
        lines = _plain(_segments(dash, 80, 30))
        text = "\n".join(lines)
        self.assertIn("event 59", text)                 # newest visible
        self.assertNotIn("event 0 ", text)              # oldest scrolled away
        self.assertRegex(text, r"EARLIER")              # hidden-history indicator

    def test_scroll_anchor_is_sticky(self):
        def feed(dash):
            return [ln for ln in _plain(_segments(dash, 90, 30)) if "event" in ln]

        dash = _build()
        with dash._lock:
            for i in range(60):
                dash.recent_events.append((f"event {i}", "cyan", time.time(), "info"))
                dash._event_seq += 1
        dash.scroll_events(-8)
        first = feed(dash)
        self.assertTrue(first)
        with dash._lock:
            dash.recent_events.append(("brand new event", "cyan", time.time(), "info"))
            dash._event_seq += 1
        # inspecting older logs must not be yanked back to the bottom
        self.assertEqual(first, feed(dash))
        dash.scroll_events(0)   # End → auto-follow again
        self.assertTrue(any("brand new event" in ln for ln in feed(dash)))


class TestActivityScrollbar(unittest.TestCase):
    """The feed scrolls inside its panel and carries a position thumb."""

    def tearDown(self):
        ScanDashboard._instance = None

    @staticmethod
    def _feed(dash, n):
        with dash._lock:
            for i in range(n):
                dash.recent_events.append((f"event {i:03d}", "cyan",
                                           time.time(), "info"))
                dash._event_seq += 1

    @staticmethod
    def _activity(dash, width=50, height=20):
        lines, _ = dash._build_activity(width, height,
                                        list(dash.recent_events),
                                        dash._event_seq, dash._view_anchor)
        return [ln.plain for ln in lines]

    def test_no_bar_when_history_fits(self):
        dash = _build()
        self._feed(dash, 3)
        rows = self._activity(dash)
        text = "\n".join(rows)
        self.assertNotIn("█", text)
        self.assertNotIn("░", text)
        for line in rows:
            self.assertEqual(cell_len(line), 50)

    def test_thumb_pinned_to_tail_while_following(self):
        dash = _build()
        self._feed(dash, 150)
        rows = self._activity(dash, 50, 20)
        thumb = [i for i, ln in enumerate(rows) if "█" in ln]
        self.assertTrue(thumb, "no scrollbar thumb rendered")
        self.assertEqual(max(thumb), 19)          # bottom of the bar
        for i, ln in enumerate(rows):
            self.assertIn("█" if i in thumb else "░", ln)
            self.assertEqual(cell_len(ln), 50)

    def test_scrolling_back_moves_thumb_to_the_top(self):
        dash = _build()
        self._feed(dash, 150)
        self._activity(dash, 50, 20)              # first paint registers window
        dash.scroll_events(-130)
        rows = self._activity(dash, 50, 20)
        thumb = [i for i, ln in enumerate(rows) if "█" in ln]
        self.assertTrue(thumb)
        self.assertEqual(min(thumb), 0)           # top of the bar

    def test_no_bar_when_anchor_set_but_history_fully_visible(self):
        dash = _build()
        self._feed(dash, 3)
        dash.scroll_events(-1)
        text = "\n".join(self._activity(dash))
        self.assertNotIn("█", text)
        self.assertNotIn("░", text)

    def test_scrolled_badge_and_full_width_geometry(self):
        dash = _build()
        self._feed(dash, 150)
        dash.scroll_events(-20)
        lines = _plain(_segments(dash, 120, 40))
        text = "\n".join(lines)
        self.assertIn("SCROLLED · End", text)
        self.assertIn("█", text)
        self.assertEqual(len(lines), 40)
        for ln in lines:
            self.assertEqual(cell_len(ln), 120)


class TestFeedScrollKeys(unittest.TestCase):
    """Keyboard and mouse-wheel bindings drive the feed cursor."""

    def tearDown(self):
        ScanDashboard._instance = None

    def _scrolled_dash(self):
        dash = _build()
        with dash._lock:
            for i in range(120):
                dash.recent_events.append((f"e{i}", "cyan", time.time(), "info"))
                dash._event_seq += 1
        _segments(dash, 120, 40)                  # paint once → window known
        return dash

    def test_wheel_steps_are_small_and_reversible(self):
        dash = self._scrolled_dash()
        top = dash._render_top_seq
        dash._handle_keys("\x1b[<64;10;5M")       # wheel up
        self.assertEqual(dash._view_anchor, top - tables._WHEEL_STEP)
        dash._handle_keys("\x1b[<65;10;5M")       # wheel down
        self.assertEqual(dash._view_anchor, top)

    def test_shift_wheel_still_scrolls(self):
        dash = self._scrolled_dash()
        top = dash._render_top_seq
        dash._handle_keys("\x1b[<68;10;5M")       # shift + wheel up
        self.assertEqual(dash._view_anchor, top - tables._WHEEL_STEP)

    def test_application_mode_arrows_and_end(self):
        dash = self._scrolled_dash()
        top = dash._render_top_seq
        dash._handle_keys("\x1bOA")               # app-mode ↑
        self.assertEqual(dash._view_anchor, top - tables._SCROLL_STEP)
        dash._handle_keys("\x1b[4~")              # End → auto-follow
        self.assertIsNone(dash._view_anchor)
        dash._handle_keys("\x1bOB")               # app-mode ↓ at tail is a no-op
        self.assertIsNone(dash._view_anchor)
        dash._handle_keys("\x1b[6~")              # PageDown at tail is a no-op
        self.assertIsNone(dash._view_anchor)


class TestPipeline(unittest.TestCase):
    def tearDown(self):
        ScanDashboard._instance = None

    def test_stages_come_from_scan_modes(self):
        dash = _build(mode="FULL")
        text = "\n".join(_plain(_segments(dash, 150, 50)))
        for stage in _PIPELINE_STAGES_BY_MODE["FULL"]:
            self.assertIn(stage["name"], text)

    def test_status_badges_and_restrained_colours(self):
        dash = _build()
        with dash._lock:
            dash.pipeline[0]["status"] = "completed"
            dash.pipeline[1]["status"] = "completed"
            dash.pipeline[2]["status"] = "active"
            dash.pipeline[3]["status"] = "pending"
        joined = _palette(_segments(dash, 150, 50))
        self.assertIn(D_EMERALD.lower(), joined)   # completed
        self.assertIn(D_WARN.lower(), joined)      # running (amber, not gold)
        self.assertIn(D_DIM.lower(), joined)       # pending is grey
        # the metallic-gold wordmark must not leak into this panel's status set
        text = "\n".join(_plain(_segments(dash, 150, 50)))
        self.assertIn("✓ COMPLETED", text)
        self.assertIn("● RUNNING", text)
        self.assertIn("○ PENDING", text)

    def test_pending_stages_do_not_invent_counters(self):
        dash = _build()
        text = "\n".join(_plain(_segments(dash, 150, 50)))
        badges = ("PENDING", "RUNNING", "COMPLETED", "FAILED", "SKIPPED")
        for stage in _PIPELINE_STAGES_BY_MODE["FULL"]:
            row = next(ln for ln in text.split("\n")
                       if stage["name"] in ln and any(b in ln for b in badges))
            if not stage["detail"]:
                self.assertIn("—", row)          # unavailable, not "0 / 0"
                self.assertNotIn("100%", row)

    def test_failed_stage_uses_critical_red(self):
        dash = _build()
        with dash._lock:
            dash.pipeline[0]["status"] = "failed"
        joined = _palette(_segments(dash, 150, 50))
        self.assertIn(D_CRIT.lower(), joined)
        text = "\n".join(_plain(_segments(dash, 150, 50)))
        self.assertIn("✕ FAILED", text)


class TestToolingMetrics(unittest.TestCase):
    def tearDown(self):
        ScanDashboard._instance = None

    def test_metrics_reflect_real_state(self):
        dash = _build()
        dash.metrics["Subdomains"] = 24
        dash.metrics["Endpoints"] = 192
        dash.metrics["Requests"] = 333
        text = "\n".join(_plain(_segments(dash, 150, 50)))
        for token in ("Request Rate", "Progress", "Targets", "Subdomains",
                      "Endpoints", "1 domain", "24", "192"):
            self.assertIn(token, text)
        self.assertIn("req/s", text)
        self.assertRegex(text, r"Stage \d+/\d+")

    def test_unavailable_values_render_dash(self):
        dash = _build(target="")
        text = "\n".join(_plain(_segments(dash, 150, 50)))
        self.assertIn("—", text)
        self.assertNotIn("0 domains", text)

    def test_compact_meter_fallback_fits_narrow_panels(self):
        """Too short for gauges → every metric still appears, unwrapped."""
        from rich.cells import cell_len
        dash = _build()
        dash.metrics["Endpoints"] = 7
        lines = _plain(_segments(dash, 72, 30))
        self.assertTrue(all(cell_len(ln) == 72 for ln in lines))
        text = "\n".join(lines)
        expected_stage = f"Stage 0/{len(_PIPELINE_STAGES_BY_MODE['FULL'])}"
        for token in ("req/s", expected_stage, "Targets", "1 domain",
                      "Subdomains", "Endpoints", "7"):
            self.assertIn(token, text)
        # the counts line must not be clipped mid-word
        metrics_row = next(ln for ln in lines if "Endpoints" in ln)
        self.assertIn("Endpoints 7", metrics_row)


class TestScalingStrip(unittest.TestCase):
    def tearDown(self):
        ScanDashboard._instance = None

    def test_gold_scaling_indicator_bottom_right(self):
        lines = _plain(_segments(_build(), 150, 50))
        last = lines[-1]
        self.assertIn("SCALING", last)
        self.assertEqual(last.strip().endswith("●"), True)
        self.assertGreater(last.rindex("SCALING"), len(last) // 2)   # right half
        self.assertIn(D_GOLD.lower(), _palette([_segments(_build(), 150, 50)[-1]]))

    def test_backgrounds_follow_palette(self):
        joined = _palette(_segments(_build(), 150, 50))
        self.assertIn(D_BG.lower(), joined)
        self.assertIn(D_PANEL.lower(), joined)
        self.assertIn(D_ELEV.lower(), joined)
        self.assertIn(D_BORDER.lower(), joined)
        self.assertIn(D_TEXT.lower(), joined)


class TestNoLiveSideEffects(unittest.TestCase):
    """The dashboard must be constructible and renderable without a tty."""

    def tearDown(self):
        ScanDashboard._instance = None

    def test_never_starts_live_or_tty_listener(self):
        dash = _build()
        _segments(dash, 100, 30)
        self.assertFalse(dash._active)
        self.assertIsNone(dash._live)
        self.assertFalse(dash.scroll_enabled)
        self.assertFalse(ScanDashboard.active())

    def test_event_history_keeps_long_window(self):
        dash = _build()
        with dash._lock:
            for i in range(dash.recent_events.maxlen + 50):
                dash.recent_events.append((f"e{i}", "cyan", time.time(), "info"))
                dash._event_seq += 1
        self.assertEqual(len(dash.recent_events), 400)


class TestFeedProxy(unittest.TestCase):
    """Stray stdout/stderr lines stay inside the dashboard while active."""

    def test_complete_lines_are_emitted_incrementally(self):
        emitted = []
        proxy = tables._FeedProxy(io.StringIO(), emitted.append)
        proxy.write("hello ")
        self.assertEqual(emitted, [])
        proxy.write("world\nnext")
        self.assertEqual(emitted, ["hello world"])
        proxy.flush()
        self.assertEqual(emitted, ["hello world", "next"])

    def test_blank_lines_and_carriage_returns_are_cleaned(self):
        emitted = []
        proxy = tables._FeedProxy(io.StringIO(), emitted.append)
        proxy.write("\n   \nprogress 1\rprogress 2\n")
        self.assertEqual(emitted, ["progress 2"])

    def test_rich_markup_is_rendered_to_plain_text(self):
        emitted = []
        proxy = tables._FeedProxy(io.StringIO(), emitted.append)
        proxy.write("  [bold green]✔[/] [cyan]200[/] [white]https://x[/]\n")
        self.assertEqual(emitted, ["✔ 200 https://x"])
        proxy.write("[INFO] stays literal\n")
        self.assertEqual(emitted[-1], "[INFO] stays literal")
        proxy.write("[/] orphan close stays raw\n")
        self.assertEqual(emitted[-1], "[/] orphan close stays raw")

    def test_console_unwraps_to_the_real_stream(self):
        wrapped = io.StringIO()
        proxy = tables._FeedProxy(wrapped, [].append)
        self.assertIs(proxy.rich_proxied_file, wrapped)

    def test_installs_and_restores_sys_streams(self):
        dash = _build()
        real_out, real_err = sys.stdout, sys.stderr
        dash._install_feed_proxy()
        try:
            self.assertIsNot(sys.stdout, real_out)
            self.assertIs(sys.stderr.rich_proxied_file, real_err)
            print("routed line")
            sys.stderr.write("routed warning\n")
        finally:
            dash._uninstall_feed_proxy()
        self.assertIs(sys.stdout, real_out)
        self.assertIs(sys.stderr, real_err)
        kinds = [ev[3] for ev in dash.recent_events]
        self.assertIn("info", kinds)
        self.assertIn("warn", kinds)


class TestDrawTableRouting(unittest.TestCase):
    """draw_table must never print above a live dashboard canvas."""

    def tearDown(self):
        ScanDashboard._instance = None

    def _capture(self, fn):
        captured = io.StringIO()
        original = tables.console
        tables.console = Console(file=captured, width=100, force_terminal=False)
        try:
            fn()
        finally:
            tables.console = original
        return captured.getvalue()

    def test_active_dashboard_streams_rows_into_feed(self):
        dash = _build()
        dash._active = True
        try:
            out = self._capture(lambda: tables.draw_table(
                ["CODE", "URL"],
                [["200", "https://a"], ["403", "https://b"]],
                title="Live Services"))
        finally:
            dash._active = False
        self.assertEqual(out, "")
        joined = "\n".join(ev[0] for ev in dash.recent_events)
        self.assertIn("Live Services", joined)
        self.assertIn("200  https://a", joined)
        self.assertIn("403  https://b", joined)

    def test_inactive_dashboard_keeps_the_markup_table(self):
        dash = _build()
        out = self._capture(lambda: tables.draw_table(
            ["CODE", "URL"], [["200", "https://a"]], title="Live Services"))
        self.assertIn("Live Services", out)
        self.assertIn("https://a", out)
        self.assertEqual(len(dash.recent_events), 0)

    def test_row_cap_keeps_the_feed_sane(self):
        dash = _build()
        dash._active = True
        try:
            self._capture(lambda: tables.draw_table(
                ["N"], [[str(i)] for i in range(30)], title="Big"))
        finally:
            dash._active = False
        joined = "\n".join(ev[0] for ev in dash.recent_events)
        self.assertIn("… 10 more rows", joined)


if __name__ == "__main__":
    unittest.main()


# ─────────────────────────────────────────────────────────────────────────────
# Round 2 polish: thick gauge arc, findings summary, rate sparkline, scroll hint
# ─────────────────────────────────────────────────────────────────────────────

_SPARK_SET = set("▁▂▃▄▅▆▇█")


class TestGaugeArc(unittest.TestCase):
    """Item 1 — the arc must read as a solid two-cell ring, not a dotted line."""

    def test_crown_is_two_cells_thick(self):
        rows = [r.plain for r in tables._gauge(
            "18.5", "Request Rate", [("req/s", D_DIM)], 1.0, D_EMERALD)]
        self.assertEqual(len(rows), tables.GAUGE_H)
        # a single-cell arc put 10 / 6 / 4 / 2 cells in rows 1-4; doubling the
        # stroke has to raise the crown well past those
        self.assertGreaterEqual(rows[1].count("█"), 9)
        self.assertGreaterEqual(rows[2].count("█"), 13)
        self.assertGreaterEqual(rows[3].count("█"), 6)
        self.assertGreaterEqual(rows[4].count("█"), 4)

    def test_value_sits_in_the_mouth_without_wiping_the_arms(self):
        rows = [r.plain for r in tables._gauge(
            "55.0%", "Progress", [("Stage 4/10", D_DIM)], 1.0, D_GOLD)]
        mouth = rows[3]
        self.assertIn("55.0%", mouth)
        left, right = mouth.split("55.0%")
        self.assertGreaterEqual(left.count("█"), 3)
        self.assertGreaterEqual(right.count("█"), 3)

    def test_label_row_and_caption_row_stay_clear_of_the_arc(self):
        rows = [r.plain for r in tables._gauge(
            "18.5", "Request Rate", [("req/s", D_DIM)], 1.0, D_EMERALD)]
        # the ring only ever occupies rows 1-4; label and caption are untouched
        self.assertIn("Request Rate", rows[0])
        self.assertNotIn("█", rows[0])
        self.assertNotIn("█", rows[5])
        self.assertIn("req/s", rows[5])

    def test_fraction_only_drives_colour_not_geometry(self):
        full = [r.plain for r in tables._gauge(
            "0.0", "Request Rate", [("req/s", D_DIM)], 1.0, D_EMERALD)]
        empty = [r.plain for r in tables._gauge(
            "0.0", "Request Rate", [("req/s", D_DIM)], 0.0, D_EMERALD)]
        self.assertEqual(full, empty)


class TestFindingsSummary(unittest.TestCase):
    """Item 2 — a one-line findings summary, only when there is something to say."""

    def test_absent_when_there_are_no_findings(self):
        dash = _build()
        text = "\n".join(_plain(_segments(dash, 150, 50)))
        self.assertNotIn("Findings", text)

    def test_present_with_severity_breakdown(self):
        dash = _build()
        dash.finding_count = 4
        dash.severity_counts = {"Critical": 1, "High": 2, "Medium": 1,
                                "Low": 0, "Info": 0}
        lines = _plain(_segments(dash, 150, 50))
        row = next(ln for ln in lines if "Findings" in ln)
        self.assertIn("Findings", row)
        self.assertIn("4", row)
        self.assertIn("1 crit", row)
        self.assertIn("2 high", row)
        self.assertIn("1 med", row)
        joined = _palette(_segments(dash, 150, 50))
        self.assertIn(D_CRIT.lower(), joined)
        self.assertIn(D_GOLD.lower(), joined)

    def test_zero_findings_helper_returns_none(self):
        self.assertIsNone(tables._findings_line(60, D_PANEL, 0, {}))
        self.assertIsNone(tables._findings_line(60, D_PANEL, -1, {}))

    def test_degrades_instead_of_clipping_mid_token(self):
        sev = {"Critical": 1, "High": 2, "Medium": 1, "Low": 0, "Info": 0}
        wide = tables._findings_line(70, D_PANEL, 4, sev)
        self.assertIn("crit", wide.plain)
        narrow = tables._findings_line(14, D_PANEL, 4, sev)
        self.assertLessEqual(cell_len(narrow.plain), 14)
        self.assertTrue(narrow.plain.rstrip().endswith("4"))
        self.assertNotIn("crit", narrow.plain)

    def test_shown_in_stacked_layout_too(self):
        dash = _build()
        dash.finding_count = 2
        dash.severity_counts = {"Critical": 1, "High": 1, "Medium": 0,
                                "Low": 0, "Info": 0}
        text = "\n".join(_plain(_segments(dash, 72, 30)))
        self.assertIn("Findings", text)


class TestRequestRateSparkline(unittest.TestCase):
    """Item 3 — the rate caption carries a trend, but never a fabricated one."""

    def test_no_history_no_sparkline(self):
        self.assertEqual(tables._sparkline([]), "")
        self.assertEqual(tables._sparkline([0.0, 0.0, 0.0]), "")

    def test_trend_is_rendered_from_real_samples(self):
        spark = tables._sparkline([1.0, 2.0, 3.0, 4.0, 5.0])
        self.assertTrue(spark)
        self.assertTrue(set(spark) <= _SPARK_SET)
        self.assertLessEqual(len(spark), 9)
        # a rising trend must end on a taller block than it starts
        self.assertGreater(max(spark), "▁")

    def test_downsamples_long_histories(self):
        spark = tables._sparkline([float(i) for i in range(40)])
        self.assertEqual(len(spark), 9)

    def test_sparkline_appears_in_the_rate_gauge_caption(self):
        dash = _build()
        dash._rps_history.extend([45.0, 40.0, 30.0, 22.0, 18.5])
        text = "\n".join(_plain(_segments(dash, 150, 50)))
        caption = next(ln for ln in text.split("\n") if "req/s" in ln)
        self.assertTrue(set(caption) & _SPARK_SET,
                        f"no sparkline in caption: {caption!r}")

    def test_empty_history_keeps_a_plain_unit(self):
        dash = _build()
        dash._rps_history.clear()
        text = "\n".join(_plain(_segments(dash, 150, 50)))
        caption = next(ln for ln in text.split("\n") if "req/s" in ln)
        self.assertFalse(set(caption) & _SPARK_SET)
        self.assertIn("req/s", caption)


class TestScrollHint(unittest.TestCase):
    """Item 4 — the feed's key bindings are always discoverable."""

    def test_hint_and_scaling_share_the_last_row(self):
        for width in (200, 150, 116, 96, 70, 50, 46, 40):
            last = _plain(_segments(_build(), width, max(20, width // 3)))[-1]
            self.assertIn("SCALING", last, f"no SCALING at width {width}")
            self.assertIn("↑↓/wheel", last, f"no scroll hint at width {width}")
            self.assertTrue(last.rstrip().endswith("●"))

    def test_hint_survives_without_a_tty_listener(self):
        dash = _build()
        self.assertFalse(dash.scroll_enabled)   # harness never starts the listener
        last = _plain(_segments(dash, 150, 50))[-1]
        self.assertIn("↑↓/wheel scroll · End follow", last)

    def test_scrolling_row_is_full_width(self):
        from rich.cells import cell_len as _cl
        for width in (200, 150, 96, 46, 40):
            last = _plain(_segments(_build(), width, 30))[-1]
            self.assertEqual(_cl(last), width)
