"""Dashboard line primitives, widgets, ScanDashboard and table printers.

Split verbatim from the old single-file core/ui/tables.py (no logic
changes). `console` is intentionally NOT imported by name here — every
renderer reads core.ui.styles.console late so tests can redirect it.
"""
from core.ui import styles

import os
import re
import sys
import time
import threading
import collections
from typing import Dict, List, Optional

from rich.live import Live

from ..banner import _PIPELINE_STAGES_BY_MODE
from ..styles import strip_ansi
from .widgets import (_FeedProxy, _MARKER_RE)
from .render import _DashboardRender

_HISTORY_LIMIT = 400
_SCROLL_STEP = 4
_WHEEL_STEP = 2
_MOUSE_ON = "\x1b[?1000h\x1b[?1006h"
_MOUSE_OFF = "\x1b[?1000l\x1b[?1006l"


class ScanDashboard(_DashboardRender):
    """Thread-safe live scanning dashboard using Rich Live.

    Provides a single, continuously-updated terminal panel that replaces
    the default line-by-line scrolling output during active scans.
    All state mutations are guarded by a threading lock and rendering is
    throttled by Rich Live's refresh thread (~15 FPS).
    """

    _instance: Optional["ScanDashboard"] = None

    @classmethod
    def get_instance(cls) -> "ScanDashboard":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def get(cls) -> "ScanDashboard":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def active(cls) -> bool:
        return cls._instance is not None and cls._instance._active

    def __init__(self):
        self._lock = threading.Lock()
        self.target: str = ""
        self.mode: str = ""
        self.version: str = "v1.4.5 - NEXUS"
        self.phase: str = ""
        self.status: str = "STARTING"
        self.current_activity: str = ""
        self.finding_count: int = 0
        self.severity_counts: Dict[str, int] = {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0,
        }
        self.metrics: Dict[str, int] = {
            "Requests": 0,
            "Subdomains": 0,
            "Live Hosts": 0,
            "Endpoints": 0,
            "Parameters": 0,
        }
        self.pipeline: List[Dict[str, str]] = [dict(s) for s in _PIPELINE_STAGES_BY_MODE["FULL"]]
        self.recent_events: collections.deque = collections.deque(maxlen=_HISTORY_LIMIT)
        self.recent_findings: collections.deque = collections.deque(maxlen=5)
        self._rps_history: collections.deque = collections.deque(maxlen=30)
        self._display_pct: float = 0.0
        self._last_completed_count: int = 0
        self.start_time: float = 0.0
        self._live: Optional[Live] = None
        self._active: bool = False

        # activity-feed cursor (absolute event sequence numbers)
        self._event_seq: int = 0
        self._view_anchor: Optional[int] = None   # None → auto-follow newest
        self._render_top_seq: int = 0

        # optional tty key listener for feed scroll-back
        self._input_thread: Optional[threading.Thread] = None
        self._input_stop = threading.Event()
        self._term_fd: Optional[int] = None
        self._term_attrs = None
        self._term_out_fd: Optional[int] = None
        self.scroll_enabled: bool = False

        # stdout/stderr shims active while the dashboard owns the screen
        self._stdout_proxy: Optional[_FeedProxy] = None
        self._stderr_proxy: Optional[_FeedProxy] = None

    # Lifecycle

    def start(self, target: str, mode: str, version: str = ""):
        """Start the live dashboard display."""
        with self._lock:
            self.target = target
            self.mode = mode or "FULL"
            if version:
                self.version = version
            self.start_time = time.time()
            self.status = "STARTING"
            self.finding_count = 0
            self.severity_counts = {
                "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0,
            }
            self.metrics = {
                "Requests": 0,
                "Subdomains": 0,
                "Live Hosts": 0,
                "Endpoints": 0,
                "Parameters": 0,
            }

            mode_key = (mode or "FULL").upper()
            raw_stages = _PIPELINE_STAGES_BY_MODE.get(
                mode_key, _PIPELINE_STAGES_BY_MODE["FULL"])

            self.pipeline = [dict(s) for s in raw_stages]
            if self.pipeline:
                self.pipeline[0]["status"] = "active"
                self.pipeline[0]["detail"] = "initializing..."

            self.recent_events.clear()
            self.recent_findings.clear()
            self._rps_history.clear()
            self._display_pct = 0.0
            self._last_completed_count = 0
            self._event_seq = 0
            self._view_anchor = None
            self._render_top_seq = 0
            self.phase = "STARTING"
            self._append_event_locked(f"Starting scan on {target}", "cyan", "info")
            self._append_event_locked("Initializing modules...", "cyan", "info")

        if not self._active:
            # Non-tty (output di-redirect ke file/pipe): Live transient
            # MENGHAPUS frame sebelumnya dari stream — semua log fase
            # (ph/i/w) hilang dari file log (verified: run testfire.log
            # hanya menyisakan ~248 baris terakhir). Tanpa Live, print
            # biasa mengalir utuh ke log; panel live cukup di terminal.
            if not getattr(styles.console, "is_terminal", False):
                return
            # screen=True → alternate screen buffer: the dashboard is a fixed
            # canvas; terminal scrollback (mouse wheel) can no longer push it
            # away and no frame is left behind when the scan ends.
            self._live = Live(
                get_renderable=self._build_layout,
                console=styles.console,
                refresh_per_second=15,
                transient=True,
                screen=True,
                redirect_stdout=False,
                redirect_stderr=False,
            )
            self._live.start()
            self._active = True
            self._install_feed_proxy()
            self._start_scroll_listener()

    def _install_feed_proxy(self):
        """Route stray stdout/stderr lines into the activity feed."""
        if self._stdout_proxy is not None:
            return
        dash = self
        stdout_proxy = _FeedProxy(
            sys.stdout, lambda line: dash.log_event(line, "white", kind="info"))
        stderr_proxy = _FeedProxy(
            sys.stderr, lambda line: dash.log_warning(line))
        sys.stdout = stdout_proxy
        sys.stderr = stderr_proxy
        self._stdout_proxy = stdout_proxy
        self._stderr_proxy = stderr_proxy

    def _uninstall_feed_proxy(self):
        """Flush and remove the stdout/stderr shims (idempotent)."""
        for name in ("_stdout_proxy", "_stderr_proxy"):
            proxy = getattr(self, name)
            if proxy is None:
                continue
            try:
                proxy.flush()
            except Exception:
                pass
            stream = "stdout" if name == "_stdout_proxy" else "stderr"
            if getattr(sys, stream) is proxy:
                setattr(sys, stream, proxy.rich_proxied_file)
            setattr(self, name, None)

    def stop(self, status: str = "COMPLETED"):
        """Stop the live dashboard."""
        if not self._active:
            return
        with self._lock:
            self.status = status
            self._active = False
            for stage in self.pipeline:
                if stage["status"] == "active":
                    stage["status"] = "completed"
            if status == "COMPLETED" and self.pipeline:
                self.pipeline[-1]["status"] = "completed"
                self.pipeline[-1]["detail"] = "report generated"

        self._uninstall_feed_proxy()
        self._stop_scroll_listener()

        if self._live:
            try:
                self._live.stop()
            except Exception:
                pass
            self._live = None

    # Optional scroll-back controller --------------------------------------
    #
    # The feed keeps a long history; ↑/↓/PageUp/PageDn walk backwards through
    # it and `End` re-arms auto-follow.  Enabled only for an interactive POSIX
    # tty, every step is best-effort, and the original terminal attributes are
    # always restored (also via the daemon thread exiting on stop).

    def _start_scroll_listener(self):
        if os.name != "posix" or self._input_thread is not None:
            return
        try:
            import termios
            import tty
            if not sys.stdin.isatty():
                return
            fd = sys.stdin.fileno()
            attrs = termios.tcgetattr(fd)
            tty.setcbreak(fd)
        except Exception:
            return
        self._term_fd = fd
        self._term_attrs = attrs
        self.scroll_enabled = True
        try:
            self._term_out_fd = sys.stdout.fileno()
        except Exception:
            self._term_out_fd = 1
        try:
            # SGR mouse tracking: wheel events arrive as \x1b[<64/65;x;yM
            os.write(self._term_out_fd, _MOUSE_ON.encode())
        except Exception:
            self._term_out_fd = None
        self._input_stop.clear()
        thread = threading.Thread(target=self._input_loop, daemon=True,
                                  name="verdamt-scroll")
        self._input_thread = thread
        thread.start()

    def _stop_scroll_listener(self):
        thread = self._input_thread
        self._input_thread = None
        self._input_stop.set()
        if self._term_out_fd is not None:
            try:
                os.write(self._term_out_fd, _MOUSE_OFF.encode())
            except Exception:
                pass
            self._term_out_fd = None
        if self._term_fd is not None:
            try:
                import termios
                termios.tcsetattr(self._term_fd, termios.TCSAFLUSH, self._term_attrs)
            except Exception:
                pass
            self._term_fd = None
            self._term_attrs = None
        self.scroll_enabled = False
        if thread is not None:
            thread.join(timeout=0.6)

    def _input_loop(self):
        try:
            import select
        except Exception:
            return
        while not self._input_stop.is_set():
            fd = self._term_fd
            if fd is None:
                break
            try:
                readable, _, _ = select.select([fd], [], [], 0.25)
                if not readable:
                    continue
                data = os.read(fd, 64).decode("utf-8", "ignore")
            except Exception:
                break
            if data:
                try:
                    self._handle_keys(data)
                except Exception:
                    pass

    _KEY_RE = re.compile(
        r"\x1b\[<[0-9;]*[Mm]"          # SGR mouse report (wheel/click)
        r"|\x1b\[[0-9;]*[A-Za-z~]"     # CSI key or sequence
        r"|\x1bO[A-Z]"                 # SS3 application cursor keys
        r"|\x1b.")

    def _handle_keys(self, data: str):
        for key in self._KEY_RE.findall(data):
            if key in ("\x1b[A", "\x1bOA"):
                self.scroll_events(-_SCROLL_STEP)
            elif key in ("\x1b[B", "\x1bOB"):
                self.scroll_events(_SCROLL_STEP)
            elif key == "\x1b[5~":
                self.scroll_events(-_SCROLL_STEP * 4)
            elif key == "\x1b[6~":
                self.scroll_events(_SCROLL_STEP * 4)
            elif key in ("\x1b[F", "\x1b[4~", "\x1b[1~", "\x1b[H"):
                self.scroll_events(0)
            elif key.startswith("\x1b[<"):
                m = re.match(r"\x1b\[<(\d+);", key)
                if not m:
                    continue
                btn = int(m.group(1))
                if btn & 64 and not btn & 32:      # 64=wheel-up, 65=wheel-down
                    self.scroll_events(
                        _WHEEL_STEP if btn & 1 else -_WHEEL_STEP)

    def scroll_events(self, delta: int):
        """Move the activity-feed cursor; 0 re-arms auto-follow."""
        with self._lock:
            newest = self._event_seq
            if delta == 0:
                self._view_anchor = None
                return
            if not self.recent_events:
                return
            oldest = newest - len(self.recent_events) + 1
            if self._view_anchor is None:
                if delta > 0:
                    return                       # already at the newest events
                top = self._render_top_seq or oldest
                if self._render_top_seq and top <= oldest:
                    return                       # whole history already visible
            else:
                top = self._view_anchor
            anchor = top + delta
            if anchor >= newest - 1:
                self._view_anchor = None
            else:
                self._view_anchor = max(oldest, anchor)

    # State mutations

    def _append_event_locked(self, text: str, style: str, kind: str):
        clean = _MARKER_RE.sub("", strip_ansi(text)).strip()
        if not clean:
            clean = strip_ansi(text).strip() or "…"
        self.recent_events.append((clean, style, time.time(), kind))
        self._event_seq += 1

    def _find_stage_index(self, keywords: tuple) -> int:
        for idx, stage in enumerate(self.pipeline):
            s_name = stage["name"].lower()
            if any(k in s_name for k in keywords):
                return idx
        return -1

    def mark_stage_status(self, status: str, *keywords):
        """Force a stage status (mis. fase kondisional = "skipped").

        Only touches pending/active stages so a finished stage is never
        rewritten retroactively.
        """
        with self._lock:
            idx = self._find_stage_index(tuple(keywords))
            if idx != -1 and self.pipeline[idx]["status"] in ("pending", "active"):
                self.pipeline[idx]["status"] = status
        self._throttled_refresh()

    def _update_pipeline_from_phase(self, phase_name: str):
        p_lower = phase_name.lower()
        target_idx = -1

        for idx, stage in enumerate(self.pipeline):
            s_name = stage["name"].lower()
            if s_name in p_lower or p_lower in s_name:
                target_idx = idx
                break

        if target_idx == -1:
            if any(k in p_lower for k in ("surface", "phase 0")):
                target_idx = self._find_stage_index(("surface",))
            elif any(k in p_lower for k in ("subfinder", "subdomain")):
                target_idx = self._find_stage_index(("subfinder",))
            elif any(k in p_lower for k in ("httpx", "probing")):
                target_idx = self._find_stage_index(("httpx", "probing"))
            elif any(k in p_lower for k in ("origin", "waf risk", "waf detected")):
                target_idx = self._find_stage_index(("waf", "origin"))
            elif any(k in p_lower for k in ("katana", "crawl", "link")):
                target_idx = self._find_stage_index(("katana", "crawler", "link", "crawl"))
            elif any(k in p_lower for k in ("browser", "spa")):
                target_idx = self._find_stage_index(("browser", "spa", "app deep"))
            elif any(k in p_lower for k in ("param", "arjun", "discovery")):
                target_idx = self._find_stage_index(("param", "parameter", "discovery"))
            elif any(k in p_lower for k in ("gau", "wayback", "osint", "dork", "takeover", "js", "secret", "recon intel", "phase 1")):
                target_idx = self._find_stage_index(("recon", "intel", "gau", "takeover", "dork", "js", "secret", "baseline"))
            elif any(k in p_lower for k in ("app", "phase 2")):
                target_idx = self._find_stage_index(("app", "dom", "api"))
            elif any(k in p_lower for k in ("nuclei", "dalfox", "assault", "vuln", "injection", "phase 3")):
                target_idx = self._find_stage_index(("nuclei", "dalfox", "injection", "vulnerability", "assault"))
            elif any(k in p_lower for k in ("poison", "smuggled", "smuggling", "cache", "directory", "auth", "exhaust", "flood")):
                target_idx = self._find_stage_index(("cache", "smuggling", "directory", "auth", "exhaust", "oob", "flood", "poison"))
            elif any(k in p_lower for k in ("sqli", "extract", "phase 4.5")):
                target_idx = self._find_stage_index(("sqli", "extraction"))
            elif any(k in p_lower for k in ("verify", "confirm", "phase 4")):
                target_idx = self._find_stage_index(("verify", "verification"))
            elif any(k in p_lower for k in ("report", "summary", "phase 5", "complete")):
                target_idx = self._find_stage_index(("report", "reporter"))

        if target_idx != -1 and target_idx < len(self.pipeline):
            for i in range(target_idx):
                if self.pipeline[i]["status"] in ("pending", "active"):
                    self.pipeline[i]["status"] = "completed"
            self.pipeline[target_idx]["status"] = "active"
            # Hanya satu stage "active": fase yang melompat ke indeks lebih
            # awal (mis. Seed Crawl setelah POISON MODE) tidak meninggalkan
            # stage lama menyala.
            for j in range(target_idx + 1, len(self.pipeline)):
                if self.pipeline[j]["status"] == "active":
                    self.pipeline[j]["status"] = "pending"
            if not self.pipeline[target_idx]["detail"]:
                self.pipeline[target_idx]["detail"] = "running..."
            self.status = "SCANNING"

    def log_event(self, text: str, style: str = "white", kind: Optional[str] = None):
        with self._lock:
            clean_text = strip_ansi(text)

            # Auto metric parsing from logs
            sub_m = re.search(r"(\d+)\s+subdomains?", clean_text, re.I)
            if sub_m:
                count = int(sub_m.group(1))
                self.metrics["Subdomains"] = count
                idx = self._find_stage_index(("subfinder", "subdomain"))
                if idx != -1:
                    self.pipeline[idx]["detail"] = f"{count} subdomains"

            host_m = re.search(r"(\d+)\s+(?:live\s+)?(?:hosts|services)", clean_text, re.I)
            if host_m:
                count = int(host_m.group(1))
                self.metrics["Live Hosts"] = count
                idx = self._find_stage_index(("httpx", "probing"))
                if idx != -1:
                    self.pipeline[idx]["detail"] = f"{count} live hosts"

            ep_m = re.search(r"(\d+)\s+(?:urls?|endpoints?)", clean_text, re.I)
            if ep_m and ep_m.group(1):
                count = int(ep_m.group(1))
                self.metrics["Endpoints"] = count
                idx = self._find_stage_index(("katana", "crawler", "link", "crawl", "recon", "extraction"))
                if idx != -1:
                    self.pipeline[idx]["detail"] = f"{count} endpoints"

            self._append_event_locked(clean_text, style, kind or "info")
        self._throttled_refresh()

    def log_finding(self, severity: str, title: str, url: str = ""):
        with self._lock:
            self.finding_count += 1
            if severity in self.severity_counts:
                self.severity_counts[severity] += 1

            for stage in self.pipeline:
                if stage["status"] == "active":
                    stage["detail"] = f"{self.finding_count} findings"
                    break

            if severity in ("Critical", "High"):
                kind = "crit"
            elif severity in ("Medium", "Low"):
                kind = "mile"
            else:
                kind = "info"
            msg = f"{severity} · {title}"
            if url:
                msg = f"{msg} · {url}"
            self._append_event_locked(msg, "white", kind)
            self.recent_findings.append({
                "severity": severity,
                "title": title,
                "url": url,
                "time": time.time(),
            })
        self._throttled_refresh()

    def set_phase(self, phase: str):
        with self._lock:
            self.phase = phase
            self._update_pipeline_from_phase(phase)
        self._throttled_refresh()

    def set_activity(self, activity: str):
        with self._lock:
            self.current_activity = activity
        self._throttled_refresh()

    def log_warning(self, text: str):
        with self._lock:
            self._append_event_locked(strip_ansi(text), "yellow", "warn")
        self._throttled_refresh()

    def log_error(self, text: str):
        with self._lock:
            self._append_event_locked(strip_ansi(text), "red", "fail")
        self._throttled_refresh()

    # Rendering

    def _throttled_refresh(self):
        # Rendering is handled by Rich Live's background refresh thread.
        pass

    # ── header ─────────────────────────────────────────────────────────────
