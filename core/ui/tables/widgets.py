"""Dashboard line primitives, widgets, ScanDashboard and table printers.

Split verbatim from the old single-file core/ui/tables.py (no logic
changes). `console` is intentionally NOT imported by name here — every
renderer reads core.ui.styles.console late so tests can redirect it.
"""

import io
import math
import re
import time

from rich.cells import cell_len
from rich.text import Text

from ..styles import D_BORDER, D_CRIT, D_DIM, D_ELEV, D_EMERALD, D_GOLD, D_INFO, D_PANEL, D_TEXT, D_WARN
from .text import _LOGO_ROWS, LOGO_W, _blank, _clip_cells, _fit, _wrap


def _logo_rows(rows: int = 3, background: str = D_PANEL) -> list[Text]:
    out: list[Text] = []
    for spec in _LOGO_ROWS[:max(0, rows)]:
        t = Text(no_wrap=True, end="")
        cells = {idx: (ch, col) for idx, ch, col in spec}
        for i in range(LOGO_W):
            ch, col = cells.get(i, (" ", None))
            t.append(ch, f"{col} on {background}" if col else f"on {background}")
        out.append(t)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Recent Activity feed
# ─────────────────────────────────────────────────────────────────────────────

_LEVELS: dict[str, dict[str, str]] = {
    "info": {"label": "[INFO]", "fg": D_INFO, "ind": "▶", "ind_fg": D_EMERALD, "body": D_INFO},
    "ok":   {"label": "[ OK ]", "fg": D_EMERALD, "ind": "●", "ind_fg": D_EMERALD, "body": D_TEXT},
    "mile": {"label": "[FIND]", "fg": D_GOLD, "ind": "◆", "ind_fg": D_GOLD, "body": D_TEXT},
    "warn": {"label": "[WARN]", "fg": D_WARN, "ind": "▲", "ind_fg": D_WARN, "body": D_WARN},
    "fail": {"label": "[FAIL]", "fg": D_CRIT, "ind": "✕", "ind_fg": D_CRIT, "body": D_CRIT},
    "crit": {"label": "[CRIT]", "fg": D_CRIT, "ind": "✕", "ind_fg": D_CRIT, "body": D_CRIT},
}

_HL_RE = re.compile(
    r"(?P<stage>stage\s+\d+\s*/\s*\d+)"
    r"|(?P<ratio>\b\d+\s*/\s*\d+\b)"
    r"|(?P<pct>\d+(?:\.\d+)?\s*%)"
    r"|(?P<rate>\b\d+(?:\.\d+)?\s*req/s\b)"
    r"|(?P<clock>\b\d{1,2}:\d{2}(?::\d{2})?\b)"
    r"|(?P<count>\b\d+(?:\.\d+)?\s+(?:subdomains?|domains?|targets?|hosts?|services?"
    r"|urls?|endpoints?|params?|parameters?|requests?|findings?|pages?|found|loaded)\b)",
    re.IGNORECASE,
)
_GOLD_TOKENS = {"stage", "ratio", "pct"}
_MARKER_RE = re.compile(r"^[❯ℹ✔✓⚠✖✕⚡!]+\s*")


def _styled_message(msg: str, base: str, background: str = D_PANEL) -> Text:
    out = Text(no_wrap=True, end="")
    pos = 0
    for m in _HL_RE.finditer(msg):
        if m.start() > pos:
            out.append(msg[pos:m.start()], f"{base} on {background}")
        colour = D_GOLD if m.lastgroup in _GOLD_TOKENS else D_EMERALD
        out.append(m.group(0), f"{colour} on {background}")
        pos = m.end()
    if pos < len(msg):
        out.append(msg[pos:], f"{base} on {background}")
    if not out.plain:
        out.append(" ", f"on {background}")
    return out


def _event_lines(ev: tuple, total_w: int, background: str = D_PANEL) -> list[Text]:
    """Render one activity event into one or more exactly-fitted lines."""
    text = ev[0]
    ts = ev[2]
    kind = ev[3] if len(ev) > 3 else None
    meta = _LEVELS.get(kind or "", None) or _LEVELS["info"]
    stamp = time.strftime("%H:%M:%S", time.localtime(ts))

    head = Text(no_wrap=True, end="")
    head.append(f"[{stamp}] ", f"{D_DIM} on {background}")
    head.append(f"{meta['ind']} ", f"{meta['ind_fg']} on {background}")
    head.append(f"{meta['label']} ", f"{meta['fg']} on {background}")
    head_w = cell_len(head.plain)

    msg_w = max(8, total_w - head_w)
    body_lines = _wrap(_styled_message(text, meta["body"], background), msg_w)

    out: list[Text] = []
    for i, piece in enumerate(body_lines):
        row = Text(no_wrap=True, end="")
        if i == 0:
            row.append_text(head)
        else:
            row.append(" " * head_w, f"on {background}")
        row.append_text(piece)
        out.append(_fit(row, total_w, background))
    return out or [_blank(total_w, background)]


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline
# ─────────────────────────────────────────────────────────────────────────────

_STAGE_BADGE = {
    "completed": ("✓ COMPLETED", D_EMERALD),
    "active":    ("● RUNNING", D_WARN),
    "failed":    ("✕ FAILED", D_CRIT),
    "skipped":   ("— SKIPPED", D_DIM),
    "pending":   ("○ PENDING", D_DIM),
}


def _stage_rows(stages: list[dict[str, str]], width: int, background: str,
                now: float, active_detail: str, spacing: int = 0,
                start_index: int = 0) -> list[Text]:
    if not stages or width < 24:
        return []
    badge_w = max(cell_len(v[0]) for v in
                  (_STAGE_BADGE.get(s.get("status", "pending"), _STAGE_BADGE["pending"])
                   for s in stages))
    counter_w = 6
    for s in stages:
        d = (s.get("detail") or "").strip()
        if d:
            counter_w = max(counter_w, min(16, cell_len(d) + 1))
    name_w = width - 4 - 2 - badge_w - 2 - counter_w
    if name_w < 12:
        counter_w = max(0, counter_w - (12 - name_w))
        name_w = width - 4 - 2 - badge_w - 2 - counter_w
    if name_w < 8:
        name_w = max(6, width - 4 - 2 - badge_w - 2)
        counter_w = 0

    rows: list[Text] = []
    for idx, stage in enumerate(stages, start=start_index + 1):
        status = stage.get("status", "pending")
        name = stage.get("name", "")
        detail = (stage.get("detail") or "").strip()
        if status == "active" and active_detail:
            detail = active_detail
        b_label, b_colour = _STAGE_BADGE.get(status, _STAGE_BADGE["pending"])
        num_colour = {"completed": D_EMERALD, "active": D_WARN,
                      "failed": D_CRIT}.get(status, D_DIM)
        paint = f"on {background}"

        line = Text(no_wrap=True, end="")
        line.append(f"{idx:02d}", f"{num_colour} on {background}")
        line.append("  ", paint)
        name_style = {"completed": D_TEXT, "active": f"bold {D_TEXT}",
                      "failed": f"bold {D_CRIT}", "skipped": D_DIM}.get(status, D_DIM)
        line.append_text(_fit(Text(name, style=name_style, no_wrap=True, end=""),
                              name_w, background))
        line.append("  ", paint)

        pill = Text(no_wrap=True, end="")
        pill.append(b_label, f"{b_colour} on {D_ELEV}")
        pill.append(" " * max(0, badge_w - cell_len(b_label)), f"on {D_ELEV}")
        line.append_text(pill)

        if counter_w:
            line.append("  ", paint)
            counter = detail if detail else "—"
            ctext = _clip_cells(Text(counter, no_wrap=True, end=""), counter_w)
            line.append(" " * max(0, counter_w - cell_len(ctext.plain)), paint)
            line.append_text(ctext)
        rows.append(_fit(line, width, background))

        # progress row
        indent = max(0, min(4, width - max(6, width - 4)))
        bar_w = max(4, width - indent)
        bar = Text(no_wrap=True, end="")
        bar.append(" " * indent, paint)
        if status == "completed":
            bar.append("━" * bar_w, f"{D_EMERALD} on {background}")
        elif status == "skipped":
            bar.append("━" * bar_w, f"{D_DIM} on {background}")
        elif status == "failed":
            bar.append("░" * bar_w, f"{D_CRIT} on {background}")
        elif status == "active":
            pct_match = re.search(r"(\d+(?:\.\d+)?)\s*%", detail)
            if pct_match:
                frac = max(0.0, min(1.0, float(pct_match.group(1)) / 100.0))
                filled = round(bar_w * frac)
                bar.append("━" * filled, f"{D_GOLD} on {background}")
                bar.append("─" * (bar_w - filled), f"{D_BORDER} on {background}")
            else:
                # unknown sub-progress → indeterminate sweep (never fakes a %)
                seg = max(3, bar_w // 4)
                span = max(1, bar_w - seg)
                pos = int(now * 2) % (span + 1)
                bar.append("─" * pos, f"{D_BORDER} on {background}")
                bar.append("━" * seg, f"{D_GOLD} on {background}")
                bar.append("─" * max(0, bar_w - pos - seg), f"{D_BORDER} on {background}")
        else:
            bar.append("─" * bar_w, f"{D_BORDER} on {background}")
        rows.append(_fit(bar, width, background))
        # spacer rows only *between* stages, so N stages cost 2N + (N-1) lines
        if spacing and idx < len(stages):
            for _ in range(spacing):
                rows.append(_blank(width, background))
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Semicircular gauges / lightweight meters
# ─────────────────────────────────────────────────────────────────────────────

GAUGE_W = 17
GAUGE_H = 6


def _gauge(value: str, label: str, caption_parts: list[tuple[str, str]],
           fraction: float, colour: str, background: str = D_PANEL) -> list[Text]:
    """Compact semicircular gauge on a fixed 17x6 grid.

    row 0        metric label
    rows 1-4     arc — a two-cell-thick ring (filled = value, track = muted
                 border).  Every sampled arc cell gets one inward neighbour so
                 the stroke reads as a solid band instead of a dotted line.
    row 5        caption parts (sparkline + unit, or stage context)
    The measured value is overlaid inside the arc mouth.
    """
    if not math.isfinite(fraction):
        fraction = 0.0
    fraction = max(0.0, min(1.0, fraction))
    grid: list[list[tuple[str, str | None]]] = [
        [(" ", None) for _ in range(GAUGE_W)] for _ in range(GAUGE_H)
    ]

    cx, cy, rx, ry = 8.4, 4.6, 8.3, 3.2
    cells: list[tuple[int, int]] = []
    seen = set()
    step = 0.25
    i = 0
    while i <= 180.0 / step:
        theta = math.radians(180.0 - i * step)
        col = int(cx + rx * math.cos(theta))
        row = int(cy - ry * math.sin(theta))
        # outer cell + its inward neighbour (radial thickness ≈ 2 cells)
        for r, c in ((row, col), (row + 1, col) if row <= 3
                     else (row, col - 1 if col < cx else col + 1)):
            if 0 <= r < GAUGE_H and 0 <= c < GAUGE_W and (r, c) not in seen:
                seen.add((r, c))
                cells.append((r, c))
        i += 1

    filled = round(fraction * len(cells))
    for n, (row, col) in enumerate(cells):
        grid[row][col] = ("█", colour if n < filled else D_BORDER)

    def _overlay(row: int, text: str, style: str):
        start = (GAUGE_W - cell_len(text)) // 2
        for j, ch in enumerate(text):
            pos = start + j
            if 0 <= pos < GAUGE_W:
                grid[row][pos] = (ch, style)

    def _overlay_parts(row: int, parts: list[tuple[str, str]]):
        pos = (GAUGE_W - sum(cell_len(t) for t, _ in parts)) // 2
        for text, style in parts:
            for j, ch in enumerate(text):
                at = pos + j
                if 0 <= at < GAUGE_W:
                    grid[row][at] = (ch, style)
            pos += cell_len(text)

    _overlay(0, label, D_TEXT)
    _overlay(3, value, D_TEXT)
    _overlay_parts(GAUGE_H - 1, caption_parts or [(" ", D_DIM)])

    rows: list[Text] = []
    for row in grid:
        t = Text(no_wrap=True, end="")
        for ch, style in row:
            t.append(ch, f"{style} on {background}" if style else f"on {background}")
        rows.append(t)
    return rows


_SPARK_BLOCKS = ("▁", "▂", "▃", "▄", "▅", "▆", "▇", "█")


def _sparkline(values: list[float], buckets: int = 9) -> str:
    """Down-sample `values` into `buckets` averages and map them to blocks.

    Returns "" when there is no traffic yet, so the caption never shows a
    fabricated trend.
    """
    if not values:
        return ""
    if len(values) > buckets:
        size = len(values) / buckets
        sampled = []
        for i in range(buckets):
            lo, hi = int(i * size), max(int(i * size) + 1, int((i + 1) * size))
            chunk = values[lo:hi]
            sampled.append(sum(chunk) / len(chunk))
    else:
        sampled = list(values)
    peak = max(sampled)
    if peak <= 0:
        return ""
    return "".join(_SPARK_BLOCKS[max(0, min(7, int(v / peak * 7)))] for v in sampled)


_SEV_ORDER = (
    ("Critical", "crit", D_CRIT),
    ("High", "high", D_CRIT),
    ("Medium", "med", D_GOLD),
    ("Low", "low", D_WARN),
    ("Info", "info", D_INFO),
)


def _findings_line(width: int, background: str, findings: int,
                   sev: dict[str, int]) -> Text | None:
    """One-line findings summary, or None when there is nothing to report.

    Only non-zero severities are rendered, and the line degrades to
    `Findings  N` rather than being clipped mid-token.
    """
    if findings <= 0:
        return None
    bits = [(sev.get(key, 0), label, colour)
            for key, label, colour in _SEV_ORDER if sev.get(key, 0)]
    total_colour = D_CRIT if (sev.get("Critical", 0) or sev.get("High", 0)) else (
        D_GOLD if (sev.get("Medium", 0) or sev.get("Low", 0)) else D_INFO)

    def build(with_breakdown: bool) -> Text:
        t = Text(no_wrap=True, end="")
        t.append("Findings", f"{D_TEXT} on {background}")
        t.append("  ", f"on {background}")
        t.append(str(findings), f"bold {total_colour} on {background}")
        if with_breakdown:
            for count, label, colour in bits:
                t.append("   ", f"on {background}")
                t.append(str(count), f"{colour} on {background}")
                t.append(f" {label}", f"{D_DIM} on {background}")
        return t

    line = build(True)
    if cell_len(line.plain) > width:
        line = build(False)
    return _fit(line, width, background)


def _bar_meter(label: str, value: str, fraction: float, colour: str,
               width: int, background: str = D_PANEL) -> Text:
    """Lightweight horizontal meter for widths where gauges do not fit."""
    if not math.isfinite(fraction):
        fraction = 0.0
    fraction = max(0.0, min(1.0, fraction))
    label_w = min(16, max(cell_len(label) + 1, 12))
    value_w = cell_len(value) + 1
    track_w = max(6, width - label_w - value_w - 3)
    filled = round(track_w * fraction)
    t = Text(no_wrap=True, end="")
    t.append(label.ljust(label_w), f"{D_DIM} on {background}")
    t.append("[", f"{D_BORDER} on {background}")
    t.append("━" * filled, f"{colour} on {background}")
    t.append("─" * (track_w - filled), f"{D_BORDER} on {background}")
    t.append("] ", f"{D_BORDER} on {background}")
    t.append(value, f"{D_TEXT} on {background}")
    return t


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────────────────────────────────────


class _FeedProxy(io.TextIOBase):
    """stdout/stderr shim used while the dashboard owns the alternate screen.

    Rich's own ``Live`` redirect funnels plain ``print()`` above the live
    frame, which scrolls the canvas and lets stray lines escape the panel.
    This proxy instead turns every complete line into a dashboard feed event
    so all output stays inside the dashboard.  ``rich_proxied_file`` keeps
    ``Console.print`` (tables, panels) pointed at the real terminal.
    """

    def __init__(self, wrapped, emit):
        self._wrapped = wrapped
        self._emit = emit
        self._buf: list[str] = []
        self.rich_proxied_file = wrapped

    # ── TextIO surface ────────────────────────────────────────────────────

    def write(self, text):
        if not isinstance(text, str):
            raise TypeError(
                f"write() argument must be str, not {type(text).__name__}")
        if not text:
            return 0
        parts = text.split("\n")
        for part in parts[:-1]:
            line = "".join(self._buf) + part
            self._buf.clear()
            self._emit_line(line)
        if parts[-1]:
            self._buf.append(parts[-1])
        return len(text)

    def flush(self):
        if self._buf:
            line = "".join(self._buf)
            self._buf.clear()
            self._emit_line(line)

    def _emit_line(self, line: str):
        if "\r" in line:                      # progress-style overwrite
            line = line.rsplit("\r", 1)[-1]
        line = line.strip()
        if not line:
            return
        if "[" in line:                       # stray print() often carries
            try:                              # Rich markup (e.g. "[bold]..")
                line = Text.from_markup(line).plain.strip() or line
            except Exception:
                pass
        try:
            self._emit(line)
        except Exception:
            pass

    def close(self):
        # Never close the real stream: only flush what is still pending.
        try:
            self.flush()
        except Exception:
            pass

    def isatty(self):
        return self._wrapped.isatty()

    def fileno(self):
        return self._wrapped.fileno()

    def writable(self):
        return True

    @property
    def encoding(self):
        return getattr(self._wrapped, "encoding", "utf-8")

    @property
    def errors(self):
        return getattr(self._wrapped, "errors", "strict")

    @property
    def name(self):
        return getattr(self._wrapped, "name", "<feed>")


