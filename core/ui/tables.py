"""tables — verbatim split from ui.py (no logic changes)."""
import os
import sys
import time
import re
import math
import random
import threading
import collections
from typing import Dict, List, Optional, Tuple

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TaskID
from rich.live import Live
from rich.layout import Layout
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule
from rich.cells import cell_len
from rich import box

from .banner import _PIPELINE_STAGES_BY_MODE
from .styles import C, G, R, Y, _CHECK, _DIAMOND, _TARGET, console, strip_ansi
from .styles import (D_BG, D_PANEL, D_ELEV, D_EMERALD, D_TEAL, D_GOLD, D_GOLD_SOFT,
                     D_TEXT, D_DIM, D_INFO, D_WARN, D_CRIT, D_BORDER)

# ─────────────────────────────────────────────────────────────────────────────
# Line primitives — every dashboard line is a single, exactly-sized Text so the
# composed screen never overflows the terminal (desktop *or* mobile widths).
# ─────────────────────────────────────────────────────────────────────────────

_HISTORY_LIMIT = 400
_SCROLL_STEP = 4


def _blank(width: int, background: str = D_BG) -> Text:
    t = Text(no_wrap=True, end="")
    if width > 0:
        t.append(" " * width, f"on {background}")
    return t


def _clip_cells(t: Text, width: int) -> Text:
    """Hard-clip a Text to `width` terminal cells (keeps styles)."""
    out = Text(no_wrap=True, end="")
    used = 0
    for seg in t.render(console):
        if seg.control or not seg.text:
            continue
        seg_w = cell_len(seg.text)
        if used + seg_w <= width:
            out.append(seg.text, seg.style)
            used += seg_w
            continue
        take = width - used
        if take > 0:
            buf, acc = "", 0
            for ch in seg.text:
                cw = cell_len(ch)
                if acc + cw > take:
                    break
                buf += ch
                acc += cw
            if buf:
                out.append(buf, seg.style)
        break
    return out


def _fit(t: Text, width: int, background: str = D_PANEL) -> Text:
    """Pad or truncate a single-line Text so it is exactly `width` cells."""
    if width <= 0:
        return Text(no_wrap=True, end="")
    if cell_len(t.plain) > width:
        t = _clip_cells(t, width)
    n = cell_len(t.plain)
    if n < width:
        t.append(" " * (width - n), f"on {background}")
    return t


def _take_cells(s: str, n: int) -> Tuple[str, str]:
    out = ""
    acc = 0
    for ch in s:
        cw = cell_len(ch)
        if acc + cw > n:
            break
        out += ch
        acc += cw
    return out, s[len(out):]


def _wrap(t: Text, width: int) -> List[Text]:
    """Word-wrap a single-line styled Text into lines of at most `width` cells."""
    if width <= 0:
        return [Text("", end="")]
    if cell_len(t.plain) <= width:
        return [t]

    tokens: List[Tuple[str, object]] = []
    for seg in t.render(console):
        if seg.control or not seg.text:
            continue
        parts = seg.text.split(" ")
        for idx, part in enumerate(parts):
            if idx > 0:
                tokens.append((" ", seg.style))
            if part:
                tokens.append((part, seg.style))

    lines: List[Text] = []
    cur = Text(no_wrap=True, end="")
    cur_w = 0

    def _flush():
        nonlocal cur, cur_w
        lines.append(cur)
        cur = Text(no_wrap=True, end="")
        cur_w = 0

    for tok, style in tokens:
        w = cell_len(tok)
        if cur_w + w <= width:
            cur.append(tok, style)
            cur_w += w
            continue
        if not tok.strip():
            if cur_w:
                _flush()
            continue
        if cur_w:
            _flush()
        rest = tok
        while cell_len(rest) > width:
            head, rest = _take_cells(rest, width)
            lines.append(Text(head, style=style, end="", no_wrap=True))
        if rest:
            cur.append(rest, style)
            cur_w = cell_len(rest)
    if cur.plain or not lines:
        lines.append(cur)
    return lines


def _center_height(lines: List[Text], height: int, width: int,
                   background: str = D_PANEL) -> List[Text]:
    """Vertically centre a block inside `height` rows (pads both sides)."""
    if len(lines) >= height:
        return lines[:height]
    pad = (height - len(lines)) // 2
    return _fit_height([_blank(width, background) for _ in range(pad)] + lines,
                       height, width, background)


def _fit_height(lines: List[Text], height: int, width: int,
                background: str = D_PANEL) -> List[Text]:
    if len(lines) > height:
        return lines[:height]
    return lines + [_blank(width, background) for _ in range(height - len(lines))]


def _frame(lines: List[Text], width: int, height: int, title: str = "",
           badge: Optional[Text] = None, background: str = D_PANEL,
           border: str = D_BORDER, pad_x: int = 1) -> List[Text]:
    """Wrap content in a rounded panel occupying exactly `height` lines."""
    if height <= 0:
        return []
    if height == 1:
        return [_fit(_blank(width, background), width, background)]
    inner = width - 2
    if inner < 4:
        return _fit_height([_blank(width, background)], height, width, background)

    bstyle = f"{border} on {background}"
    paint = f"on {background}"
    content_w = max(1, inner - 2 * pad_x)
    body = [_fit(ln, content_w, background) for ln in lines[:max(0, height - 2)]]
    body = _fit_height(body, height - 2, content_w, background)

    out: List[Text] = []

    # ── top border: title left, status badge right ──
    top = Text(no_wrap=True, end="")
    top.append("╭", bstyle)
    t_w = cell_len(title) if title else 0
    b_w = cell_len(badge.plain) if badge is not None else 0
    k = -1
    if title and badge is not None:
        k = inner - 6 - t_w - b_w
    elif title:
        k = inner - 3 - t_w
    elif badge is not None:
        k = inner - 3 - b_w

    if k >= 1:
        if title:
            top.append("─ ", bstyle)
            top.append(title, f"bold {D_TEXT} on {background}")
            top.append(" ", paint)
            top.append("─" * k, bstyle)
        else:
            top.append("─" * (k + 1), bstyle)
        if badge is not None:
            top.append(" ", paint)
            top.append_text(badge)
            top.append(" ", paint)
            top.append("─", bstyle)
    elif badge is not None and b_w + 4 <= inner:
        room = inner - b_w - 4
        top.append("─" * room, bstyle)
        top.append(" ", paint)
        top.append_text(badge)
        top.append(" ", paint)
        top.append("─", bstyle)
    else:
        top.append("─" * inner, bstyle)
    top.append("╮", bstyle)
    out.append(_fit(top, width, background))

    for line in body:
        row = Text(no_wrap=True, end="")
        row.append("│", bstyle)
        row.append(" " * pad_x, paint)
        row.append_text(line)
        row.append(" " * pad_x, paint)
        row.append("│", bstyle)
        out.append(_fit(row, width, background))

    bot = Text(no_wrap=True, end="")
    bot.append("╰", bstyle)
    bot.append("─" * inner, bstyle)
    bot.append("╯", bstyle)
    out.append(_fit(bot, width, background))
    return out


def _hstack(left: List[Text], right: List[Text], left_w: int, right_w: int,
            gap: int) -> List[Text]:
    n = max(len(left), len(right))
    out: List[Text] = []
    g = " " * gap if gap > 0 else ""
    for i in range(n):
        row = Text(no_wrap=True, end="")
        row.append_text(left[i] if i < len(left) else _blank(left_w, D_BG))
        if g:
            row.append(g, f"on {D_BG}")
        row.append_text(right[i] if i < len(right) else _blank(right_w, D_BG))
        out.append(_fit(row, left_w + gap + right_w, D_BG))
    return out


def _blank_line(width: int) -> Text:
    return _blank(width, D_BG)


# ─────────────────────────────────────────────────────────────────────────────
# Brand mark — compact V emblem, emerald left stroke / metallic-gold right.
# ─────────────────────────────────────────────────────────────────────────────

_LOGO_ROWS = [
    ((0, "⊕", D_TEAL), (1, "╲", D_EMERALD), (6, "╱", D_GOLD)),
    ((2, "╲", D_EMERALD), (4, "▲", D_GOLD), (5, "╱", D_GOLD)),
    ((3, "╲", D_EMERALD), (4, "╱", D_GOLD)),
]
LOGO_W = 7


def _logo_rows(rows: int = 3, background: str = D_PANEL) -> List[Text]:
    out: List[Text] = []
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

_LEVELS: Dict[str, Dict[str, str]] = {
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


def _event_lines(ev: Tuple, total_w: int, background: str = D_PANEL) -> List[Text]:
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

    out: List[Text] = []
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


def _stage_rows(stages: List[Dict[str, str]], width: int, background: str,
                now: float, active_detail: str, spacing: int = 0,
                start_index: int = 0) -> List[Text]:
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

    rows: List[Text] = []
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
                filled = int(round(bar_w * frac))
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


def _gauge(value: str, label: str, caption_parts: List[Tuple[str, str]],
           fraction: float, colour: str, background: str = D_PANEL) -> List[Text]:
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
    grid: List[List[Tuple[str, Optional[str]]]] = [
        [(" ", None) for _ in range(GAUGE_W)] for _ in range(GAUGE_H)
    ]

    cx, cy, rx, ry = 8.4, 4.6, 8.3, 3.2
    cells: List[Tuple[int, int]] = []
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

    filled = int(round(fraction * len(cells)))
    for n, (row, col) in enumerate(cells):
        grid[row][col] = ("█", colour if n < filled else D_BORDER)

    def _overlay(row: int, text: str, style: str):
        start = (GAUGE_W - cell_len(text)) // 2
        for j, ch in enumerate(text):
            pos = start + j
            if 0 <= pos < GAUGE_W:
                grid[row][pos] = (ch, style)

    def _overlay_parts(row: int, parts: List[Tuple[str, str]]):
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

    rows: List[Text] = []
    for row in grid:
        t = Text(no_wrap=True, end="")
        for ch, style in row:
            t.append(ch, f"{style} on {background}" if style else f"on {background}")
        rows.append(t)
    return rows


_SPARK_BLOCKS = ("▁", "▂", "▃", "▄", "▅", "▆", "▇", "█")


def _sparkline(values: List[float], buckets: int = 9) -> str:
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
                   sev: Dict[str, int]) -> Optional[Text]:
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
    filled = int(round(track_w * fraction))
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


class ScanDashboard:
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
        self.event_count: int = 0
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
        self._flash_until: float = 0.0
        self.warning_count: int = 0
        self.error_count: int = 0
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
        self.scroll_enabled: bool = False

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
            self.event_count = 0
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
            self._flash_until = 0.0
            self._event_seq = 0
            self._view_anchor = None
            self._render_top_seq = 0
            self.warning_count = 0
            self.error_count = 0
            self.phase = "STARTING"
            self._append_event_locked(f"Starting scan on {target}", "cyan", "info")
            self._append_event_locked("Initializing modules...", "cyan", "info")

        if not self._active:
            # Non-tty (output di-redirect ke file/pipe): Live transient
            # MENGHAPUS frame sebelumnya dari stream — semua log fase
            # (ph/i/w) hilang dari file log (verified: run testfire.log
            # hanya menyisakan ~248 baris terakhir). Tanpa Live, print
            # biasa mengalir utuh ke log; panel live cukup di terminal.
            if not getattr(console, "is_terminal", False):
                return
            self._live = Live(
                get_renderable=self._build_layout,
                console=console,
                refresh_per_second=15,
                transient=True,
            )
            self._live.start()
            self._active = True
            self._start_scroll_listener()

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
        self._input_stop.clear()
        thread = threading.Thread(target=self._input_loop, daemon=True,
                                  name="verdamt-scroll")
        self._input_thread = thread
        thread.start()

    def _stop_scroll_listener(self):
        thread = self._input_thread
        self._input_thread = None
        self._input_stop.set()
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

    def _handle_keys(self, data: str):
        for key in re.findall(r"\x1b\[[0-9;]*[A-Za-z~]|\x1b.", data):
            if key == "\x1b[A":
                self.scroll_events(-_SCROLL_STEP)
            elif key == "\x1b[B":
                self.scroll_events(_SCROLL_STEP)
            elif key == "\x1b[5~":
                self.scroll_events(-_SCROLL_STEP * 4)
            elif key == "\x1b[6~":
                self.scroll_events(_SCROLL_STEP * 4)
            elif key in ("\x1b[F", "\x1b[4~", "\x1b[1~", "\x1b[H"):
                self.scroll_events(0)

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
                top = self._render_top_seq or oldest
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
                target_idx = self._find_stage_index(("katana", "crawler", "link"))
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
                target_idx = self._find_stage_index(("cache", "smuggling", "directory", "auth", "exhaust", "oob", "flood"))
            elif any(k in p_lower for k in ("verify", "confirm", "phase 4")):
                target_idx = self._find_stage_index(("verify", "verification"))
            elif any(k in p_lower for k in ("sqli", "extract", "phase 4.5")):
                target_idx = self._find_stage_index(("sqli", "extraction"))
            elif any(k in p_lower for k in ("report", "summary", "phase 5", "complete")):
                target_idx = self._find_stage_index(("report", "reporter"))

        if target_idx != -1 and target_idx < len(self.pipeline):
            for i in range(target_idx):
                if self.pipeline[i]["status"] in ("pending", "active"):
                    self.pipeline[i]["status"] = "completed"
            self.pipeline[target_idx]["status"] = "active"
            if not self.pipeline[target_idx]["detail"]:
                self.pipeline[target_idx]["detail"] = "running..."
            self.status = "SCANNING"

    def log_event(self, text: str, style: str = "white", kind: Optional[str] = None):
        with self._lock:
            self.event_count += 1
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
                idx = self._find_stage_index(("katana", "crawler", "link", "recon", "extraction"))
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
            self.warning_count += 1
            self._append_event_locked(strip_ansi(text), "yellow", "warn")
        self._throttled_refresh()

    def log_error(self, text: str):
        with self._lock:
            self.error_count += 1
            self._append_event_locked(strip_ansi(text), "red", "fail")
        self._throttled_refresh()

    # Rendering

    def _throttled_refresh(self):
        # Rendering is handled by Rich Live's background refresh thread.
        pass

    def _fmt_elapsed(self) -> str:
        elapsed = time.time() - self.start_time
        mins = int(elapsed) // 60
        secs = int(elapsed) % 60
        return f"{mins:02d}:{secs:02d}"

    # ── header ─────────────────────────────────────────────────────────────

    def _build_header(self, width: int, target: str, mode: str, status: str,
                      elapsed: str, logo_rows: int) -> List[Text]:
        """Header content lines: V emblem + wordmark + status/target/mode/elapsed."""
        bg = D_PANEL
        height = logo_rows
        rows = [Text(no_wrap=True, end="") for _ in range(height)]

        if status in ("STARTING", "SCANNING"):
            status_text, status_colour = "● RUNNING", D_EMERALD
        elif status == "COMPLETED":
            status_text, status_colour = "✓ DONE", D_EMERALD
        else:
            status_text, status_colour = "✕ FAILED", D_CRIT

        wordmark = "VERDAMT-SNIPE"
        subtitle = "RECON · SCAN · EXPLOIT"
        logo = _logo_rows(logo_rows, bg)
        brand_x = LOGO_W + 2

        blocks: List[Tuple[str, str, str, int]] = [
            ("◎", "Target", target, max(14, min(34, cell_len(target) + 2))),
            ("◈", "Mode", (mode or "—").upper(), max(10, len(mode or "—") + 4)),
            ("◔", "Elapsed", elapsed, 10),
        ]
        pill_w = cell_len(status_text) + 4

        def _group_width(items) -> int:
            if not items:
                return 0
            return sum(b[3] for b in items) + (len(items) - 1) + pill_w + 1

        room = width - brand_x - 2
        chosen = list(blocks)
        while chosen and _group_width(chosen) > room:
            chosen.pop()

        items: List[Tuple[int, Text, Text]] = []   # ordered left → right
        if _group_width(chosen) <= room:
            pill_inner = cell_len(status_text) + 2
            p0 = Text(no_wrap=True, end="")
            p0.append("╭─", f"{status_colour} on {D_ELEV}")
            p0.append(status_text, f"bold {status_colour} on {D_ELEV}")
            p0.append("─╮", f"{status_colour} on {D_ELEV}")
            p1 = Text(no_wrap=True, end="")
            p1.append("╰" + "─" * pill_inner + "╯", f"{status_colour} on {D_ELEV}")
            x = width
            for idx, (icon, label, value, bw) in enumerate(reversed(chosen)):
                if idx:
                    x -= 1
                l0 = Text(no_wrap=True, end="")
                l0.append(f"{icon} ", f"{D_TEAL} on {bg}")
                l0.append(label, f"{D_DIM} on {bg}")
                l1 = Text(no_wrap=True, end="")
                l1.append("  ", f"on {bg}")
                l1.append(value, f"{D_TEXT} on {bg}")
                if cell_len(l1.plain) > bw:
                    l1 = _clip_cells(l1, bw)
                x -= bw
                items.append((x, _fit(l0, bw, bg), _fit(l1, bw, bg)))
            x -= 1
            x -= pill_w
            items.append((x, p0, p1))
            items.reverse()      # pill first, then Target / Mode / Elapsed
        else:
            s = Text(no_wrap=True, end="")
            s.append(status_text, f"bold {status_colour} on {bg}")
            x = max(brand_x, width - cell_len(s.plain))
            items.append((x, _fit(s, cell_len(s.plain), bg), _blank(cell_len(s.plain), bg)))

        for i in range(height):
            line = rows[i]
            if i < len(logo):
                line.append_text(logo[i])
            else:
                line.append(" " * LOGO_W, f"on {bg}")
            line.append("  ", f"on {bg}")

            if i == 0:
                line.append(wordmark, f"bold {D_GOLD_SOFT} on {bg}")
            elif i == 1:
                for seg in subtitle:
                    line.append(seg, f"{D_TEAL} on {bg}" if seg == "·"
                                else f"{D_DIM} on {bg}")

            used = cell_len(line.plain)
            for bx, l0, l1 in items:
                if bx <= used:
                    continue
                line.append(" " * (bx - used), f"on {bg}")
                line.append_text(l0 if i == 0 else l1 if i == 1 else _blank(cell_len(l0.plain), bg))
                used = cell_len(line.plain)

            rows[i] = _fit(line, width, bg)
        return rows

    # ── activity feed ──────────────────────────────────────────────────────

    def _build_activity(self, width: int, height: int, events: List[Tuple],
                        seq: int, anchor: Optional[int]) -> Tuple[List[Text], int]:
        if width <= 0 or height <= 0:
            return [], seq
        if not events:
            return [_blank(width, D_PANEL) for _ in range(height)], seq

        oldest = seq - len(events) + 1
        budget = height
        chosen: List[Tuple[int, int, int]] = []   # (seq, idx, lines)

        if anchor is None:
            for i in range(len(events) - 1, -1, -1):
                lines = _event_lines(events[i], width, D_PANEL)
                if sum(c for _, _, c in chosen) + len(lines) > budget:
                    break
                chosen.append((seq - len(events) + 1 + i, i, len(lines)))
            chosen.reverse()
        else:
            start = max(0, min(len(events) - 1, anchor - oldest))
            for i in range(start, len(events)):
                lines = _event_lines(events[i], width, D_PANEL)
                if sum(c for _, _, c in chosen) + len(lines) > budget:
                    break
                chosen.append((seq - len(events) + 1 + i, i, len(lines)))

        out: List[Text] = []
        for _, idx, _c in chosen:
            out.extend(_event_lines(events[idx], width, D_PANEL))
        top_seq = chosen[0][0] if chosen else seq
        with self._lock:
            self._render_top_seq = top_seq
        return _fit_height(out, height, width, D_PANEL), top_seq

    def _activity_badge(self, status: str, hidden_older: int) -> Text:
        if hidden_older > 0:
            text, colour = f"▲ {hidden_older} EARLIER", D_GOLD
        elif status in ("STARTING", "SCANNING"):
            text, colour = "● LIVE", D_EMERALD
        elif status == "COMPLETED":
            text, colour = "✓ DONE", D_EMERALD
        else:
            text, colour = "✕ FAILED", D_CRIT
        t = Text(no_wrap=True, end="")
        t.append(text, f"bold {colour} on {D_ELEV}")
        return t

    # ── pipeline window ────────────────────────────────────────────────────

    def _pipeline_window(self, stages: List[Dict[str, str]], height: int):
        """Return (visible stages, start index, spacer rows between stages)."""
        if not stages:
            return [], 0, 0
        visible_n = max(1, min(len(stages), height // 2))
        spacing = 1 if visible_n * 3 - 1 <= height else 0
        if visible_n >= len(stages):
            return list(stages), 0, spacing
        active_idx = next((i for i, s in enumerate(stages) if s["status"] == "active"), 0)
        start = max(0, min(active_idx - (visible_n // 2), len(stages) - visible_n))
        return stages[start:start + visible_n], start, spacing

    # ── tooling / metrics ──────────────────────────────────────────────────

    def _build_metrics(self, width: int, height: int, rps: float, rps_frac: float,
                       pct: float, stage_num: int, total_stages: int, target: str,
                       metrics: Dict[str, int], findings: int = 0,
                       sev: Optional[Dict[str, int]] = None,
                       rps_hist: Optional[List[float]] = None) -> List[Text]:
        if width <= 0 or height <= 0:
            return []
        bg = D_PANEL
        findings_row = _findings_line(width, bg, findings, sev or {})
        targets = [t for t in re.split(r"[\s,]+", (target or "").strip()) if t]
        n_targets = len(targets)
        target_val = (f"{n_targets} domain" if n_targets == 1
                      else f"{n_targets} domains" if n_targets else "—")
        stage_caption = f"Stage {stage_num}/{total_stages}"

        if width >= 44 and height >= 6:
            left_w = GAUGE_W * 2 + 1
            list_w = max(12, width - left_w - 1)
            spark = _sparkline(rps_hist or [])
            rate_caption = ([(spark, D_EMERALD), ("  req/s", D_DIM)] if spark
                            else [("req/s", D_DIM)])
            rate = _gauge(f"{rps:.1f}", "Request Rate", rate_caption,
                          rps_frac, D_EMERALD, bg)
            prog = _gauge(f"{pct:.1f}%", "Progress", [(stage_caption, D_DIM)],
                          pct / 100.0, D_GOLD, bg)
            gauges = [_hstack([rate[i]], [prog[i]], GAUGE_W, GAUGE_W, 1)[0]
                      for i in range(GAUGE_H)]

            items = [("◎", "Targets", target_val),
                     ("◈", "Subdomains", str(metrics.get("Subdomains", 0))),
                     ("⊙", "Endpoints", str(metrics.get("Endpoints", 0)))]
            listing: List[Text] = []
            for icon, label, value in items:
                l0 = Text(no_wrap=True, end="")
                l0.append(f"{icon} ", f"{D_TEAL} on {bg}")
                l0.append(label, f"{D_TEXT} on {bg}")
                listing.append(_fit(l0, list_w, bg))
                l1 = Text(no_wrap=True, end="")
                l1.append("  ", f"on {bg}")
                l1.append(value, f"{D_EMERALD} on {bg}")
                listing.append(_fit(l1, list_w, bg))

            # the gauge/list block owns 6 rows; anything left over (there is
            # always >= 1 on a desktop panel) becomes the findings summary
            reserve = 1 if (findings_row is not None and height > GAUGE_H) else 0
            block_h = height - reserve
            left = _center_height([_fit(g, left_w, bg) for g in gauges],
                                  block_h, left_w, bg)
            listing = _center_height(listing, block_h, list_w, bg)
            merged = [_hstack([left[i]], [listing[i]], left_w, list_w, 1)[0]
                      for i in range(block_h)]
            if reserve:
                merged.append(findings_row)
            return _fit_height(merged, height, width, bg)

        # Lightweight fallback for widths where gauges do not fit.
        # Every line is word-wrapped (never clipped mid-token) and the block
        # degrades gracefully as the panel gets shorter.
        subs = str(metrics.get("Subdomains", 0))
        eps = str(metrics.get("Endpoints", 0))

        def _counts(long_labels: bool) -> List[Text]:
            pairs = ([("Targets", target_val), ("Subdomains", subs), ("Endpoints", eps)]
                     if long_labels else
                     [("Targets", target_val), ("Subs", subs), ("Eps", eps)])
            sep = "  ·  " if long_labels else " · "
            line = Text(no_wrap=True, end="")
            for idx, (label, value) in enumerate(pairs):
                if idx:
                    line.append(sep, f"{D_DIM} on {bg}")
                line.append(f"{label} ", f"{D_TEXT} on {bg}")
                line.append(value, f"{D_EMERALD} on {bg}")
            return _wrap(line, width)

        rows: List[Text] = []
        if height >= 5:
            rows.append(_bar_meter("Request Rate", f"{rps:.1f} req/s", rps_frac,
                                   D_EMERALD, width, bg))
            rows.append(_bar_meter("Progress", f"{pct:.1f}% · {stage_caption}",
                                   pct / 100.0, D_GOLD, width, bg))
        else:
            head = Text(no_wrap=True, end="")
            head.append(f"{rps:.1f} req/s", f"{D_TEXT} on {bg}")
            head.append("  ·  ", f"{D_DIM} on {bg}")
            head.append(f"{pct:.1f}%", f"{D_GOLD} on {bg}")
            head.append("  ·  ", f"{D_DIM} on {bg}")
            head.append(stage_caption, f"{D_TEXT} on {bg}")
            rows.extend(_wrap(head, width))

        remaining = height - len(rows)
        counts = _counts(remaining >= 3)
        if remaining >= 1 and len(counts) > remaining:
            counts = _counts(False)
        rows.extend(counts)
        if findings_row is not None and len(rows) < height:
            rows.append(findings_row)
        return _fit_height([_fit(r, width, bg) for r in rows], height, width, bg)

    # ── SCALING strip ──────────────────────────────────────────────────────

    def _scaling_line(self, width: int) -> Text:
        """Bottom strip: brand hatch + scroll hint on the left, SCALING right.

        The hint documents the feed's key bindings, so it is rendered
        unconditionally; the connector length and the decoration degrade as
        the terminal narrows.
        """
        core_w = 4 + len(" SCALING ") + 1      # ╱╱╱╱ + label + dot

        def _tail(dashes: int) -> Text:
            t = Text(no_wrap=True, end="")
            if dashes:
                t.append("━" * dashes, f"{D_GOLD} on {D_BG}")
            t.append("╱" * 4, f"bold {D_GOLD} on {D_BG}")
            t.append(" SCALING ", f"bold {D_GOLD} on {D_BG}")
            t.append("●", f"{D_GOLD_SOFT} on {D_BG}")
            return t

        def _head(parts: List[Tuple[str, str]]) -> Text:
            t = Text(no_wrap=True, end="")
            for text, style in parts:
                t.append(text, f"{style} on {D_BG}" if style else f"on {D_BG}")
            return t

        candidates = [
            _head([("╱" * 3, D_GOLD), ("   ", D_TEXT),
                   ("↑↓ scroll · End follow", D_DIM)]),
            _head([("↑↓ scroll · End follow", D_DIM)]),
            _head([("╱" * 3, D_GOLD), ("   ", D_TEXT), ("↑↓ scroll", D_DIM)]),
            _head([("↑↓ scroll", D_DIM)]),
            _head([("╱" * 3, D_GOLD)]),
            _head([]),
        ]
        for head in candidates:
            head_w = cell_len(head.plain)
            base = head_w + (2 if head_w else 0)      # 2-cell gutter
            dashes = width - base - core_w
            if dashes < 4:
                continue
            row = Text(no_wrap=True, end="")
            row.append_text(head)
            if head_w:
                row.append("  ", f"on {D_BG}")
            if dashes > 24:
                row.append(" " * (dashes - 24), f"on {D_BG}")
            row.append_text(_tail(min(dashes, 24)))
            return _fit(row, width, D_BG)
        return _fit(_tail(max(4, width - core_w)), width, D_BG)

    # ── main compose ───────────────────────────────────────────────────────

    def _build_layout(self):
        """Compose the live dashboard: header / activity / pipeline / metrics."""
        with self._lock:
            snap_target = self.target
            snap_mode = self.mode
            snap_status = self.status
            snap_start = self.start_time
            snap_metrics = self.metrics.copy()
            snap_pipeline = [dict(stg) for stg in self.pipeline]
            snap_events = list(self.recent_events)
            snap_activity = self.current_activity
            snap_seq = self._event_seq
            snap_findings = self.finding_count
            snap_sev = self.severity_counts.copy()
            snap_anchor = self._view_anchor

            completed = sum(1 for s in snap_pipeline if s["status"] in ("completed", "skipped"))
            active = sum(1 for s in snap_pipeline if s["status"] == "active")
            total_stages = len(snap_pipeline) or 1
            if completed > self._last_completed_count:
                self._last_completed_count = completed
                self._flash_until = time.monotonic() + 1.5
            if snap_status == "COMPLETED":
                target_pct = 100.0
            elif snap_status in ("ERROR", "FAILED"):
                target_pct = completed / total_stages * 100.0
            else:
                target_pct = (completed + (0.5 if active else 0.0)) / total_stages * 100.0
            self._display_pct += (target_pct - self._display_pct) * 0.25
            display_pct = self._display_pct
            rps_history = list(self._rps_history)

            reqs = snap_metrics.get("Requests", 0)
            now = time.time()
            elapsed = max(now - snap_start, 0.0)
            if snap_status in ("STARTING", "SCANNING"):
                rps = reqs / max(elapsed, 0.1)
                self._rps_history.append(rps)
                rps_history.append(rps)

        mins, secs = int(elapsed) // 60, int(elapsed) % 60
        elapsed_str = f"{mins:02d}:{secs:02d}"
        rps = (reqs / max(elapsed, 0.1)) if reqs else 0.0
        peak = max(rps_history) if rps_history else 0.0
        rps_frac = (rps / peak) if peak > 0 else 0.0
        stage_num = min(total_stages, completed + (1 if active else 0))

        # ── geometry ───────────────────────────────────────────────────────
        size = console.size
        tw = max(40, int(size.width))
        th = max(12, int(size.height))
        desktop = tw >= 116 and th >= 18
        micro = tw < 64 or th < 13

        header_h = 4 if micro else 5
        if desktop:
            body_h = th - (1 + header_h + 1 + 1 + 1 + 1)
        else:
            body_h = th - (header_h + 1 + 1 + 1)
        body_h = max(4, body_h)

        def outer(row: Text) -> Text:
            r = Text(no_wrap=True, end="")
            r.append("│", f"{D_BORDER} on {D_BG}")
            r.append_text(row)
            r.append("│", f"{D_BORDER} on {D_BG}")
            return _fit(r, tw, D_BG)

        lines: List[Text] = []

        if desktop:
            t = Text(no_wrap=True, end="")
            t.append("╭", f"{D_BORDER} on {D_BG}")
            t.append("─" * (tw - 2), f"{D_BORDER} on {D_BG}")
            t.append("╮", f"{D_BORDER} on {D_BG}")
            lines.append(t)

        panel_w = (tw - 2) if desktop else tw
        content_w = panel_w - 4      # _frame: 2 border cells + pad_x=1 each side

        # ── header panel ──
        logo_rows = header_h - 2
        header_content = self._build_header(content_w, snap_target, snap_mode,
                                            snap_status, elapsed_str, logo_rows)
        header_panel = _frame(header_content, panel_w, header_h)
        if desktop:
            for row in header_panel:
                lines.append(outer(row))
            lines.append(outer(_blank_line(panel_w)))
        else:
            lines.extend(header_panel)
            lines.append(_blank_line(tw))

        # ── body ──
        if desktop:
            act_w = max(36, int((panel_w - 2) * 0.53))
            right_w = panel_w - act_w - 2
            n_stages = len(snap_pipeline)
            # 2 rows per stage + one spacer *between* stages  →  3N + 1
            ideal_pipe = n_stages * 3 + 1
            min_met = 9                     # 7 content rows: gauge/list + summary
            if ideal_pipe + min_met <= body_h:
                pipe_h = ideal_pipe
            else:
                pipe_h = max(4, min(n_stages * 2 + 2, body_h - min_met))
            if body_h >= 10 and body_h - pipe_h < 6:
                pipe_h = max(2, body_h - 6)  # never let the metrics panel collapse
            met_h = body_h - pipe_h

            act_lines, top_seq = self._build_activity(act_w - 4, body_h - 2,
                                                       snap_events, snap_seq, snap_anchor)
            oldest = snap_seq - len(snap_events) + 1 if snap_events else snap_seq
            hidden = max(0, top_seq - oldest)
            act_panel = _frame(act_lines, act_w, body_h, title="RECENT ACTIVITY",
                               badge=self._activity_badge(snap_status, hidden))

            visible, _start, spacing = self._pipeline_window(snap_pipeline, pipe_h - 2)
            stage_active = any(s["status"] == "active" for s in snap_pipeline)
            pipe_lines = _stage_rows(visible, right_w - 4, D_PANEL, now,
                                     snap_activity if stage_active else "",
                                     spacing=spacing,
                                     start_index=_start)
            pipe_panel = _frame(pipe_lines, right_w, pipe_h, title="PIPELINE")

            met_lines = self._build_metrics(right_w - 4, met_h - 2, rps, rps_frac,
                                            display_pct, stage_num, total_stages,
                                            snap_target, snap_metrics,
                                            findings=snap_findings,
                                            sev=snap_sev,
                                            rps_hist=rps_history)
            met_panel = _frame(met_lines, right_w, met_h, title="TOOLING / METRICS")

            right = pipe_panel + met_panel   # Pipeline above, Tooling / Metrics below
            body = _hstack(act_panel, right, act_w, right_w, 2)
            for row in _fit_height(body, body_h, panel_w, D_BG):
                lines.append(outer(row))

            b = Text(no_wrap=True, end="")
            b.append("╰", f"{D_BORDER} on {D_BG}")
            b.append("─" * (tw - 2), f"{D_BORDER} on {D_BG}")
            b.append("╯", f"{D_BORDER} on {D_BG}")
            lines.append(b)
            lines.append(_blank_line(tw))
        else:
            n_stages = len(snap_pipeline)
            avail = max(4, body_h - (1 if body_h >= 16 else 0))
            act_h = max(4, avail // 2)
            rest = avail - act_h

            pieces: List[Text] = []
            act_lines, top_seq = self._build_activity(tw - 4, act_h - 2,
                                                       snap_events, snap_seq, snap_anchor)
            oldest = snap_seq - len(snap_events) + 1 if snap_events else snap_seq
            hidden = max(0, top_seq - oldest)
            pieces.extend(_frame(act_lines, tw, act_h, title="RECENT ACTIVITY",
                                 badge=self._activity_badge(snap_status, hidden)))

            pipe_h2 = met_h2 = 0
            if rest >= 8:
                pipe_h2 = max(4, rest - 6)   # reserve >= 6 rows for the metrics
                met_h2 = rest - pipe_h2
            elif rest >= 4:
                pipe_h2, met_h2 = rest, 0

            if pipe_h2 >= 4:
                pieces.append(_blank_line(tw))
                visible, _start, spacing = self._pipeline_window(snap_pipeline, pipe_h2 - 2)
                stage_active = any(s["status"] == "active" for s in snap_pipeline)
                pipe_lines = _stage_rows(visible, tw - 4, D_PANEL, now,
                                         snap_activity if stage_active else "",
                                         spacing=spacing,
                                         start_index=_start)
                pieces.extend(_frame(pipe_lines, tw, pipe_h2, title="PIPELINE"))
            if met_h2 >= 4:
                pieces.append(_blank_line(tw))
                met_lines = self._build_metrics(tw - 4, met_h2 - 2, rps, rps_frac,
                                                display_pct, stage_num, total_stages,
                                                snap_target, snap_metrics,
                                                findings=snap_findings,
                                                sev=snap_sev,
                                                rps_hist=rps_history)
                pieces.extend(_frame(met_lines, tw, met_h2, title="TOOLING / METRICS"))

            lines.extend(_fit_height(pieces, body_h, tw, D_BG))
            lines.append(_blank_line(tw))

        lines.append(self._scaling_line(tw))
        final = [_fit(ln, tw, D_BG) for ln in _fit_height(lines, th, tw, D_BG)]
        for row in final:
            row.end = "\n"
        return Group(*final)


def draw_box(title, lines, color=None):
    """Draw a labeled box with content lines using rich."""
    c = "cyan"
    if color == G: c = "green"
    elif color == R: c = "red"
    elif color == Y: c = "yellow"
    elif color == C: c = "cyan"

    text = "\n".join(lines)
    panel = Panel(
        Text.from_ansi(text),
        title=f"[bold white] {_DIAMOND} {title} [/]",
        title_align="left",
        border_style=c,
        expand=False,
        padding=(1, 3),
        box=box.HEAVY
    )
    console.print(panel)


def draw_table(headers, rows, padding=2, title=None):
    """Animated table rendering with premium styling."""
    if not rows: return
    table = Table(
        title=f" {_TARGET} {title} " if title else None,
        title_style="bold white",
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        box=box.SIMPLE_HEAVY,
        row_styles=["", "dim"],
        padding=(0, 2),
        show_lines=False,
    )
    for h in headers:
        table.add_column(h)

    for i, r in enumerate(rows):
        table.add_row(*[Text.from_ansi(str(x)) for x in r])

    console.print(table)


def progress_bar(iterable, total=0, prefix='', length=30):
    """Simple progress bar wrapping an iterable using rich.

    When a ScanDashboard is active, yields items normally but routes
    progress updates through the dashboard instead of creating a
    separate Rich Progress bar.
    """
    if not total:
        total = 100 # fallback

    if ScanDashboard.active():
        dashboard = ScanDashboard.get()
        count = 0
        for item in iterable:
            yield item
            count += 1
            if count % max(1, total // 50) == 0 or count == total:
                dashboard.set_activity(f"{prefix} {count}/{total}")
        dashboard.set_activity("")
        dashboard.log_event(f"{_CHECK} {prefix} {total}/{total}", "green", kind="ok")
    else:
        with Progress(
            SpinnerColumn(spinner_name="dots", style="magenta"),
            TextColumn(f"  [bright_black]{prefix}[/]"),
            BarColumn(bar_width=length, complete_style="cyan", finished_style="green"),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Working", total=total)
            for item in iterable:
                yield item
                progress.update(task, advance=1)

        console.print(f"  [bold green]{_CHECK}[/] [bright_black]{prefix}[/] [white]{total}/{total}[/]")
