"""Dashboard line primitives, widgets, ScanDashboard and table printers.

Split verbatim from the old single-file core/ui/tables.py (no logic
changes). `console` is intentionally NOT imported by name here — every
renderer reads core.ui.styles.console late so tests can redirect it.
"""
import re
import time

from rich.cells import cell_len
from rich.console import Group
from rich.text import Text

from core.ui import styles

from ..styles import (
    D_BG,
    D_BORDER,
    D_CRIT,
    D_DIM,
    D_ELEV,
    D_EMERALD,
    D_GOLD,
    D_GOLD_SOFT,
    D_INFO,
    D_PANEL,
    D_TEAL,
    D_TEXT,
)
from .text import (
    _SCROLLBAR_W,
    LOGO_W,
    _blank,
    _blank_line,
    _center_height,
    _clip_cells,
    _fit,
    _fit_height,
    _frame,
    _hstack,
    _wrap,
)
from .widgets import (
    GAUGE_H,
    GAUGE_W,
    _bar_meter,
    _event_lines,
    _findings_line,
    _gauge,
    _logo_rows,
    _sparkline,
    _stage_rows,
)


class _DashboardRender:
    """Rendering half of ScanDashboard (header/activity/metrics/layout).

    Kept as a mixin so the state half in dashboard.py stays untouched.
    """

    def _build_header(self, width: int, target: str, mode: str, status: str,
                      elapsed: str, logo_rows: int) -> list[Text]:
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

        blocks: list[tuple[str, str, str, int]] = [
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

        items: list[tuple[int, Text, Text]] = []   # ordered left → right
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

    def _build_activity(self, width: int, height: int, events: list[tuple],
                        seq: int, anchor: int | None) -> tuple[list[Text], int]:
        if width <= 0 or height <= 0:
            return [], seq
        if not events:
            return [_blank(width, D_PANEL) for _ in range(height)], seq

        content_w = max(8, width - _SCROLLBAR_W)
        oldest = seq - len(events) + 1
        budget = height
        chosen: list[tuple[int, int, int]] = []   # (seq, idx, lines)

        if anchor is None:
            for i in range(len(events) - 1, -1, -1):
                lines = _event_lines(events[i], content_w, D_PANEL)
                if sum(c for _, _, c in chosen) + len(lines) > budget:
                    break
                chosen.append((seq - len(events) + 1 + i, i, len(lines)))
            chosen.reverse()
        else:
            start = max(0, min(len(events) - 1, anchor - oldest))
            for i in range(start, len(events)):
                lines = _event_lines(events[i], content_w, D_PANEL)
                if sum(c for _, _, c in chosen) + len(lines) > budget:
                    break
                chosen.append((seq - len(events) + 1 + i, i, len(lines)))

        out: list[Text] = []
        visible_idx: list[int] = []
        for _, idx, _c in chosen:
            out.extend(_event_lines(events[idx], content_w, D_PANEL))
            visible_idx.append(idx)
        top_seq = chosen[0][0] if chosen else seq
        with self._lock:
            self._render_top_seq = top_seq

        body = _fit_height(out, height, content_w, D_PANEL)
        bar = self._activity_scrollbar(height, len(events), visible_idx, anchor)
        rows: list[Text] = []
        for i in range(height):
            row = Text(no_wrap=True, end="")
            row.append_text(body[i])
            ch, style = bar[i]
            row.append(ch, style)
            rows.append(_fit(row, width, D_PANEL))
        return rows, top_seq

    def _activity_scrollbar(self, height: int, total: int,
                            visible_idx: list[int],
                            anchor: int | None) -> list[tuple[str, str]]:
        """One (char, style) cell per row describing the feed scroll position.

        Drawn only while part of the history sits outside the window; the
        thumb is gold on auto-follow and informational blue once the view is
        parked on older events.
        """
        blank = (" ", f"on {D_PANEL}")
        cells = [blank for _ in range(max(0, height))]
        if total <= 0 or height <= 0 or not visible_idx:
            return cells
        top, bottom = visible_idx[0], visible_idx[-1]
        if top <= 0 and bottom >= total - 1:
            return cells                       # whole history on screen
        span = max(1, bottom - top + 1)
        thumb_h = max(1, min(height, round(height * span / total)))
        travel = total - span
        pos = 0 if travel <= 0 else round(top / travel * (height - thumb_h))
        pos = max(0, min(height - thumb_h, pos))
        thumb_style = (f"bold {D_GOLD} on {D_PANEL}" if anchor is None
                       else f"bold {D_INFO} on {D_PANEL}")
        track_style = f"{D_BORDER} on {D_PANEL}"
        for i in range(height):
            if pos <= i < pos + thumb_h:
                cells[i] = ("█", thumb_style)
            else:
                cells[i] = ("░", track_style)
        return cells

    def _activity_badge(self, status: str, hidden_older: int,
                        following: bool = True) -> Text:
        if not following:
            text, colour = "↕ SCROLLED · End", D_INFO
        elif hidden_older > 0:
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

    def _pipeline_window(self, stages: list[dict[str, str]], height: int):
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
                       metrics: dict[str, int], findings: int = 0,
                       sev: dict[str, int] | None = None,
                       rps_hist: list[float] | None = None) -> list[Text]:
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
            listing: list[Text] = []
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

        def _counts(long_labels: bool) -> list[Text]:
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

        rows: list[Text] = []
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

        def _head(parts: list[tuple[str, str]]) -> Text:
            t = Text(no_wrap=True, end="")
            for text, style in parts:
                t.append(text, f"{style} on {D_BG}" if style else f"on {D_BG}")
            return t

        candidates = [
            _head([("╱" * 3, D_GOLD), ("   ", D_TEXT),
                   ("↑↓/wheel scroll · End follow", D_DIM)]),
            _head([("↑↓/wheel scroll · End follow", D_DIM)]),
            _head([("╱" * 3, D_GOLD), ("   ", D_TEXT),
                   ("↑↓/wheel · End", D_DIM)]),
            _head([("↑↓/wheel · End", D_DIM)]),
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
            self._last_completed_count = max(self._last_completed_count, completed)
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
        size = styles.console.size
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

        lines: list[Text] = []

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
                               badge=self._activity_badge(snap_status, hidden,
                                                          snap_anchor is None))

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

            pieces: list[Text] = []
            act_lines, top_seq = self._build_activity(tw - 4, act_h - 2,
                                                       snap_events, snap_seq, snap_anchor)
            oldest = snap_seq - len(snap_events) + 1 if snap_events else snap_seq
            hidden = max(0, top_seq - oldest)
            pieces.extend(_frame(act_lines, tw, act_h, title="RECENT ACTIVITY",
                                 badge=self._activity_badge(snap_status, hidden,
                                                            snap_anchor is None)))

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

