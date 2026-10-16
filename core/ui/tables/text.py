"""Dashboard line primitives, widgets, ScanDashboard and table printers.

Split verbatim from the old single-file core/ui/tables.py (no logic
changes). `console` is intentionally NOT imported by name here — every
renderer reads core.ui.styles.console late so tests can redirect it.
"""

from rich.cells import cell_len
from rich.text import Text

from core.ui import styles

from ..styles import D_BG, D_BORDER, D_EMERALD, D_GOLD, D_PANEL, D_TEAL, D_TEXT


def _blank(width: int, background: str = D_BG) -> Text:
    t = Text(no_wrap=True, end="")
    if width > 0:
        t.append(" " * width, f"on {background}")
    return t


def _clip_cells(t: Text, width: int) -> Text:
    """Hard-clip a Text to `width` terminal cells (keeps styles)."""
    out = Text(no_wrap=True, end="")
    used = 0
    for seg in t.render(styles.console):
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


def _take_cells(s: str, n: int) -> tuple[str, str]:
    out = ""
    acc = 0
    for ch in s:
        cw = cell_len(ch)
        if acc + cw > n:
            break
        out += ch
        acc += cw
    return out, s[len(out):]


def _wrap(t: Text, width: int) -> list[Text]:
    """Word-wrap a single-line styled Text into lines of at most `width` cells."""
    if width <= 0:
        return [Text("", end="")]
    if cell_len(t.plain) <= width:
        return [t]

    tokens: list[tuple[str, object]] = []
    for seg in t.render(styles.console):
        if seg.control or not seg.text:
            continue
        parts = seg.text.split(" ")
        for idx, part in enumerate(parts):
            if idx > 0:
                tokens.append((" ", seg.style))
            if part:
                tokens.append((part, seg.style))

    lines: list[Text] = []
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


def _center_height(lines: list[Text], height: int, width: int,
                   background: str = D_PANEL) -> list[Text]:
    """Vertically centre a block inside `height` rows (pads both sides)."""
    if len(lines) >= height:
        return lines[:height]
    pad = (height - len(lines)) // 2
    return _fit_height([_blank(width, background) for _ in range(pad)] + lines,
                       height, width, background)


def _fit_height(lines: list[Text], height: int, width: int,
                background: str = D_PANEL) -> list[Text]:
    if len(lines) > height:
        return lines[:height]
    return lines + [_blank(width, background) for _ in range(height - len(lines))]


def _frame(lines: list[Text], width: int, height: int, title: str = "",
           badge: Text | None = None, background: str = D_PANEL,
           border: str = D_BORDER, pad_x: int = 1) -> list[Text]:
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

    out: list[Text] = []

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


def _hstack(left: list[Text], right: list[Text], left_w: int, right_w: int,
            gap: int) -> list[Text]:
    n = max(len(left), len(right))
    out: list[Text] = []
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

_SCROLLBAR_W = 2           # 1 gutter cell + 1 bar cell at the feed's right edge
_LOGO_ROWS = [
    ((0, "⊕", D_TEAL), (1, "╲", D_EMERALD), (6, "╱", D_GOLD)),
    ((2, "╲", D_EMERALD), (4, "▲", D_GOLD), (5, "╱", D_GOLD)),
    ((3, "╲", D_EMERALD), (4, "╱", D_GOLD)),
]
LOGO_W = 7

