"""Dashboard line primitives, widgets, ScanDashboard and table printers.

Split verbatim from the old single-file core/ui/tables.py (no logic
changes). `console` is intentionally NOT imported by name here — every
renderer reads core.ui.styles.console late so tests can redirect it.
"""
from core.ui import styles


from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from ..styles import C, G, R, Y, _DIAMOND, _TARGET, strip_ansi
from .dashboard import ScanDashboard


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
    styles.console.print(panel)


def draw_table(headers, rows, title=None):
    """Animated table rendering with premium styling.

    While a ScanDashboard is active the rows are streamed into the Recent
    Activity feed instead of printed above the live canvas, so nothing ever
    escapes the dashboard frame.
    """
    if not rows: return

    dash = ScanDashboard._instance
    if dash is not None and ScanDashboard.active():
        if title:
            dash.log_event(title, "white", kind="info")
        shown = rows[:20]
        for r in shown:
            cells = [strip_ansi(str(x)).strip() for x in r]
            line = "  ".join(c for c in cells if c)
            if line:
                dash.log_event(line, "white", kind="ok")
        if len(rows) > len(shown):
            dash.log_event(f"… {len(rows) - len(shown)} more rows",
                           "white", kind="info")
        return

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

    styles.console.print(table)


