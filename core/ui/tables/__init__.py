"""core.ui.tables package — public surface of the old single module.

Everything the old core/ui/tables.py exported is re-exported here so
`from core.ui import tables; tables._FeedProxy` style access keeps working.
"""
from ..styles import console
from .api import draw_box, draw_table
from .dashboard import _HISTORY_LIMIT, _MOUSE_OFF, _MOUSE_ON, _SCROLL_STEP, _WHEEL_STEP, ScanDashboard
from .text import (
                   _SCROLLBAR_W,
                   _blank,
                   _blank_line,
                   _center_height,
                   _clip_cells,
                   _fit,
                   _fit_height,
                   _frame,
                   _hstack,
                   _take_cells,
                   _wrap,
)
from .widgets import (
                   GAUGE_H,
                   GAUGE_W,
                   _bar_meter,
                   _event_lines,
                   _FeedProxy,
                   _findings_line,
                   _gauge,
                   _logo_rows,
                   _sparkline,
                   _stage_rows,
                   _styled_message,
)

__all__ = [
                   "GAUGE_H",
                   "GAUGE_W",
                   "_HISTORY_LIMIT",
                   "_MOUSE_OFF",
                   "_MOUSE_ON",
                   "_SCROLLBAR_W",
                   "_SCROLL_STEP",
                   "_WHEEL_STEP",
                   "ScanDashboard",
                   "_FeedProxy",
                   "_bar_meter",
                   "_blank",
                   "_blank_line",
                   "_center_height",
                   "_clip_cells",
                   "_event_lines",
                   "_findings_line",
                   "_fit",
                   "_fit_height",
                   "_frame",
                   "_gauge",
                   "_hstack",
                   "_logo_rows",
                   "_sparkline",
                   "_stage_rows",
                   "_styled_message",
                   "_take_cells",
                   "_wrap",
                   "console",
                   "draw_box",
                   "draw_table",
]
