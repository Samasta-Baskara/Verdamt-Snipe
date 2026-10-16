"""core.ui.tables package — public surface of the old single module.

Everything the old core/ui/tables.py exported is re-exported here so
`from core.ui import tables; tables._FeedProxy` style access keeps working.
"""
from ..styles import console  # noqa: F401  (legacy attribute; patch styles.console instead)
from .text import (_blank, _clip_cells, _fit, _take_cells, _wrap, _center_height,
                   _fit_height, _frame, _hstack, _blank_line, _SCROLLBAR_W)
from .widgets import (_logo_rows, _styled_message, _event_lines, _stage_rows, _gauge,
                      _sparkline, _findings_line, _bar_meter, _FeedProxy,
                      GAUGE_W, GAUGE_H)
from .dashboard import (ScanDashboard, _HISTORY_LIMIT, _SCROLL_STEP, _WHEEL_STEP,
                        _MOUSE_ON, _MOUSE_OFF)
from .api import draw_box, draw_table

__all__ = [
    "ScanDashboard", "draw_box", "draw_table",
    "_blank", "_clip_cells", "_fit", "_take_cells", "_wrap", "_center_height",
    "_fit_height", "_frame", "_hstack", "_blank_line",
    "_logo_rows", "_styled_message", "_event_lines", "_stage_rows", "_gauge",
    "_sparkline", "_findings_line", "_bar_meter", "_FeedProxy",
    "GAUGE_W", "GAUGE_H",
    "_HISTORY_LIMIT", "_SCROLL_STEP", "_WHEEL_STEP", "_SCROLLBAR_W",
    "_MOUSE_ON", "_MOUSE_OFF", "console",
]
