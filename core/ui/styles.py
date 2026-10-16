"""styles — verbatim split from ui.py (no logic changes)."""
import os
import sys
import time
import re
import random
import threading
import collections
from typing import Dict, List, Optional
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
from rich import box

console = Console(highlight=False)

# Legacy ANSI Colors (Kept for compatibility with existing string formats)
G = '\033[92m'
R = '\033[91m'
Y = '\033[93m'
C = '\033[96m'
M = '\033[95m'
W = '\033[97m'
GY = '\033[90m'
B = '\033[1m'
U = '\033[4m'
N = '\033[0m'
D = '\033[2m'
I = '\033[3m'
O = '\033[38;5;208m'

# Symbols
_CHECK = "✔"
_CROSS = "✖"
_WARN = "⚠"
_INFO = "ℹ"
_RARROW = "❯"
_DIAMOND = "◈"
_HBAR = "━"
_SKULL = "☠"
_BOLT = "⚡"
_SHIELD = "🛡"
_TARGET = "◎"
_DOT = "●"
_CIRCLE = "○"
_ARROW_R = "▸"
_BLOCK = "█"

# ── Verdamt-Snipe design system ────────────────────────────────────────────
# Dashboard palette (single source of truth — keep in sync with the docs).
D_BG = "#080B0A"          # main background
D_PANEL = "#111916"       # panel background
D_ELEV = "#18221D"        # elevated surfaces
D_EMERALD = "#00D68F"     # success / completed / positive results
D_TEAL = "#00CFC1"        # brand accent
D_GOLD = "#D4AF37"        # metallic gold — milestones & progress
D_GOLD_SOFT = "#FFF1A8"   # soft gold — wordmark / emphasis
D_TEXT = "#F0F3F0"        # primary text
D_DIM = "#A5ACA8"         # secondary text / timestamps / metadata
D_INFO = "#77CBEF"        # informational blue
D_WARN = "#FFB547"        # warning / running
D_CRIT = "#FF5D68"        # critical red
D_BORDER = "#263A32"      # muted border / progress track

# Rich Color Palette (Military-Tactical)
_CLR_PRIMARY = "#c8a832"
_CLR_ACCENT = "#c8a832"
_CLR_SHIMMER = "#e8d060"
_CLR_SUCCESS = "#4a8a5e"
_CLR_DANGER = "bold red"
_CLR_WARN = "#c0a020"
_CLR_MUTED = "#3a3a3a"
_CLR_TEXT = "#d0c8a0"
_CLR_DIM = "#666050"
_CLR_BORDER = "#3a3a2a"
_CLR_BG_ACCENT = "#1a1e26"

def strip_ansi(text: str) -> str:
    return re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', text)

def _get_term_width():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80


# LIVE SCANNING DASHBOARD

_DOT = "●"
