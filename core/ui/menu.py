"""menu — verbatim split from ui.py (no logic changes)."""
import os
import re
import sys

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.text import Text

from .banner import _HELP_EXAMPLES, _HELP_GROUPS, _HELP_LAUNCHER, _HELP_USAGE, _MODES, mode_flag
from .styles import (
    _ARROW_R,
    _CHECK,
    _CROSS,
    _DIAMOND,
    _INFO,
    _RARROW,
    _SKULL,
    _TARGET,
    _WARN,
    D_BORDER,
    D_DIM,
    D_EMERALD,
    D_GOLD,
    D_GOLD_SOFT,
    D_INFO,
    D_TEAL,
    GY,
    C,
    G,
    N,
    R,
    W,
    _get_term_width,
    console,
    strip_ansi,
)
from .tables import ScanDashboard, draw_box

# BANNER

def count_request() -> None:
    """Count one actually-dispatched HTTP request (dashboard TOTAL REQ/REQ-S).

    Called from client dispatch points — replaces the old behaviour of
    incrementing 'Requests' for every log line (which measured log volume,
    not traffic).
    """
    dash = ScanDashboard._instance
    if dash is not None:
        with dash._lock:
            dash.metrics["Requests"] += 1


# THREAD-SAFE RICH OUTPUT FUNCTIONS

def _rich_print(msg):
    console.print(msg)

def p(msg):
    if ScanDashboard.active():
        ScanDashboard.get().log_event(strip_ansi(str(msg)), "cyan", kind="info")
    else:
        _rich_print(f"  [bold #5a8a9e]{_RARROW}[/] {msg}")

def i(msg):
    if ScanDashboard.active():
        ScanDashboard.get().log_event(strip_ansi(str(msg)), "bright_black", kind="info")
    else:
        _rich_print(f"  [#555555]{_INFO}[/] {msg}")

def w(msg):
    if ScanDashboard.active():
        ScanDashboard.get().log_warning(strip_ansi(str(msg)))
    else:
        _rich_print(f"  [bold #c0a020]{_WARN}[/] [#c0a020]{msg}[/]")

def e(msg):
    if ScanDashboard.active():
        ScanDashboard.get().log_error(strip_ansi(str(msg)))
    else:
        _rich_print(f"  [bold red]{_CROSS}[/] [red]{msg}[/]")

def s(msg):
    if ScanDashboard.active():
        ScanDashboard.get().log_event(strip_ansi(str(msg)), "green", kind="ok")
    else:
        _rich_print(f"  [bold #4a8a5e]{_CHECK}[/] {msg}")

def ph(msg):
    """Animated phase transition header with brutalist styling."""
    if ScanDashboard.active():
        ScanDashboard.get().set_phase(msg)
        return

    console.print()

    # Build the phase header content
    phase_text = Text()
    phase_text.append(f" {_SKULL} ", style="bold red")
    phase_text.append(msg.upper(), style="bold white")

    panel = Panel(
        Align.center(phase_text),
        border_style="#C6A15B",
        box=box.DOUBLE_EDGE,
        expand=True,
        padding=(0, 0),
    )
    console.print(panel)


# ANIMATED COMPONENTS

class Spinner:
    """Enhanced multi-task capable Spinner using rich.progress.

    When a ScanDashboard is active, the Spinner delegates to the
    dashboard's activity indicator instead of creating its own
    Rich Progress (avoids nested Live conflicts).
    """
    def __init__(self, message="Processing", interval=0.1):
        self.message = message
        self._dashboard_mode = ScanDashboard.active()
        self._running = False
        self._live = None

        if not self._dashboard_mode:
            self.progress = Progress(
                SpinnerColumn(spinner_name="dots", style="magenta"),
                TextColumn("  [bold cyan]{task.description}[/]"),
                TimeElapsedColumn(),
                console=console,
                transient=True
            )
            self.task_id = None
        else:
            self.progress = None
            self.task_id = None

    def start(self):
        if self._running:
            return
        if self._dashboard_mode:
            ScanDashboard.get().set_activity(self.message)
            self._running = True
        else:
            self.task_id = self.progress.add_task(self.message, total=None)
            self.progress.start()
            self._running = True

    def stop(self):
        if not self._running:
            return
        if self._dashboard_mode:
            ScanDashboard.get().set_activity("")
            self._running = False
        else:
            self.progress.stop()
            self._running = False

    def update(self, message):
        self.message = message
        if self._dashboard_mode:
            if self._running:
                ScanDashboard.get().set_activity(message)
        else:
            if self._running and self.task_id is not None:
                self.progress.update(self.task_id, description=message)

    def next(self):
        if self._dashboard_mode:
            return
        if not self._running:
            self.start()

def draw_interactive_menu(target, settings, selected_mode=None):
    """Draw the interactive TUI using Rich panels."""
    if os.name == 'posix':
        sys.stdout.write('\033[2J\033[H')
        sys.stdout.flush()
    else:
        os.system('cls')

    # Banner (compact)
    banner_text = Text()
    banner_text.append("  VERDAMT", style="bold white")
    banner_text.append("-", style="bright_black")
    banner_text.append("SNIPE", style="bold magenta")
    banner_text.append("  ", style="")
    banner_text.append(_SKULL, style="bold magenta")

    console.print()
    console.print(Panel(
        Align.center(banner_text),
        border_style="magenta",
        box=box.DOUBLE_EDGE,
        expand=True,
        padding=(0, 0),
    ))
    console.print()

    # Mode Selection Panel
    mode_lines = []
    for key, (mode_id, label, desc) in _MODES.items():
        if selected_mode == key:
            mode_lines.append(f"  [bold magenta]{_DIAMOND}[/] [bold cyan][{key}][/] [bold white]{label:<13}[/] [white]{desc}[/]")
        else:
            mode_lines.append(f"    [cyan][{key}][/] [white]{label:<13}[/] [bright_black]{desc}[/]")
    mode_content = "\n".join(mode_lines)

    # Settings Panel
    st_val = "[bold green]ON[/]" if settings.get('stealth') else "[bold red]OFF[/]"
    tb_val = "[bold green]ON[/]" if settings.get('turbo') else "[bold red]OFF[/]"
    pr_val = f"[white]{settings.get('proxy')}[/]" if settings.get('proxy') else "[bright_black]none[/]"
    im_val = f"[white]{settings.get('impersonate')}[/]" if settings.get('impersonate') else "[bright_black]chrome[/]"

    settings_lines = [
        f"  [cyan]\\[S][/] Stealth     {st_val}",
        f"  [cyan]\\[T][/] Turbo       {tb_val}",
        f"  [cyan]\\[P][/] Proxy       {pr_val}",
        f"  [cyan]\\[I][/] Impersonate {im_val}",
    ]
    settings_content = "\n".join(settings_lines)

    # Print panels side by side using Columns
    mode_panel = Panel(
        mode_content,
        title="[bold white] SCAN MODES [/]",
        title_align="left",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 1),
        expand=True,
    )
    settings_panel = Panel(
        settings_content,
        title="[bold white] SETTINGS [/]",
        title_align="left",
        border_style="bright_black",
        box=box.ROUNDED,
        padding=(1, 1),
        expand=True,
    )

    console.print(Columns([mode_panel, settings_panel], expand=True, padding=(0, 1)))
    console.print()

    # Target Info Bar
    target_line = Text()
    target_line.append(f"  {_TARGET} ", style="cyan")
    target_line.append("Target: ", style="bright_black")
    target_line.append(target, style="bold white")

    if selected_mode and selected_mode in _MODES:
        _, label, _ = _MODES[selected_mode]
        target_line.append("  │  ", style="bright_black")
        target_line.append("Mode: ", style="bright_black")
        target_line.append(label, style="bold green")

    console.print(target_line)
    console.print()

    if selected_mode:
        console.print(f"  [bold green]{_CHECK}[/] Mode selected. Press [bold green]\\[G][/] to [bold green]GAS[/] or [cyan]\\[Q][/] to cancel")
    mode_hint = f"1-{max(int(k) for k in _MODES)}"
    console.print(f"  [cyan]{_RARROW}[/] Select mode [cyan]\\[{mode_hint}][/] or toggle [cyan]\\[S/T/P/I/H][/]: ", end="")


# ── --help screen ───────────────────────────────────────────────────────────
#
# Rendered straight from the _HELP_* catalogue in .banner, which
# tests/test_help_screen.py cross-checks against the flags
# core/cli_parser.py actually consumes — so this screen cannot drift.

_HELP_PANEL_W = 116


def _help_panel(title: str, body) -> Panel:
    return Panel(
        body,
        title=Text.assemble(f" {title} ", style=f"bold {D_GOLD_SOFT}"),
        title_align="left",
        border_style=D_BORDER,
        box=box.ROUNDED,
        expand=True,
        width=_HELP_PANEL_W,
        padding=(0, 1),
    )


def _help_kv(rows, key_colour=D_EMERALD, indent=2, gap=3) -> Text:
    """Aligned `flag   description` block; Rich wraps long rows on render."""
    key_w = max((len(flag) for flag, _ in rows), default=0)
    out = Text()
    for idx, (flag, desc) in enumerate(rows):
        if idx:
            out.append("\n")
        out.append(" " * indent)
        out.append(flag.ljust(key_w), key_colour)
        out.append(" " * gap)
        out.append(desc, D_DIM)
    return out


def draw_help_screen():
    header = Text()
    header.append("\n  VERDAMT-SNIPE ", style=f"bold {D_GOLD_SOFT}")
    header.append("· RECON · SCAN · EXPLOIT", style=D_TEAL)
    header.append("\n  Authorized targets only.\n", style=D_DIM)
    header.append("  Scope is enforced by --allowed-hosts and --allowed-ports.\n",
                  style=D_DIM)

    usage = Text()
    for idx, (cmd, desc) in enumerate(_HELP_USAGE):
        if idx:
            usage.append("\n")
        usage.append("  ")
        usage.append(cmd.ljust(36), D_INFO)
        usage.append(desc, D_DIM)

    modes = Text()
    for key, (mode_id, _label, desc) in _MODES.items():
        if modes.plain:
            modes.append("\n")
        modes.append("  ")
        modes.append(f"[{key}] ".ljust(6), D_GOLD)
        modes.append(mode_flag(mode_id).ljust(15), D_EMERALD)
        modes.append("  ")
        modes.append(desc, D_DIM)

    launcher = _help_kv(_HELP_LAUNCHER, key_colour=D_TEAL)

    examples = Text()
    for idx, example in enumerate(_HELP_EXAMPLES):
        if idx:
            examples.append("\n")
        parts = re.split(r"\s{2,}", example, maxsplit=1)
        examples.append("  $ ", D_GOLD)
        examples.append(parts[0], D_INFO)
        if len(parts) > 1:
            examples.append("  " + parts[1], D_DIM)

    panels = [_help_panel("USAGE", usage), _help_panel("MODES", modes)]
    panels += [_help_panel(title, _help_kv(rows)) for title, rows in _HELP_GROUPS]
    panels += [_help_panel("SNIPER LAUNCHER", launcher),
               _help_panel("EXAMPLES", examples)]

    # Pair the compact panels side by side when the terminal is wide enough
    # to keep every description on one line; otherwise stack them.
    tw = _get_term_width()
    blocks: list = []
    if tw >= 150:
        blocks.append(panels[0])
        for i in range(1, len(panels) - 1, 2):
            blocks.append(Columns([panels[i], panels[i + 1]],
                                  expand=True, padding=(0, 1)))
        blocks.append(panels[-1])
    else:
        blocks = panels

    console.print(header)
    for block in blocks:
        console.print(block)
    print()


def draw_confirm_bar(mode, target, settings):
    st = f"{G}{_CHECK} ON{N}" if settings.get('stealth') else f"{R}{_CROSS} OFF{N}"
    tb = f"{G}{_CHECK} ON{N}" if settings.get('turbo') else f"{R}{_CROSS} OFF{N}"
    pr = settings.get('proxy') or f"{GY}none{N}"
    im = settings.get('impersonate') or f"{GY}chrome{N}"

    lines = [
        f"  {C}{_ARROW_R} Mode:{N}       {W}{mode.upper()}{N}",
        f"  {C}{_ARROW_R} Target:{N}     {W}{target}{N}",
        f"  {C}{_ARROW_R} Stealth:{N}    {st}",
        f"  {C}{_ARROW_R} Turbo:{N}      {tb}",
        f"  {C}{_ARROW_R} Proxy:{N}      {pr}",
        f"  {C}{_ARROW_R} Impersonate:{N} {im}",
    ]
    draw_box(f"{_SKULL} READY TO ENGAGE", lines, color=G)
    print(f"\n  {G}{_CHECK}{N} Confirm & start? [{G}Y{N}/n]: ", end="")
