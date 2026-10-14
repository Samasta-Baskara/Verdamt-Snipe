"""banner — verbatim split from ui.py (no logic changes)."""
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

from .styles import B, C, M, N, O, W, _get_term_width, console, strip_ansi

def _get_stage_description(stage_name: str) -> str:
    s_lower = stage_name.lower()
    if "surface" in s_lower:
        return "Analyzing target surface..."
    elif "subfinder" in s_lower:
        return "Enumerating subdomains..."
    elif "httpx" in s_lower:
        return "Probing targets & services..."
    elif "recon light" in s_lower:
        return "Performing light recon scan..."
    elif "recon intel" in s_lower:
        return "Gathering deep intelligence..."
    elif "js" in s_lower or "secret" in s_lower:
        return "Scanning JS files for secrets..."
    elif "dork" in s_lower:
        return "Search engine reconnaissance..."
    elif "baseline" in s_lower:
        return "Auditing security baseline..."
    elif "waf" in s_lower or "origin" in s_lower:
        return "Hunting origin IP & WAF..."
    elif "katana" in s_lower or "crawl" in s_lower:
        return "Crawling web endpoints..."
    elif "parameter" in s_lower or "param" in s_lower:
        return "Discovering hidden parameters..."
    elif "app" in s_lower:
        return "Analyzing application structure..."
    elif "nuclei" in s_lower or "dalfox" in s_lower:
        return "Running template & XSS scans..."
    elif "injection" in s_lower:
        return "Testing injection vectors..."
    elif "smuggling" in s_lower or "oob" in s_lower:
        return "Testing smuggling & callbacks..."
    elif "cache" in s_lower or "poison" in s_lower:
        return "Testing cache poison vectors..."
    elif "directory" in s_lower:
        return "Bruteforcing directories..."
    elif "auth" in s_lower:
        return "Testing authentication..."
    elif "vulnerability" in s_lower or "assault" in s_lower:
        return "Testing vulnerabilities..."
    elif "target" in s_lower or "resolution" in s_lower:
        return "Resolving target endpoints..."
    elif "verify" in s_lower or "verification" in s_lower:
        return "Verifying security findings..."
    elif "sqli" in s_lower or "extract" in s_lower:
        return "Extracting database data..."
    elif "report" in s_lower:
        return "Generating final scan report..."
    return "Processing..."


def _get_stage_icon(name: str) -> str:
    """Return a tactical icon for the pipeline stage."""
    n = name.lower()
    if "surface" in n: return "⊙"
    if "subfinder" in n or "subdomain" in n: return "◈"
    if "httpx" in n or "probing" in n: return "⚡"
    if "waf" in n or "origin" in n: return "◎"
    if "katana" in n or "crawl" in n: return "⊕"
    if "param" in n: return "⚙"
    if "recon" in n and "light" in n: return "⊙"
    if "recon" in n: return "⊛"
    if "app" in n and "deep" in n: return "⬡"
    if "app" in n: return "⬡"
    if "nuclei" in n or "dalfox" in n: return "☢"
    if "injection" in n: return "⚔"
    if "vulnerability" in n or "assault" in n: return "☠"
    if "cache" in n or "poison" in n: return "☣"
    if "smuggling" in n: return "⇌"
    if "directory" in n: return "⊞"
    if "auth" in n: return "⊟"
    if "verification" in n or "finding" in n: return "⊘"
    if "sqli" in n or "extract" in n: return "⊞"
    if "report" in n: return "⊕"
    if "baseline" in n: return "⊙"
    if "js" in n or "secret" in n: return "⊛"
    if "dork" in n or "google" in n: return "◈"
    if "oob" in n or "flood" in n: return "⊘"
    if "target" in n or "resolution" in n: return "◎"
    return "·"


def _get_stage_subtitle(name: str) -> str:
    """Return a tactical subtitle for pipeline stage display."""
    n = name.lower()
    if "surface" in n: return "DNS + WEB DISCOVERY"
    if "subfinder" in n: return "SUBDOMAIN ENUM"
    if "httpx" in n or "probing" in n: return "LIVE HOSTS"
    if "waf" in n and "risk" in n: return "WAF RISK ASSESSMENT"
    if "waf" in n or "origin" in n: return "WAF DETECTION + ORIGIN"
    if "katana" in n or "crawl" in n: return "ENDPOINT CRAWLING"
    if "param" in n and "app" in n: return "APP + PARAM DISCOVERY"
    if "param" in n: return "HIDDEN PARAMETERS"
    if "recon light" in n: return "FAST RECON"
    if "recon intel" in n: return "DEEP INTELLIGENCE"
    if "recon" in n: return "RECONNAISSANCE"
    if "app" in n and "deep" in n: return "APP DEEP ANALYSIS"
    if "app" in n: return "APPLICATION ANALYSIS"
    if "nuclei" in n and "dalfox" in n: return "TEMPLATE + XSS SCAN"
    if "nuclei" in n: return "TEMPLATE ENGINE"
    if "injection" in n: return "INJECTION VECTORS"
    if "vulnerability" in n or "assault" in n: return "SCAN + ANALYZE"
    if "cache" in n or "poison" in n: return "CACHE POISON VECTORS"
    if "smuggling" in n: return "HTTP SMUGGLING"
    if "directory" in n: return "DIR BRUTEFORCE"
    if "auth" in n: return "AUTH BRUTEFORCE"
    if "verification" in n or "finding" in n: return "CONFIRM + VALIDATE"
    if "sqli" in n or "extract" in n: return "EXPLOIT + DUMP"
    if "report" in n: return "GENERATE REPORT"
    if "baseline" in n: return "SECURITY BASELINE"
    if "js" in n or "secret" in n: return "JS FILE SECRETS"
    if "dork" in n or "google" in n: return "SEARCH ENGINE RECON"
    if "oob" in n or "flood" in n: return "OOB + PAYLOAD FLOOD"
    if "target" in n or "resolution" in n: return "TARGET RESOLUTION"
    return "PROCESSING"

_BANNER_LINES = [
    "  " + chr(9556) + chr(9552)*29 + chr(9559),
    "  " + chr(9553) + W + chr(183)*29 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*29 + N + chr(9553),
    "  " + chr(9553) + O + chr(9608)*4 + W + chr(183)*6 + N + O + chr(9608)*4 + N + W + chr(183) + N + O + chr(9608)*12 + W + chr(183)*2 + N + chr(9553),
    "  " + chr(9553) + W + chr(183) + N + O + chr(9608)*4 + W + chr(183)*4 + N + O + chr(9608)*4 + W + chr(183) + N + W + chr(183) + N + O + chr(9608)*2 + W + chr(183)*12 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*2 + N + O + chr(9608)*4 + W + chr(183)*2 + N + O + chr(9608)*4 + W + chr(183)*2 + N + W + chr(183) + N + O + chr(9608)*2 + W + chr(183)*12 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*3 + N + O + chr(9608)*8 + W + chr(183)*3 + N + W + chr(183) + N + O + chr(9608)*12 + W + chr(183)*2 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*4 + N + O + chr(9608)*6 + W + chr(183)*4 + N + W + chr(183) + N + W + chr(183)*9 + N + O + chr(9608)*2 + W + chr(183)*3 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*5 + N + O + chr(9608)*4 + W + chr(183)*5 + N + W + chr(183) + N + W + chr(183)*9 + N + O + chr(9608)*2 + W + chr(183)*3 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*6 + N + O + chr(9608)*2 + W + chr(183)*6 + N + W + chr(183) + N + O + chr(9608)*12 + W + chr(183)*2 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*29 + N + chr(9553),
    "  " + chr(9553) + B + W + "  " + chr(9608)*2 + "    VERDAMT-SNIPE     " + chr(9608)*2 + " " + N + chr(9553),
    "  " + chr(9553) + C + "     recon" + chr(183) + "scan" + chr(183) + "exploit      " + N + chr(9553),
    "  " + chr(9562) + chr(9552)*29 + chr(9565),
]

_MODES = {
    "1": ("recon", "RECON", "Passive intel + archive URLs"),
    "2": ("app", "APP", "WAF bypass + param discovery"),
    "3": ("assault", "ASSAULT", "Origin IP + vuln scan"),
    "4": ("poisoning", "POISONING", "Cache poison + smuggle + bruteforce"),
    "5": ("full", "FULL", "Recon + app + assault"),
    "6": ("recon_light", "RECON LIGHT", "Fast crawl + baseline"),
    "7": ("nuclei", "NUCLEI", "Template scan only"),
}

_MODE_ICONS = {
    "1": "🔍",
    "2": "🧪",
    "3": "💀",
    "4": "☣️",
    "5": "💥",
    "6": "⚡",
    "7": "🎯",
}

_IMPERSONATE_OPTS = [None, "chrome", "safari", "firefox"]


# ── --help catalogue ────────────────────────────────────────────────────────
# Single source of truth for the help screen.  tests/test_help_screen.py
# cross-checks this table against the flags core/cli_parser.py actually
# consumes, so the help text cannot drift from the real grammar again.

def mode_flag(mode_id: str) -> str:
    """Long CLI flag for a mode id (``recon_light`` → ``--recon-light``)."""
    return "--" + mode_id.replace("_", "-")


_HELP_USAGE = [
    ("snipe <mode 1-7> <target> [flags]", "quick launcher (recommended)"),
    ("snipe <target> [flags]", "opens the interactive mode menu"),
    ("python3 verd.py <target> [flags]", "same, without the snipe wrapper"),
    ("python3 verd.py --full <target>", "run one mode directly"),
    ("snipe --help", "this screen   ·   snipe --version"),
]

_HELP_GROUPS = [
    ("SCAN CONTROL", [
        ("-s, --stealth", "Camouflage, jitter and human-like headers"),
        ("-t, --turbo", "Max concurrency, no delays"),
        ("--max-time <sec>", "Global scan time budget"),
        ("--passive", "Passive methods and tools only"),
        ("-r, --resume [path]", "Resume from a saved state file"),
    ]),
    ("PROXY & IMPERSONATION", [
        ("-p, --proxy <url>", "Proxy URL, e.g. socks5://1.2.3.4:1080"),
        ("--proxy-list <path>", "Load a proxy list from a file"),
        ("--proxy-rotate <n>", "Rotate to the next proxy every N requests"),
        ("--no-proxy", "Ignore the VERDAMT_PROXY environment fallback"),
        ("-i, --impersonate <b>", "TLS fingerprint: chrome, safari or firefox"),
    ]),
    ("SAFETY & SCOPE", [
        ("--max-requests <n>", "Hard cap on requests against the target"),
        ("--max-concurrency <n>", "Max concurrent requests against the target"),
        ("--request-timeout <sec>", "Per-request timeout against the target"),
        ("--allowed-hosts <h,h>", "Extra exact hosts or IPs kept in scope"),
        ("--allowed-ports <p,p>", "Ports allowed for active probes (80,443)"),
        ("--dry-run", "Authorise and log every request, send nothing"),
    ]),
    ("AUTH & HEADERS", [
        ("--bearer <val>", "Bearer token: literal, env:VAR or file:PATH"),
        ("--bearer-file <path>", "Bearer token read from a file"),
        ("--bearer2 <val>", "Bearer token for role-2 requests"),
        ("--bearer2-file <path>", "Role-2 bearer token read from a file"),
        ("--cookie <val>", "Cookie header: literal, env:VAR or file:PATH"),
        ("--cookie-file <path>", "Cookie header read from a file"),
        ("--cookie2 <val>", "Cookie header for role-2 requests"),
        ("--cookie2-file <path>", "Role-2 cookie read from a file"),
        ('-H "Name: value"', "Custom header for role-1 requests"),
        ('-H2 "Name: value"', "Custom header for role-2 requests"),
    ]),
    ("MODULE FOCUS", [
        ("--jwt", "Focus the JWT module"),
        ("--idor", "Focus the IDOR module"),
        ("--crlf", "Focus the CRLF module"),
        ("--host-inject", "Focus Host-header injection"),
        ("--stored-xss", "Focus stored XSS"),
    ]),
    ("OUTPUT & TOOLING", [
        ("--audit-log <path>", "Write the JSONL audit trail to <path>"),
        ("--setup-wordlists", "Install or refresh the wordlist set"),
        ("--setup-wordlists --force", "Re-download wordlists that already exist"),
        ("-h, --help, /h", "Show this help screen"),
        ("--version, /v", "Print the version"),
    ]),
]

_HELP_LAUNCHER = [
    ("1 … 7", "Mode shortcuts for --recon … --nuclei"),
    ("-s / -t / -r", "--stealth / --turbo / --resume"),
    ("-p <url> / -i <browser>", "--proxy / --impersonate"),
    ("-j / -x / -id", "--jwt / --stored-xss / --idor"),
    ("-c / -hi / -a", "--crlf / --host-inject / all five focus flags"),
]

_HELP_EXAMPLES = [
    "snipe 6 example.com                       fast baseline",
    "snipe 4 example.com -s -p socks5://1.2.3.4:1080",
    "snipe example.com                         interactive menu",
    "python3 verd.py example.com --full --max-time 300",
    "python3 verd.py --nuclei example.com --dry-run",
    "snipe example.com --resume                continue last scan",
]

_PIPELINE_STAGES_BY_MODE: Dict[str, List[Dict[str, str]]] = {
    "RECON_LIGHT": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Recon Light", "status": "pending", "detail": ""},
        {"name": "Baseline Checks", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "RECON": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Recon Intel", "status": "pending", "detail": ""},
        {"name": "JS & Secret Analysis", "status": "pending", "detail": ""},
        {"name": "Google Dorking", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "APP": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "WAF / Origin Hunt", "status": "pending", "detail": ""},
        {"name": "Katana Crawler", "status": "pending", "detail": ""},
        {"name": "Parameter Discovery", "status": "pending", "detail": ""},
        {"name": "App Deep Analysis", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "ASSAULT": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "WAF Risk Assessment", "status": "pending", "detail": ""},
        {"name": "Parameter Discovery", "status": "pending", "detail": ""},
        {"name": "Nuclei & Dalfox", "status": "pending", "detail": ""},
        {"name": "Injection Engine", "status": "pending", "detail": ""},
        {"name": "Smuggling & OOB", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "POISONING": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Cache Poisoning", "status": "pending", "detail": ""},
        {"name": "HTTP Smuggling", "status": "pending", "detail": ""},
        {"name": "Directory Bruteforce", "status": "pending", "detail": ""},
        {"name": "Auth Bruteforce", "status": "pending", "detail": ""},
        {"name": "OOB & Payload Flood", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "FULL": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Recon Intel", "status": "pending", "detail": ""},
        {"name": "WAF / Origin Hunt", "status": "pending", "detail": ""},
        {"name": "App & Param Discovery", "status": "pending", "detail": ""},
        {"name": "Vulnerability Assault", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "NUCLEI": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Target Resolution", "status": "pending", "detail": ""},
        {"name": "Nuclei Engine", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
}


def print_banner(version, author):
    if os.name == 'posix':
        sys.stdout.write('\033[2J\033[H')
        sys.stdout.flush()
    else:
        os.system('cls')
    tw = _get_term_width()
    print()

    # Glitch-animated banner render
    glitch_chars = "!<>-_\\\\/[]{}—=+*^?#@$%&"
    for idx, line in enumerate(_BANNER_LINES):
        # Glitch pass: briefly show corrupted line
        clean = strip_ansi(line)
        if len(clean) > 4 and random.random() > 0.3:
            corrupted = list(clean)
            for _ in range(random.randint(2, 5)):
                pos = random.randint(0, len(corrupted) - 1)
                corrupted[pos] = random.choice(glitch_chars)
            sys.stdout.write(f"\r{M}{''.join(corrupted)}{N}")
            sys.stdout.flush()
            time.sleep(0.02)
        sys.stdout.write(f"\r{line}\n")
        sys.stdout.flush()
        time.sleep(0.01)

    print()
    console.print(Rule(style="bright_black"))
    print()

    # Quick start derived from the same catalogue `--help` renders, so the
    # banner can never advertise a flag list that no longer exists.
    quick = Text()
    for idx, (cmd, desc) in enumerate(_HELP_USAGE[:3]):
        if idx:
            quick.append("\n")
        quick.append("  ")
        quick.append(cmd.ljust(36), "cyan")
        quick.append(desc, "bright_black")
    console.print(Panel(
        quick,
        title=Text.assemble(" QUICK START ", style="bold white"),
        title_align="left",
        border_style="bright_black",
        box=box.ROUNDED,
        expand=False,
        padding=(0, 1),
    ))

    print()
    # Version line with style
    console.print(f"  [cyan]v{version}[/] [bright_black]•[/] [magenta]{author}[/] [bright_black]•[/] [bright_black]recon[/][dim]·[/][bright_black]scan[/][dim]·[/][bright_black]exploit[/]")
    console.print(Rule(style="bright_black"))
    print()
