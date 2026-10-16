"""banner — verbatim split from ui.py (no logic changes)."""
import os
import sys
import time
import random
from typing import Dict, List
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich import box

from .styles import B, C, M, N, O, W, console, strip_ansi


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
    "2": ("app", "APP", "Light crawl + param/API/client-side"),
    "3": ("assault", "ASSAULT", "Auto-enrich + vuln scan"),
    "4": ("poisoning", "POISONING", "Cache poison + smuggle + bruteforce"),
    "5": ("full", "FULL", "Recon + app + assault + poisoning"),
    "6": ("recon_light", "RECON LIGHT", "Fast crawl + baseline"),
    "7": ("nuclei", "NUCLEI", "Template scan only"),
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
        ("--no-dork", "Skip Google/DDG scraping (queries still exported)"),
        ("--archive-timeout <sec>", "gau/waybackurls budget (default 90s)"),
        ("--passive", "Passive methods and tools only"),
        ("-r, --resume [path]", "Resume from a saved state file"),
    ]),
    ("LIVE DASHBOARD", [
        ("↑ / ↓ · mouse wheel", "Scroll the Recent Activity feed"),
        ("PgUp / PgDn", "Jump a page through the feed history"),
        ("End", "Snap back to live follow mode"),
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
        {"name": "Deep Crawl", "status": "pending", "detail": ""},
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
        {"name": "Auto-Recon", "status": "pending", "detail": ""},
        {"name": "Katana Crawl", "status": "pending", "detail": ""},
        {"name": "Auto-App", "status": "pending", "detail": ""},
        {"name": "WAF / Origin Hunt", "status": "pending", "detail": ""},
        {"name": "Parameter Discovery", "status": "pending", "detail": ""},
        {"name": "Nuclei & Dalfox", "status": "pending", "detail": ""},
        {"name": "Injection Engine", "status": "pending", "detail": ""},
        {"name": "OOB Detector", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "POISONING": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Seed Crawl", "status": "pending", "detail": ""},
        {"name": "Cache Poisoning", "status": "pending", "detail": ""},
        {"name": "HTTP Smuggling", "status": "pending", "detail": ""},
        {"name": "Directory Bruteforce", "status": "pending", "detail": ""},
        {"name": "Auth Bruteforce", "status": "pending", "detail": ""},
        {"name": "OOB & Payload Flood", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "FULL": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Recon Intel", "status": "pending", "detail": ""},
        {"name": "Katana Crawl", "status": "pending", "detail": ""},
        {"name": "App & Param Discovery", "status": "pending", "detail": ""},
        {"name": "WAF / Origin Hunt", "status": "pending", "detail": ""},
        {"name": "Vulnerability Assault", "status": "pending", "detail": ""},
        {"name": "Poisoning Wave Loop", "status": "pending", "detail": ""},
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
