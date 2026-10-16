"""CLI flag grammar for verdamt-snipe (Tahap 2 split).

Parsing only — scan orchestration lives in core.orchestrator and the
mode runners in core.modes. Moved VERBATIM out of verd.py (no logic
changes); verd.py stays a thin entry point (`verd:main` in pyproject).
"""
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

VERSION = "1.4.5 - NEXUS"
AUTHOR = "Verdammt"
VULN_THREADS = 25


def parse_target(arg):
    if arg.startswith("http://") or arg.startswith("https://"):
        parsed = urlparse(arg)
        return parsed.netloc, arg
    return arg, f"https://{arg}"


def _resolve_secret(value: str) -> str:
    """Resolve a secret value from a file path, env var, or literal.

    Supported formats:
      - ``env:VAR_NAME``   → reads from environment variable
      - ``file:/path``     → reads first line from file
      - ``/absolute/path`` → reads first line from file (convenience)
      - anything else      → returned as-is (literal value)
    """
    if value.startswith("env:"):
        var_name = value[4:]
        resolved = os.environ.get(var_name)
        if not resolved:
            print(f"\033[91m[!] Environment variable not set: {var_name}\033[0m")
            sys.exit(1)
        return resolved.strip()

    # Explicit file: prefix or --bearer-file / --cookie-file path
    file_path = None
    if value.startswith("file:"):
        file_path = value[5:]
    elif os.path.isfile(value):
        # Only treat as file if the path actually exists (avoids eating
        # a literal token that happens to not contain spaces).
        file_path = value

    if file_path is not None:
        p = Path(file_path).expanduser()
        if not p.is_file():
            print(f"\033[91m[!] Secret file not found: {p}\033[0m")
            sys.exit(1)
        return p.read_text().strip().splitlines()[0].strip()

    return value


def parse_cli_headers(flags):
    h1, h2 = {}, {}
    i = 0
    while i < len(flags):
        f = flags[i]
        if f == "--bearer" and i + 1 < len(flags):
            h1["Authorization"] = f"Bearer {_resolve_secret(flags[i+1])}"; i += 1
        elif f == "--bearer-file" and i + 1 < len(flags):
            h1["Authorization"] = f"Bearer {_resolve_secret('file:' + flags[i+1])}"; i += 1
        elif f == "--bearer2" and i + 1 < len(flags):
            h2["Authorization"] = f"Bearer {_resolve_secret(flags[i+1])}"; i += 1
        elif f == "--bearer2-file" and i + 1 < len(flags):
            h2["Authorization"] = f"Bearer {_resolve_secret('file:' + flags[i+1])}"; i += 1
        elif f == "-H" and i + 1 < len(flags):
            if ":" in flags[i+1]:
                k, v = flags[i+1].split(":", 1)
                h1[k.strip()] = v.strip()
            i += 1
        elif f == "-H2" and i + 1 < len(flags):
            if ":" in flags[i+1]:
                k, v = flags[i+1].split(":", 1)
                h2[k.strip()] = v.strip()
            i += 1
        elif f == "--cookie" and i + 1 < len(flags):
            h1["Cookie"] = _resolve_secret(flags[i+1]); i += 1
        elif f == "--cookie-file" and i + 1 < len(flags):
            h1["Cookie"] = _resolve_secret("file:" + flags[i+1]); i += 1
        elif f == "--cookie2" and i + 1 < len(flags):
            h2["Cookie"] = _resolve_secret(flags[i+1]); i += 1
        elif f == "--cookie2-file" and i + 1 < len(flags):
            h2["Cookie"] = _resolve_secret("file:" + flags[i+1]); i += 1
        i += 1
    return h1, h2


def parse_mode(flags):
    mode_flags = {
        "--recon-light": "recon_light",
        "--recon": "recon",
        "--app": "app",
        "--assault": "assault",
        "--poisoning": "poisoning",
        "--full": "full",
        "--nuclei": "nuclei",
    }
    selected = None
    for flag in flags:
        if flag in mode_flags:
            selected = mode_flags[flag]
    return selected


# Flags that consume the following argv token as their value.
_VALUE_FLAGS = {
    "-p", "-i", "-r", "--proxy", "--proxy-list", "--proxy-rotate", "--impersonate",
    "--max-time", "--max-requests", "--max-concurrency", "--request-timeout",
    "--archive-timeout",
    "--allowed-hosts", "--allowed-ports", "--audit-log", "--resume",
    "--bearer", "--bearer-file", "--bearer2", "--bearer2-file",
    "--cookie", "--cookie-file", "--cookie2", "--cookie2-file",
    "-H", "-H2",
}

# Single-dash aliases -> the long flags this file actually consumes.
# Without this, `python3 verd.py -p socks5://... target` parsed the target
# fine but proxy_url stayed None (only `--proxy` was ever read) and the
# WHOLE scan went direct, silently — MED-OPSEC finding, verified 2026-10-06.
_SHORT_ALIASES = {
    "-p": "--proxy", "-i": "--impersonate", "-s": "--stealth",
    "-t": "--turbo", "-r": "--resume",
}


def parse_scan_args(argv: List[str]) -> Tuple[Optional[str], List[str], Optional[str]]:
    """Parse target/resume layout while keeping legacy free-form flags intact.

    The target may sit before or after flags (``snipe --recon target.com`` and
    ``snipe target.com --recon`` both work). ``--resume`` without a value keeps
    resume_path as None — the caller resolves the default state file from the
    target.
    """
    if len(argv) < 2:
        return None, [], None

    # Legacy: ``--resume <path>`` as the very first argument.
    if argv[1] == "--resume":
        flags = [_SHORT_ALIASES.get(t, t) for t in argv[1:]]
        if len(argv) >= 3 and not argv[2].startswith("-"):
            return None, flags, argv[2]
        return None, flags, None

    # Locate the first positional token (the target), skipping flags and
    # the values they consume.
    idx = 1
    while idx < len(argv):
        token = argv[idx]
        if token.startswith("-"):
            if (token in _VALUE_FLAGS and idx + 1 < len(argv)
                    and not argv[idx + 1].startswith("-")):
                idx += 2
            else:
                idx += 1
            continue
        break

    target_arg = argv[idx] if idx < len(argv) else None
    flags = (argv[1:idx] + argv[idx + 1:]) if idx < len(argv) else argv[1:]
    flags = [_SHORT_ALIASES.get(t, t) for t in flags]

    resume_path = None
    if "--resume" in flags:
        r_idx = flags.index("--resume")
        if r_idx + 1 < len(flags) and not flags[r_idx + 1].startswith("-"):
            resume_path = flags[r_idx + 1]

    return target_arg, flags, resume_path


def _flag_value(flags: List[str], name: str) -> Optional[str]:
    """Read a value from either ``--flag value`` or ``--flag=value``."""
    for idx, flag in enumerate(flags):
        if flag == name and idx + 1 < len(flags):
            return flags[idx + 1]
        if flag.startswith(f"{name}="):
            return flag.split("=", 1)[1]
    return None


def parse_scan_policy_options(flags: List[str]) -> Dict:
    """Parse bounded operational controls without changing scan mode parsing."""
    options = {
        "mode": "passive" if "--passive" in flags else "active",
        "max_requests": 30_000,
        "max_concurrency": 100,
        "max_timeout": 30.0,
        "allowed_hosts": None,
        "allowed_ports": (80, 443),
        "dry_run": "--dry-run" in flags,
    }

    numeric_flags = {
        "--max-requests": ("max_requests", int),
        "--max-concurrency": ("max_concurrency", int),
        "--request-timeout": ("max_timeout", float),
    }
    for flag, (key, converter) in numeric_flags.items():
        raw = _flag_value(flags, flag)
        if raw is None:
            continue
        try:
            value = converter(raw)
            if value <= 0:
                raise ValueError
            options[key] = value
        except (TypeError, ValueError):
            raise ValueError(f"{flag} must be a positive number")

    raw_ports = _flag_value(flags, "--allowed-ports")
    if raw_ports is not None:
        try:
            ports = tuple(sorted({int(port.strip()) for port in raw_ports.split(",") if port.strip()}))
            if not ports or any(port < 1 or port > 65535 for port in ports):
                raise ValueError
            options["allowed_ports"] = ports
        except (TypeError, ValueError):
            raise ValueError("--allowed-ports must be a comma-separated list of ports")

    raw_hosts = _flag_value(flags, "--allowed-hosts")
    if raw_hosts is not None:
        hosts = tuple(host.strip() for host in raw_hosts.split(",") if host.strip())
        if not hosts:
            raise ValueError("--allowed-hosts must contain at least one host")
        options["allowed_hosts"] = hosts

    audit_file = _flag_value(flags, "--audit-log")
    if audit_file:
        options["audit_log"] = audit_file

    return options


def seed_session_headers(sm, seed_url, headers):
    if not headers: return
    parsed = urlparse(seed_url)
    nl, hn = parsed.netloc, parsed.hostname or parsed.netloc
    for k, v in headers.items():
        kl = k.lower()
        if kl == "authorization":
            if v.lower().startswith("bearer "):
                sm.register_token(nl, "bearer", v[7:])
                sm.register_token(hn, "bearer", v[7:])
            elif v.lower().startswith("basic "):
                sm.register_token(nl, "basic", v[6:])
                sm.register_token(hn, "basic", v[6:])
        elif kl == "cookie":
            ck = {}
            for part in v.split(";"):
                if "=" not in part: continue
                kk, vv = part.split("=", 1)
                ck[kk.strip()] = vv.strip()
            if ck:
                sm.update_cookies(nl, ck)
                sm.update_cookies(hn, ck)
