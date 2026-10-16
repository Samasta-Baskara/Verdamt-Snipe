"""CLI parsing + scan orchestration for verdamt-snipe (Tahap 2 split).

Moved VERBATIM out of verd.py (no logic changes): flag grammar lives
here so verd.py stays a thin entry point (`verd:main` in pyproject).
"""
#!/usr/bin/env python3
import sys, time, asyncio, os, re, ipaddress
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode
from pathlib import Path

from core.ui import print_banner, ph, i, w, s, Spinner, G, R, C, W, N, B, M, D, GY, ScanDashboard
from core.ui import draw_interactive_menu, draw_help_screen, draw_confirm_bar, _MODES, _IMPERSONATE_OPTS
from core.network import GhostMode
from core.ratelimit import get_global_rate_limiter
from core.policy import ScanPolicy
from core.state import SessionManager
from core.async_network import AsyncNetworkEngine
from core.project import ProjectState, sanitize_filename
from modules.scanners import VulnVerifier
from modules.web.server_side.blind_sqli_extract import BlindSQLiExtractor
from runners.shared import inject_query_payload, run_katana_phase, run_waf_origin_phase
from reports.engine import ReportEngine, finding_cvss
from runners.surface import run_surface_scan
from runners.recon_intel import run_recon_intel
from runners.recon_light import run_recon_light
from runners.app_analysis import run_app_analysis
from runners.vuln_assault import run_vuln_assault
from runners.full_assault import run_full_assault
from runners.poison import run_poison_assault
from core.camouflage import CamouflageBrowser
from core.proxy_manager import setup_proxy, get_global_proxy_manager

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


def interactive_mode_select(target, settings):
    """Interactive TUI mode selection.

    Args:
        target: Target domain
        settings: dict with stealth, turbo, proxy, impersonate

    Returns:
        (mode_key, settings) tuple
    """
    selected_mode = None

    while True:
        draw_interactive_menu(target, settings, selected_mode)

        try:
            choice = input().strip().lower()
        except KeyboardInterrupt:
            print()
            sys.exit(0)

        if not choice:
            continue

        # Mode selection
        if choice in _MODES:
            selected_mode = choice
            continue

        # Toggle settings
        if choice == 's':
            settings['stealth'] = not settings.get('stealth', False)
            continue
        if choice == 't':
            settings['turbo'] = not settings.get('turbo', False)
            continue
        if choice == 'p':
            print(f"  {C}{chr(8250)}{N} Proxy URL [{GY}none{N}]: ", end="")
            proxy_input = input().strip()
            settings['proxy'] = proxy_input if proxy_input else None
            continue
        if choice == 'i':
            current = settings.get('impersonate') or 'chrome'
            try:
                idx = _IMPERSONATE_OPTS.index(current)
            except ValueError:
                idx = 0
            next_idx = (idx + 1) % len(_IMPERSONATE_OPTS)
            settings['impersonate'] = _IMPERSONATE_OPTS[next_idx]
            continue

        # Help
        if choice == 'h':
            draw_help_screen()
            input(f"  {GY}Press Enter to continue...{N}")
            continue

        # Gas!
        if choice == 'g':
            if not selected_mode:
                w("Select a mode first [1-5]")
                continue
            mode_id, mode_name, _ = _MODES[selected_mode]
            draw_confirm_bar(mode_id, target, settings)
            confirm = input().strip().lower()
            if confirm == 'n':
                selected_mode = None
                continue
            return mode_id, settings

        # Quit
        if choice == 'q':
            print()
            sys.exit(0)

        # Legacy flags
        if choice == '--recon':
            return "recon", settings
        if choice == '--recon-light':
            return "recon_light", settings
        if choice == '--app':
            return "app", settings
        if choice == '--assault':
            return "assault", settings
        if choice == '--poisoning':
            return "poisoning", settings
        if choice == '--full':
            return "full", settings
        if choice == '--nuclei':
            return "nuclei", settings

        w(f"Invalid choice. Select [1-{max(int(k) for k in _MODES)}] or press [H] for help.")


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


def _active_proxy():
    """Current proxy from ProxyManager singleton (flag-only: None when unset)."""
    pm = get_global_proxy_manager()
    return pm.current_proxy if pm and pm.current_proxy else None


async def phase_verify_report(target, findings, services, subs, scan_urls, target_wafs, t0, mode, async_engine=None, session_manager=None):
    # Ref ke list milik caller (all_findings) — di-mutasi di akhir agar hasil
    # verify + ekstraksi ikut tersimpan ke .state saat save_project_state().
    caller_findings = findings
    if findings:
        ph("Phase 4: Finding Verification")

        # Dedup SEBELUM verify: temuan kembar (nuclei ↔ injection ↔ dalfox)
        # dulu diverifikasi 2× — 2 request per duplikat membakar budget yang
        # sering sudah menipis. (Dedup Phase 5 tetap jadi jaring pengaman.)
        _seen = set()
        _deduped = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            key = (f.get("url", ""), f.get("type", ""), f.get("title", ""),
                   (f.get("detail") or "")[:120])
            if key not in _seen:
                _seen.add(key)
                _deduped.append(f)
        _dropped = len(findings) - len(_deduped)
        if _dropped:
            i(f"Deduplicated {_dropped} finding(s) before verification")
        findings = _deduped

        spin = Spinner("Confirming vulnerabilities...")
        spin.start()

        def _audit_confirmed(f):
            """Persist confirmed finding + scan-time evidence to the audit trail."""
            try:
                from core.audit import AuditLogger
                AuditLogger.get_instance().log_finding(
                    f.get("title", ""),
                    f.get("severity") or finding_cvss(f)["v"],
                    f.get("url", ""),
                    f.get("detail", ""),
                    evidence=f.get("evidence", ""),
                )
            except Exception:
                pass

        async def _verify(f):
            """Verify a single finding in thread pool or async."""
            try:
                # POST-body re-verify (xxe_file) hanya di mode 4 (poisoning).
                result = await VulnVerifier.verify(f, async_engine, session_manager,
                                                   allow_post=(mode == "poisoning"))
                if result is None:
                    # Probe tak terkirim (budget habis / rate-limit / circuit
                    # open) — gagal kirim BUKAN bukti salah. Pertahankan
                    # temuan dengan confidence scan-time + peringatan, jangan
                    # dibuang senyap seperti perilaku lama.
                    w(f"verify untestable for {f.get('title','?')[:40]} "
                      "(probe not dispatched) — keeping finding as-is")
                    return f
                if result:
                    _audit_confirmed(f)
                    return f
            except Exception as e:
                w(f"verify error for {f.get('title','?')[:40]}: {str(e)[:60]}")
                if f.get("confidence") == "confirmed":
                    return f
            return None

        # Verify all findings in parallel
        tasks = [_verify(f) for f in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        verified = [r for r in results if r is not None and not isinstance(r, BaseException)]
        for f in verified:
            s(f"Confirmed: {G}{f.get('title', '?')}{N}")
        spin.stop()
        findings = verified

        # Phase 4.5: SQLi Data Extraction for confirmed findings
        sqli_findings = [f for f in findings if f.get("type") in ("sqli_error", "sqli_time") and f.get("confidence") == "confirmed"]
        if sqli_findings and async_engine:
            ph("Phase 4.5: SQLi Data Extraction")
            i(f"Attempting blind extraction on {W}{len(sqli_findings)}{N} confirmed SQLi targets...")

            async def _make_send_fn(eng, sm):
                """Create a send function compatible with BlindSQLiExtractor."""
                async def _send(url, param, payload, timeout=15):
                    target_url = inject_query_payload(url, param, payload)
                    return await eng.ahttp_send(target_url, timeout=timeout, state_context=sm)
                return _send

            send_fn = await _make_send_fn(async_engine, session_manager)
            extractor = BlindSQLiExtractor(send_fn=send_fn)

            for sqli_f in sqli_findings[:3]:  # Limit to 3 targets to avoid excessive requests
                try:
                    # Extract param name robustly
                    param_name = None
                    sqli_url = sqli_f.get("url") or ""
                    if not sqli_url:
                        continue
                    parsed_url = urlparse(sqli_url)
                    params = parse_qsl(parsed_url.query, keep_blank_values=True)
                    if params:
                        for k, v in params:
                            v_lower = str(v).lower()
                            if any(p in v_lower for p in ["'", '"', "sleep", "waitfor", "select", "union", "and", "or"]):
                                param_name = k
                                break
                        if not param_name:
                            param_name = params[0][0]
                    else:
                        param_match = re.search(r'Param:\s*(\w+)', sqli_f.get("detail", ""))
                        if param_match:
                            param_name = param_match.group(1)

                    if not param_name:
                        continue

                    # Strip the injected payload from URL to get the clean base URL
                    clean_query = []
                    for k, v in params:
                        if k == param_name:
                            clean_query.append((k, "1")) # Reset to safe default value
                        else:
                            clean_query.append((k, v))
                    from urllib.parse import urlunsplit
                    clean_url = urlunsplit((parsed_url.scheme, parsed_url.netloc, parsed_url.path, urlencode(clean_query), parsed_url.fragment))

                    extracted = await extractor.extract_all(clean_url, param_name)
                    if extracted:
                        for ex in extracted:
                            s(f"{R}SQLi Extracted:{N} {W}{ex.get('detail', '')}{N}")
                        findings.extend([ex for ex in extracted if isinstance(ex, dict)])
                except Exception as e:
                    w(f"SQLi extraction error: {str(e)[:80]}")

    ph("Phase 5: Kill Chain Summary")
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("url",""), f.get("type",""), f.get("title",""), (f.get("detail") or "")[:120])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: finding_cvss(f)["s"], reverse=True)
    # Tulis hasil akhir (verified + extracted, terdedup) ke list milik caller
    # — dulu hanya local rebind, .state tak pernah menyimpan hasil verify dan
    # resume mengulang Phase 4 penuh.
    caller_findings[:] = unique
    dur = time.time() - t0
    # Attach exact recorded requests (audit trail) so the report's PoC is a
    # real replay instead of a generic template when the jsonl has the URL.
    # Best-effort: a missing/unreadable audit file must not kill the report.
    from core.audit import AuditLogger, inject_replay_curls
    try:
        inject_replay_curls(unique, AuditLogger.get_instance().log_path)
    except Exception as e:
        w(f"Replay-curl injection failed (report will use generic PoC): {e}")
    rep = ReportEngine(target, unique, services, subs, scan_urls, dur, target_wafs, VERSION, AUTHOR, mode)
    # Each artifact separately guarded — one broken renderer (html/pdf) must
    # not prevent the others nor the console summary from running.
    try:
        rep.save_html()
    except Exception as e:
        w(f"HTML report generation failed: {e.__class__.__name__}: {str(e)[:120]}")
    try:
        rep.save_pdf()
    except Exception as e:
        w(f"PDF report generation failed: {e.__class__.__name__}: {str(e)[:120]}")
    try:
        rep.print_summary()
    except Exception as e:
        w(f"Console summary failed: {e.__class__.__name__}: {str(e)[:120]}")
    print(f"\n  {M}[ {chr(10086)} ]{N} {B}{W}SCAN COMPLETE: {target.upper()}{N}")
    print(f"  {D}{chr(9472)*65}{N}\n")


async def async_main():
    # Handle special commands
    if len(sys.argv) < 2 or sys.argv[1] in ("--help", "-h", "/h"):
        print_banner(VERSION, AUTHOR)
        draw_help_screen()
        sys.exit(0)

    if sys.argv[1] in ("--version", "/v"):
        print(f"verdamt-snipe v{VERSION}")
        sys.exit(0)

    if sys.argv[1] in ("--setup-wordlists",):
        from modules.wordlists import auto_setup_wordlists
        await auto_setup_wordlists(force="--force" in sys.argv)
        sys.exit(0)

    target_arg, flags, resume_path = parse_scan_args(sys.argv)

    # Bare --resume / -r without a path → default to the target's state file
    if not resume_path and "--resume" in flags:
        if not target_arg:
            print(f"{R}[!] --resume needs a state file path (or a target for outputs/<target>.state){N}")
            sys.exit(1)
        default_target, _ = parse_target(target_arg)
        resume_path = f"outputs/{sanitize_filename(default_target)}.state"

    if not target_arg and not resume_path:
        print(f"{R}[!] Target or --resume <state-file> is required{N}")
        sys.exit(1)

    auth_headers, auth_headers2 = parse_cli_headers(flags)
    mode_override = parse_mode(flags)

    is_turbo = "--turbo" in flags

    # Dork scraping + archive mining knobs. Defaults: scraping ON (fast-bails
    # by itself when search engines block the IP) and 90s archive budget —
    # 30s was too short for medium/large targets (wayback/Gau index fetch).
    no_dork = "--no-dork" in flags
    archive_timeout = None
    _archive_raw = _flag_value(flags, "--archive-timeout")
    if _archive_raw is not None:
        try:
            archive_timeout = int(_archive_raw)
            if archive_timeout <= 0:
                raise ValueError
        except (TypeError, ValueError):
            print(f"{R}[!] --archive-timeout needs a positive number of seconds{N}")
            sys.exit(2)

    resume_state = None
    if resume_path:
        if not os.path.exists(resume_path):
            print(f"{R}[!] State file not found: {resume_path}{N}"); sys.exit(1)
        resume_state = ProjectState.load(resume_path)
        target, seed_url = resume_state.target, resume_state.seed_url
        mode = mode_override or resume_state.mode
        print(f"{G}[V] Resumed project: {target} ({mode}){N}")
    else:
        target, seed_url = parse_target(target_arg)
        mode = mode_override

    try:
        policy_options = parse_scan_policy_options(flags)
        audit_log_path = policy_options.pop("audit_log", None)
        policy = ScanPolicy(target, **policy_options)
        from core.audit import AuditLogger
        log_file = audit_log_path or f"outputs/audit_{sanitize_filename(target)}.jsonl"
        AuditLogger.configure(log_file)
    except ValueError as exc:
        print(f"{R}[!] Invalid scan policy: {exc}{N}")
        sys.exit(2)

    scope_guard = policy.scope
    if policy.dry_run:
        w("DRY-RUN MODE ACTIVE: Payloads generated & authorized, no active network traffic dispatched.")

    if "--stealth" in flags:
        GhostMode.ENABLED = True
        w("GhostMode Enabled: Stealth Jitter, Rotating Headers, Camouflage Active.")
    if "--turbo" in flags:
        global VULN_THREADS
        VULN_THREADS = 50
        GhostMode.ENABLED = False
        w("TURBO MODE ACTIVE: Maxing out concurrency. No delays.")

    module_flags = {
        "jwt": "--jwt" in flags,
        "host": "--host-inject" in flags,
        "crlf": "--crlf" in flags,
        "stored_xss": "--stored-xss" in flags,
        "idor": "--idor" in flags,
    }
    # Parse proxy and timeout flags
    proxy_list = None
    proxy_url = None
    impersonate_browser = None
    proxy_rotate = 0
    max_time = None
    # --no-proxy: ignore VERDAMT_PROXY env (explicit --proxy/--proxy-list
    # still win; this only kills the automatic env fallback).
    no_proxy = "--no-proxy" in flags
    for idx, f in enumerate(flags):
        if f == "--max-time" and idx + 1 < len(flags):
            try:
                max_time = int(flags[idx + 1])
            except ValueError:
                pass
        elif f.startswith("--max-time="):
            try:
                max_time = int(f.split("=", 1)[1])
            except ValueError:
                pass
        if f == "--proxy-list" and idx + 1 < len(flags):
            proxy_list = flags[idx + 1]
        if f == "--proxy" and idx + 1 < len(flags):
            proxy_url = flags[idx + 1]
        elif f.startswith("--proxy="):
            proxy_url = f.split("=", 1)[1]
        if f == "--impersonate" and idx + 1 < len(flags):
            impersonate_browser = flags[idx + 1]
        elif f.startswith("--impersonate="):
            impersonate_browser = f.split("=", 1)[1]
        if f == "--proxy-rotate" and idx + 1 < len(flags):
            try:
                proxy_rotate = int(flags[idx + 1])
                if proxy_rotate < 0:
                    raise ValueError
            except ValueError:
                print(f"{R}[!] --proxy-rotate must be a non-negative integer{N}")
                sys.exit(2)

    # ProxyManager — unified proxy routing for ALL tools
    proxy_mgr = setup_proxy(
        proxy=proxy_url,
        proxy_file=proxy_list,
        rotate=proxy_rotate,
        use_env=not no_proxy,
    )
    if proxy_mgr.current_proxy:
        s(f"Proxy Active: {proxy_mgr.current_proxy} "
          f"({len(proxy_mgr.proxies)} loaded, "
          f"rotate={'every ' + str(proxy_rotate) + ' req' if proxy_rotate else 'off'})")

    from core.ui import console, ScanDashboard
    console.clear()
    t0 = time.time()

    dashboard = ScanDashboard.get_instance()
    dashboard.start(target=target, mode=(mode.upper() if mode else "FULL"), version=VERSION)

    ph(f"Target Locked: {target}")

    # Initialize async engine BEFORE camouflage (needs it)
    async_engine = AsyncNetworkEngine(
        max_connections=100,
        browser=impersonate_browser,
        policy=policy,
    )

    # Auto-stealth wiring: RateLimiter escalation toggles GhostMode stealth
    # headers per host. set_rate_limiter() was never called before, so
    # should_stealth() could never see is_auto_stealth() — the whole chain
    # (ratelimit escalation -> ghost headers) was unreachable in production.
    GhostMode.set_rate_limiter(get_global_rate_limiter())

    # === CAMOUFLAGE: Warm-up browsing before scan ===
    if GhostMode.ENABLED:
        ph("Camouflage: Warming up session")
        camo = CamouflageBrowser(async_engine)
        await camo.warm_up(seed_url, num_visits=3)
        s(f"Camouflage: visited {len(camo.visited)} pages — session looks human")

    if impersonate_browser:
        from core.curl_cffi_transport import CURL_CFFI_AVAILABLE, get_impersonate_target
        if CURL_CFFI_AVAILABLE:
            target_name = get_impersonate_target(impersonate_browser)
            s(f"Impersonation Active: {target_name} (TLS fingerprint spoofing)")
        else:
            w("curl_cffi not installed — impersonation disabled")
    else:
        from core.curl_cffi_transport import CURL_CFFI_AVAILABLE
        if CURL_CFFI_AVAILABLE:
            s("TLS Fingerprint: Chrome (curl_cffi default)")
        else:
            w("curl_cffi not installed — using raw socket")

    session_manager = SessionManager()
    if resume_state:
        session_manager.auth_tokens = dict(resume_state.auth_tokens)
        session_manager.cookies = dict(resume_state.cookies)
        session_manager.local_storage = dict(resume_state.local_storage)
    seed_session_headers(session_manager, seed_url, auth_headers)

    if resume_state:
        subs = list(resume_state.subs)
        services = list(resume_state.services)
        scan_urls = list(resume_state.scan_urls)
        all_findings = list(resume_state.findings)
        params = dict(resume_state.params)
        target_wafs = list(resume_state.target_wafs)
        t0 = resume_state.t0
        print(f"  {GY}..{N} Skipped Phase 0 (surface) — loaded from state")
    else:
        subs, services, scan_urls = await run_surface_scan(
            target,
            seed_url,
            scope_guard,
            proxy=proxy_mgr.current_proxy,
            policy=policy,
        )
        all_findings = []
        params = {}
        target_wafs = []

    if not mode:
        dashboard.stop()
        # Build settings dict for interactive TUI
        settings = {
            'stealth': GhostMode.ENABLED,
            'turbo': '--turbo' in flags,
            'proxy': proxy_url,
            'impersonate': impersonate_browser,
        }
        mode, settings = interactive_mode_select(target, settings)
        # Apply settings from TUI
        if settings.get('stealth'):
            GhostMode.ENABLED = True
        if settings.get('turbo'):
            is_turbo = True
            # Same mutations as the --turbo flag path (previously the TUI
            # toggle only flipped is_turbo — concurrency stayed at default).
            VULN_THREADS = 50
            GhostMode.ENABLED = False
            w("TURBO MODE ACTIVE: Maxing out concurrency. No delays.")
        if settings.get('proxy') and not proxy_url:
            proxy_url = settings['proxy']
            proxy_mgr = setup_proxy(proxy=proxy_url, proxy_file=proxy_list,
                                rotate=proxy_rotate, use_env=not no_proxy)
            if proxy_mgr.current_proxy:
                s(f"Proxy Active: {proxy_mgr.current_proxy}")
        if settings.get('impersonate') and not impersonate_browser:
            impersonate_browser = settings['impersonate']

        dashboard.start(target=target, mode=mode.upper(), version=VERSION)

    i(f"Selected Mode: {W}{mode.upper()}{N}")

    def save_project_state():
        def _strip_ip_keys(mapping):
            # Key IP hasil mirror origin-IP hanya untuk run berjalan (dibangun
            # ulang tiap kali) — menyimpannya menodai .state dengan entri
            # sekali pakai yang tak relevan saat resume lewat domain.
            out = {}
            for k, v in (mapping or {}).items():
                host = str(k).split(":")[0].strip("[]")
                try:
                    ipaddress.ip_address(host)
                    continue
                except ValueError:
                    out[k] = v
            return out

        st = ProjectState(
            target=target, seed_url=seed_url, mode=mode, version=VERSION,
            subs=subs, services=services, scan_urls=scan_urls,
            findings=all_findings, params=params, target_wafs=list(set(target_wafs)),
            auth_tokens=_strip_ip_keys(session_manager.auth_tokens),
            cookies=_strip_ip_keys(session_manager.cookies),
            local_storage=dict(session_manager.local_storage), t0=t0,
            phase_done_assault=(mode == "assault" and mode_completed))
        path = st.save()
        print(f"  {GY}..{N} State saved: {C}{path}{N}")

    # === MODE EXECUTION ===
    # Crash-safety contract (Paket 4): any failure/interrupt below must
    # still (a) kill tracked tool processes, (b) persist project state,
    # (c) stop the dashboard, (d) run verify+report on whatever findings
    # we already have, and (e) close the engine/browser pool. Before this
    # only the --max-time path saved state; a mid-mode crash lost the run,
    # skipped the report entirely and leaked engine/dashboard/browser.
    interrupted = False
    # phase_done_assault hanya True bila mode selesai SUKSES (tidak saat
    # crash/timeout yang menyimpan state darurat) — flag dipakai resume
    # untuk melewati re-run penuh Phase 3.
    mode_completed = False
    # Mode crash: `raise` langsung di dalam except dulu melewati blok
    # verify/report+cleanup di bawah — crash sebelum Phase 4 selesai TIDAK
    # pernah menghasilkan report dan resume mengulang dari awal (persis
    # keluhan "mental sebelum verification, balik ke WAF risk assessment
    # lagi"). Exception ditahan dulu, verify/report+cleanup jalan di
    # finally, baru di-raise lagi supaya exit code tetap non-zero.
    mode_error = None
    skip_assault = (resume_state is not None and mode == "assault"
                    and getattr(resume_state, "phase_done_assault", False))
    try:
        try:
            if skip_assault:
                i("Assault phase already completed (state flag) — skipping re-run, "
                  "proceeding to verify/report only")
            elif max_time:
                i(f"Global Time Limit set to {W}{max_time}s{N}")
                try:
                    await asyncio.wait_for(
                        _execute_mode(
                            mode, target, seed_url, services, subs, scan_urls, params,
                            all_findings, target_wafs, scope_guard, session_manager,
                            auth_headers, auth_headers2, async_engine, is_turbo,
                            module_flags,
                            save_project_state,
                            max_time,
                            policy,
                            no_dork=no_dork,
                            archive_timeout=archive_timeout,
                        ),
                        timeout=max_time
                    )
                except asyncio.TimeoutError:
                    w(f"Scan timed out after {max_time} seconds! Saving findings and proceeding to reporting...")
                    # Tracker A:521: cancellation never stops a thread already
                    # inside subprocess.run — terminate the tool processes or
                    # nuclei/dalfox keep hitting the target past --max-time and
                    # asyncio.run joins them at exit (process outlives report).
                    from core.external_tools import kill_active_procs
                    kill_active_procs(f"--max-time {max_time}s")
                    # Old path skipped save entirely: .state lost everything the
                    # timeout interrupted; resume would restart from stale data.
                    try:
                        save_project_state()
                    except Exception as e:
                        w(f"State save after timeout failed: {e}")
            else:
                await _execute_mode(
                    mode, target, seed_url, services, subs, scan_urls, params,
                    all_findings, target_wafs, scope_guard, session_manager,
                    auth_headers, auth_headers2, async_engine, is_turbo,
                    module_flags,
                    save_project_state,
                    None,
                    policy,
                    no_dork=no_dork,
                    archive_timeout=archive_timeout,
                )
            mode_completed = True
        except KeyboardInterrupt:
            interrupted = True
            from core.external_tools import kill_active_procs
            kill_active_procs("interrupted by user")
            try:
                save_project_state()
            except Exception as e:
                w(f"State save after interrupt failed: {e}")
            raise
        except BaseException as e:
            # Jangan raise di sini — tahan sampai finally di bawah selesai
            # mengurus verify/report + cleanup, lalu dilempar lagi.
            mode_error = e
            w(f"Mode '{mode}' crashed: {e.__class__.__name__}: {str(e)[:160]} — "
              "saving state, still reporting what we have")
            from core.external_tools import kill_active_procs
            kill_active_procs(f"mode {mode} crashed")
            try:
                save_project_state()
            except Exception as se:
                w(f"State save after failure failed: {se}")
    finally:
        # verify/report + cleanup — SELALU jalan, termasuk saat mode crash
        # di tengah jalan (exception di atas ditahan, bukan langsung
        # di-raise). Ctrl+C tetap melewati verify/report (user minta stop),
        # tapi cleanup engine/browser/dashboard tetap dijalankan.
        try:
            dashboard.stop()
            if not interrupted:
                # Ctrl+C skips network verify/report (user asked to stop) but a
                # crashed mode still gets its partial findings reported.
                try:
                    await phase_verify_report(target, all_findings, services, subs, scan_urls, list(set(target_wafs)), t0, mode, async_engine, session_manager)
                    # Simpan state FINAL: findings terverifikasi (+ ekstraksi
                    # SQLi) sudah mengisi all_findings in-place — resume tak
                    # perlu mengulang Phase 4 penuh.
                    try:
                        save_project_state()
                    except Exception:
                        pass
                except Exception as e:
                    w(f"Verify/report phase failed: {e.__class__.__name__}: {str(e)[:160]}")
                    try:
                        save_project_state()
                    except Exception:
                        pass
        finally:
            try:
                await async_engine.close()
            except Exception as e:
                w(f"Engine close failed: {e}")
            try:
                from core.browser_pool import SharedBrowserPool
                await SharedBrowserPool.shutdown()
            except Exception as e:
                w(f"Browser pool shutdown failed: {e}")

    if mode_error is not None:
        # Re-raise SETELAH state tersimpan + report jadi + engine ditutup.
        raise mode_error


async def _execute_mode(
    mode, target, seed_url, services, subs, scan_urls, params,
    all_findings, target_wafs, scope_guard, session_manager,
    auth_headers, auth_headers2, async_engine, is_turbo,
    module_flags,
    save_project_state,
    max_time=None,
    policy=None,
    no_dork=False,
    archive_timeout=None,
):
    """Execute the selected scan mode."""

    if policy and policy.mode == "passive" and mode in {"app", "assault", "poisoning", "full", "nuclei"}:
        w(f"Passive policy blocked active mode: {mode}")
        save_project_state()
        return

    if mode == "nuclei":
        from core.external_tools import run_nuclei
        ntargets = [s["url"] for s in services] + scan_urls[:100]
        nauth = session_manager.auth_headers_for(target) if session_manager else {}
        # to_thread, NOT a direct call: run_nuclei is blocking — inline it
        # froze the event loop, so asyncio.wait_for's --max-time timer
        # never fired for mode 7 (verified live 2026-10-06: 3s nuclei run
        # under timeout=1 completed "normally"). Cancellation + the
        # kill_active_procs registry now terminate it properly.
        all_findings.extend(await asyncio.to_thread(
            run_nuclei, ntargets, auth_headers=nauth or None, policy=policy))
        i(f"Nuclei scan complete: {W}{len(all_findings)}{N} findings")
        save_project_state()

    elif mode == "recon":
        recon_f, recon_u = await run_recon_intel(
            target, services, subs, scan_urls, scope_guard, async_engine,
            is_turbo, session_manager=session_manager, policy=policy,
            no_dork=no_dork, archive_timeout=archive_timeout,
        )
        all_findings.extend(recon_f)
        merged = sorted(set(scan_urls + recon_u))
        scan_urls.clear()
        scan_urls.extend(merged)
        save_project_state()

    elif mode == "recon_light":
        light_f, light_u = await run_recon_light(
            target, seed_url, services, subs, scan_urls, scope_guard,
            async_engine, is_turbo, session_manager=session_manager,
        )
        all_findings.extend(light_f)
        merged = sorted(set(scan_urls + light_u))
        scan_urls.clear()
        scan_urls.extend(merged)
        save_project_state()

    elif mode == "app":
        await _run_app_mode(
            target, seed_url, services, subs, scan_urls, scope_guard, session_manager,
            auth_headers, auth_headers2, async_engine, is_turbo, all_findings,
            params, policy=policy,
        )
        save_project_state()

    elif mode == "assault":
        await _run_assault_mode(
            target, seed_url, services, subs, scan_urls, scope_guard, session_manager,
            auth_headers, auth_headers2, async_engine, is_turbo, all_findings,
            params, target_wafs, module_flags, policy=policy,
            no_dork=no_dork, archive_timeout=archive_timeout,
        )
        save_project_state()

    elif mode == "poisoning":
        await _run_poisoning_mode(
            target, seed_url, services, subs, scan_urls, scope_guard, session_manager,
            auth_headers, auth_headers2, async_engine, is_turbo, all_findings,
            params, target_wafs, module_flags, max_time, policy=policy,
        )
        save_project_state()

    elif mode == "full":
        full_f, full_p, full_u, full_w = await run_full_assault(
            target, seed_url, services, subs, scan_urls, scope_guard, session_manager,
            auth_headers, auth_headers2, async_engine, VULN_THREADS, is_turbo,
            module_flags=module_flags, policy=policy,
            no_dork=no_dork, archive_timeout=archive_timeout,
            max_time=max_time,
        )
        all_findings.extend(full_f)
        params.update(full_p)
        merged = sorted(set(scan_urls + full_u))
        scan_urls.clear()
        scan_urls.extend(merged)
        target_wafs.extend(full_w)
        save_project_state()
    else:
        w(f"Unknown mode: {mode}")


async def _run_app_mode(target, seed_url, services, subs, scan_urls, scope_guard, session_manager, auth_headers, auth_headers2, async_engine, is_turbo, all_findings, params, policy=None):
    """App analysis mode: WAF/origin hunt + light-crawl analysis.

    Katana tidak berjalan di sini (mode 3-5 punya fase Katana Crawl resmi);
    crawl ringan mode 2 memakai DeepCrawler di dalam run_app_analysis.
    """
    await run_waf_origin_phase(target, services, subs, policy=policy)
    f, p, u = await run_app_analysis(
        target, seed_url, services, scan_urls, scope_guard, session_manager,
        auth_headers, auth_headers2, async_engine, is_turbo, policy=policy,
    )
    all_findings.extend(f); params.update(p)
    scan_urls.clear()
    scan_urls.extend(u)


async def _run_assault_mode(target, seed_url, services, subs, scan_urls, scope_guard, session_manager, auth_headers, auth_headers2, async_engine, is_turbo, all_findings, params, target_wafs, module_flags=None, policy=None, no_dork=False, archive_timeout=None):
    """Assault mode: auto-enrich (recon → katana → app) → WAF → assault.

    Fase enrichment HANYA berjalan saat korpus/param kosong dan tampil sebagai
    fase resmi di dashboard/README (Auto-Recon / Katana Crawl / Auto-App —
    kontrak sama dengan _PIPELINE_STAGES_BY_MODE["ASSAULT"]). Best-effort:
    kegagalan satu fase lanjut dengan data yang ada. Kegagalan
    run_vuln_assault TIDAK ditelan: async_main menyimpan state, tetap
    verify/report, lalu melempar ulang supaya exit code non-zero.
    """
    need_enrich = not params

    # Korpus/param sudah ada (mode 1/2 dijalankan lebih dulu) → tandai fase
    # enrichment sebagai skipped, jangan seolah-olah "completed".
    if not need_enrich and ScanDashboard.active():
        dash = ScanDashboard.get()
        for kw in ("auto-recon", "katana crawl", "auto-app"):
            dash.mark_stage_status("skipped", kw)

    if need_enrich and len(scan_urls) <= len(services):
        ph("AUTO-RECON: Collecting intel before assault")
        try:
            f, u = await run_recon_intel(
                target, services, subs, scan_urls, scope_guard, async_engine,
                is_turbo, session_manager=session_manager, policy=policy,
                no_dork=no_dork, archive_timeout=archive_timeout,
            )
            all_findings.extend(f)
            scan_urls.clear()
            scan_urls.extend(u)
        except Exception as e:
            w(f"AUTO-RECON failed: {str(e)[:80]} — continuing with existing URLs")

    if need_enrich:
        ph("KATANA CRAWL: Expanding endpoint & parameter corpus")
        kr = await run_katana_phase(seed_url, policy=policy)
        crawled = scope_guard.filter_urls(kr.get("endpoints", []) or [])
        if crawled:
            merged = sorted(set(scan_urls + crawled))
            scan_urls.clear()
            scan_urls.extend(merged)
        bucket = params.setdefault("/", [])
        for _p in (kr.get("params") or []):
            if _p not in bucket:
                bucket.append(_p)

    if need_enrich:
        ph("AUTO-APP: Analyzing application structure")
        try:
            f, p, u = await run_app_analysis(
                target, seed_url, services, scan_urls, scope_guard, session_manager,
                auth_headers, auth_headers2, async_engine, is_turbo, policy=policy,
            )
            all_findings.extend(f); params.update(p)
            scan_urls.clear()
            scan_urls.extend(u)
        except Exception as e:
            w(f"AUTO-APP failed: {str(e)[:80]} — continuing with existing data")

    # WAF/origin — satu implementasi bersama mode 2/5 (dulu blok salinan).
    await run_waf_origin_phase(target, services, subs, policy=policy)

    f, wl = await run_vuln_assault(
        target, services, scan_urls, params, scope_guard, session_manager,
        async_engine, VULN_THREADS, is_turbo, module_flags=module_flags,
        policy=policy,
    )
    all_findings.extend(f); target_wafs.extend(wl)


async def _run_poisoning_mode(target, seed_url, services, subs, scan_urls, scope_guard, session_manager, auth_headers, auth_headers2, async_engine, is_turbo, all_findings, params, target_wafs, module_flags=None, max_time=None, policy=None):
    """Poisoning mode: cache poison + smuggling + bruteforce + flood + connection exhaust."""
    ph("POISONING MODE: Event-Driven Orchestrator")
    # Merge auth headers
    combined_headers = dict(auth_headers or {})
    if auth_headers2:
        combined_headers.update(auth_headers2)
    result = await run_poison_assault(
        target, seed_url, services, subs, scan_urls,
        scope_guard, session_manager, async_engine,
        is_turbo=is_turbo, module_flags=module_flags,
        auth_headers=combined_headers,
        max_duration=max_time or 120,
        policy=policy,
    )
    poison_f, poison_p, poison_u, poison_w = result if result else ([], {}, [], [])
    all_findings.extend(poison_f)
    params.update(poison_p)
    merged = sorted(set(scan_urls + poison_u))
    scan_urls.clear()
    scan_urls.extend(merged)
    target_wafs.extend(poison_w)


# Entry alias consumed by verd.main() / asyncio.run(main_cli()).
main_cli = async_main
