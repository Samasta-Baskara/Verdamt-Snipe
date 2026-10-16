"""Scan orchestration — async_main/main_cli entry, crash-safety wrapper,
interactive TUI mode selection.

Split out of core/cli_parser.py (Tahap 3): parsing stays in
core.cli_parser, mode dispatch in core.modes.
"""
import asyncio
import ipaddress
import os
import sys
import time

from core import cli_parser as _cli
from core.camouflage import CamouflageBrowser
from core.cli_parser import (
    AUTHOR,
    VERSION,
    _flag_value,
    parse_cli_headers,
    parse_mode,
    parse_scan_args,
    parse_scan_policy_options,
    parse_target,
    seed_session_headers,
)
from core.client import AsyncNetworkEngine
from core.http_client import GhostMode
from core.modes import _execute_mode, phase_verify_report
from core.policy import ScanPolicy
from core.project import ProjectState, sanitize_filename
from core.proxy_manager import get_global_proxy_manager, setup_proxy
from core.ratelimit import get_global_rate_limiter
from core.state import SessionManager
from core.ui import (
    _IMPERSONATE_OPTS,
    _MODES,
    GY,
    C,
    G,
    N,
    R,
    ScanDashboard,
    W,
    console,
    draw_confirm_bar,
    draw_help_screen,
    draw_interactive_menu,
    i,
    ph,
    print_banner,
    s,
    w,
)
from runners.surface import run_surface_scan


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
            mode_id = _MODES[selected_mode][0]
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


def _active_proxy():
    """Current proxy from ProxyManager singleton (flag-only: None when unset)."""
    pm = get_global_proxy_manager()
    return pm.current_proxy if pm and pm.current_proxy else None


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
        _cli.VULN_THREADS = 50
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
            _cli.VULN_THREADS = 50
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
                except TimeoutError:
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


# Entry alias consumed by verd.main() / asyncio.run(main_cli()).
main_cli = async_main
