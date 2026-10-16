"""Scan-mode execution + finding verification/report phases.

_execute_mode dispatches the selected pipeline; phase_verify_report is
the shared Phase 4/5 (verify + SQLi extraction + kill-chain report).
Split out of core/cli_parser.py (Tahap 3).
"""
import asyncio
import re
import time
from urllib.parse import urlparse, parse_qsl, urlencode

from core import cli_parser as _cli
from core.cli_parser import AUTHOR, VERSION
from core.ui import ph, i, w, s, Spinner, ScanDashboard, G, R, B, W, N, M, D
from modules.scanners import VulnVerifier
from modules.web.server_side.blind_sqli_extract import BlindSQLiExtractor
from runners.shared import inject_query_payload, run_katana_phase, run_waf_origin_phase
from reports.engine import ReportEngine, finding_cvss
from runners.recon_intel import run_recon_intel
from runners.recon_light import run_recon_light
from runners.app_analysis import run_app_analysis
from runners.vuln_assault import run_vuln_assault
from runners.full_assault import run_full_assault
from runners.poison import run_poison_assault


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
            auth_headers, auth_headers2, async_engine, _cli.VULN_THREADS, is_turbo,
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
        async_engine, _cli.VULN_THREADS, is_turbo, module_flags=module_flags,
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
