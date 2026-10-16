from core.ui import ph, w
from runners.app_analysis import run_app_analysis
from runners.poison import run_poison_assault
from runners.recon_intel import run_recon_intel
from runners.shared import run_katana_phase, run_waf_origin_phase
from runners.vuln_assault import run_vuln_assault


async def run_full_assault(
    target,
    seed_url,
    services,
    subs,
    scan_urls,
    scope_guard,
    session_manager,
    auth_headers,
    auth_headers2,
    async_engine,
    vuln_threads,
    is_turbo=False,
    module_flags=None,
    policy=None,
    no_dork=False,
    archive_timeout=None,
    max_time=None,
):
    """Option 5: recon → katana → app → WAF → assault → poisoning.

    Pipeline komposit = rangkaian fase milik mode rumahnya (1 → Katana → 2 →
    3 → 4). Tidak ada tool yang muncul di luar peta modul: Katana crawl
    adalah fase resmi (mode 2 memakai DeepCrawler), dan poisoning (mode 4)
    ikut sebagai fase terakhir — termasuk probe POST-body yang hanya hidup
    di sana.
    """
    all_findings = []
    params = {}
    target_wafs = []
    # Work on a copy to avoid mutating caller's list
    current_urls = list(scan_urls)

    # Phase 1: Recon Intel
    try:
        findings, urls = await run_recon_intel(
            target, services, subs, current_urls, scope_guard,
            async_engine, is_turbo, session_manager=session_manager, policy=policy,
            no_dork=no_dork, archive_timeout=archive_timeout,
        )
        all_findings.extend(findings)
        current_urls = list(urls)
    except Exception as e:
        w(f"Recon failed: {str(e)[:80]} — continuing with existing URLs")

    # Phase 2a: Katana Crawl — fase resmi mode assault-class (3/4/5);
    # mode 2 tidak crawl berat (DeepCrawler ringan di run_app_analysis).
    try:
        ph("KATANA CRAWL: Expanding endpoint & parameter corpus")
        kr = await run_katana_phase(seed_url, policy=policy)
        crawled = scope_guard.filter_urls(kr.get("endpoints", []) or [])
        if crawled:
            current_urls = sorted(set(current_urls + crawled))
        bucket = params.setdefault("/", [])
        for _p in (kr.get("params") or []):
            if _p not in bucket:
                bucket.append(_p)
    except Exception as e:
        w(f"Katana crawl failed: {str(e)[:80]} — continuing without crawl data")

    # Phase 2b: App Analysis
    try:
        findings, discovered_params, urls = await run_app_analysis(
            target,
            seed_url,
            services,
            current_urls,
            scope_guard,
            session_manager,
            auth_headers,
            auth_headers2,
            async_engine,
            is_turbo,
            policy,
        )
        all_findings.extend(findings)
        params.update(discovered_params)
        current_urls = list(urls)
    except Exception as e:
        w(f"App analysis failed: {str(e)[:80]} — continuing with existing data")

    # Phase 3a: WAF / origin hunt — dulu hilang di mode 5 (mode 2/3 punya,
    # jadi full tidak pernah identik dengan 1+2+3). Satu implementasi
    # bersama; menyiapkan origin IP untuk fase assault.
    try:
        await run_waf_origin_phase(target, services, subs, policy=policy)
    except Exception as e:
        w(f"Origin hunt failed: {str(e)[:80]} — scanning through WAF")

    # Phase 3b: Vuln Assault
    try:
        findings, wafs = await run_vuln_assault(
            target,
            services,
            current_urls,
            params,
            scope_guard,
            session_manager,
            async_engine,
            vuln_threads,
            is_turbo=is_turbo,
            module_flags=module_flags,
            policy=policy,
        )
        all_findings.extend(findings)
        target_wafs.extend(wafs)
    except Exception as e:
        w(f"Vuln assault failed: {str(e)[:80]}")

    # Phase 4: Poisoning (mode 4) — termasuk probe POST-body (h2 smuggling
    # CL.TE, stored-XSS form, blind XXE) yang hanya berjalan di fase ini.
    try:
        combined_auth = dict(auth_headers or {})
        if auth_headers2:
            combined_auth.update(auth_headers2)
        poison_result = await run_poison_assault(
            target, seed_url, services, subs, current_urls,
            scope_guard, session_manager, async_engine,
            is_turbo=is_turbo, module_flags=module_flags,
            auth_headers=combined_auth,
            max_duration=max_time or 120,
            policy=policy,
        )
        pf, pp, pu, pw = poison_result if poison_result else ([], {}, [], [])
        all_findings.extend(pf)
        params.update(pp)
        current_urls = sorted(set(current_urls + list(pu)))
        target_wafs.extend(pw)
    except Exception as e:
        w(f"Poisoning failed: {str(e)[:80]} — continuing to verify/report")

    return all_findings, params, current_urls, target_wafs
