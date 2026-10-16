import asyncio
from urllib.parse import urlparse, urlunparse
from modules.auth.bypass import WAFBypass
from core.external_tools import run_dalfox, run_nuclei
from core.proxy_manager import get_global_proxy_manager
from core.ui import B, C, N, R, Spinner, W, Y, i, ph, s, w
from modules.extras.oob_detector import OOBDetector
from modules.recon import ParamExtractor
from modules.scanners import AsyncVulnEngine, HeuristicVulnEngine
from runners.shared import PARAM_TARGET_CAP, build_param_scan_targets, build_param_url


def _current_proxy():
    """Proxy aktif dari ProxyManager (flag-only: None bila tak diset)."""
    pm = get_global_proxy_manager()
    return pm.current_proxy if pm and pm.current_proxy else None

# Timeout per modul (detik) — backstop anti-hang di gather raksasa.
# nuclei(300)/dalfox(180)/oob(60) punya timeout internal + partial salvage,
# jadi backstop-nya LEBIH GEDE biar mekanisme internal tetap kepakai.
# Modul async engine lain tanpa batas -> di-bound di sini.
MODULE_TIMEOUTS = {
    "nuclei": 360, "dalfox": 240, "internal_injection": 600,
    "smuggling": 150, "oob": 70, "jwt": 90, "host_header": 90,
    "crlf": 90, "stored_xss": 180, "idor": 120,
}

# Kerja serial SEBELM gather (param mining, waf risk) juga butuh backstop —
# dulu tanpa batas, satu kegantungan menggagalkan seluruh phase 3 senyap.
PRE_GATHER_TIMEOUTS = {
    "param_extractor": 90,
    "waf_risk": 60,
}


async def run_vuln_assault(
    target: str,
    services,
    scan_urls,
    params,
    scope_guard,
    session_manager,
    async_engine,
    vuln_threads: int = 25,
    is_turbo: bool = False,
    module_flags: dict = None,
    policy=None,
    allow_post: bool = False,
):
    """Option 3: vulnerability assault and active fuzzing.

    allow_post: POST-body probes (h2 smuggling CL.TE, stored-XSS form
    submission, OOB blind XXE) only run when the caller opts in — the ONLY
    caller that does is mode 4 (poisoning). Default False = mode 3 / full
    stay path-discovery + GET param injection only.
    """
    if policy and policy.mode == "passive":
        return [], []

    ph("PHASE 3: VULNERABILITY ASSAULT")
    findings = []

    selected_web_modules = {k for k, v in (module_flags or {}).items() if v}
    # Focus mode: ada flag fokus (--jwt dst) -> CUMA modul web fokus jalan.
    # Scanner generik (nuclei/dalfox/injection/smuggle/OOB) ikut OFF — kontrak
    # "module lain OFF" di docs sebelumnya cuma berlaku buat 5 modul web.
    focus_mode = bool(selected_web_modules)
    if focus_mode:
        i(f"Focus mode ({', '.join(sorted(selected_web_modules))}) — "
          "nuclei/dalfox/injection/smuggle/OOB OFF")

    def web_module_enabled(name: str) -> bool:
        return not selected_web_modules or name in selected_web_modules

    if not params:
        try:
            mined = await asyncio.wait_for(
                ParamExtractor(scan_urls).run(),
                timeout=PRE_GATHER_TIMEOUTS["param_extractor"],
            ) or {}
        except asyncio.TimeoutError:
            w(f"param extraction timed out after "
              f"{PRE_GATHER_TIMEOUTS['param_extractor']}s — continuing without mined params")
            mined = {}
        except Exception as e:
            w(f"param extraction failed: {e.__class__.__name__}: {str(e)[:80]}")
            mined = {}
        if isinstance(mined, dict):
            # Tulis balik ke dict MILIK CALLER (dulu rebind lokal → hasil
            # mining tak pernah masuk .state; resume mengulang kerja yang
            # sama). params dikosongkan via clear/update agar referensi
            # asli ikut berubah.
            params.clear()
            params.update(mined)

    target_wafs = set()
    for service in services:
        for waf in service.get("waf", []):
            target_wafs.add(waf)

    if target_wafs:
        print(f"\n  {R}{B}PROTECTION DETECTED:{N} {', '.join(target_wafs)}")
        wrisk = None
        try:
            wrisk = await asyncio.wait_for(
                asyncio.to_thread(
                    HeuristicVulnEngine.waf_risk_test,
                    services[0]["url"],
                    list(target_wafs),
                    policy,
                ),
                timeout=PRE_GATHER_TIMEOUTS["waf_risk"],
            )
        except asyncio.TimeoutError:
            w(f"WAF risk assessment timed out after "
              f"{PRE_GATHER_TIMEOUTS['waf_risk']}s — skipping verdict")
        except Exception as e:
            w(f"WAF risk assessment failed: {e.__class__.__name__}: {str(e)[:80]}")
        if wrisk:
            if wrisk["risk"] == "Critical":
                print(f"  {R}{B}!! CRITICAL WAF RISK:{N} {wrisk['reason']}")
            else:
                i(f"WAF Risk Assessment: {Y}{wrisk['risk']}{N}")

    # dedup — URL service biasanya juga ada di scan_urls; tanpa ini nuclei
    # nembak URL yang sama berkali-kali.
    targets = list(dict.fromkeys(
        [service["url"] for service in services] + (scan_urls or [])))
    scan_urls_origin = list(scan_urls)
    original_domain = urlparse(services[0]["url"]).netloc if services else urlparse(target).netloc
    
    # Origin IP passthrough: replace domain with origin IP
    origin_ip = None
    for service in services:
        if service.get("origin_ip"):
            origin_ip = service["origin_ip"]
            break
            
    if origin_ip:
        i(f"Using origin IP {origin_ip} for direct scan — WAF by-passed")
        if policy:
            # Origin IP = aset target yang sama di balik WAF. Tanpa ini,
            # policy.filter_urls membuang semua URL IP dari nuclei/dalfox
            # (dan finding-nya) dengan alasan out_of_scope_host.
            policy.authorize_host(origin_ip)
        def replace_host(url: str) -> str:
            parsed = urlparse(url)
            # Preserve original port if non-standard
            original_port = parsed.port
            if original_port and original_port not in (80, 443):
                new_netloc = f"{origin_ip}:{original_port}"
            else:
                new_netloc = origin_ip
            return urlunparse((parsed.scheme, new_netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
            
        # Peta Host asli untuk SEMUA modul async: ahttp_send / AsyncVulnEngine
        # membaca origin_host_overrides (per-URL) dan origin_host_map (per-IP)
        # lalu memasang header Host otomatis — dulu hanya nuclei/dalfox yang
        # mendapat Host, lima modul web + injection menembak vhost default
        # (Host: <IP>) = false negative senyap saat WAF-bypass.
        # Dibangun SEBELUM rewrite, dari URL sumber yang masih ber-domain.
        if async_engine is not None:
            async_engine.origin_host_map = {origin_ip: original_domain}
            overrides = {}
            for src in [service["url"] for service in services] + list(scan_urls or []):
                overrides[replace_host(src)] = urlparse(src).netloc
            async_engine.origin_host_overrides = overrides

        targets = [replace_host(t) for t in targets]
        scan_urls_origin = [replace_host(u) for u in scan_urls]
        
        # Salinan lokal ber-IP — services asli JANGAN dimutasi, karena list itu
        # dibawa pulang ke verd.py dan ke-save ke outputs/<target>.state.
        # Mutasi lama bikin resume/report bawa URL IP, bukan domain.
        services = [dict(sv, url=replace_host(sv["url"])) for sv in services]

        # Add Host header via session manager
        if session_manager:
            # Token DAN cookie host asli diduplikasi ke key hostname IP
            # (dulu cuma auth_tokens dengan exact-match rapuh; cookies tak
            # ikut sama sekali → request origin-IP kehilangan sesi login).
            for service in services:
                ip_host = urlparse(service["url"]).hostname
                if ip_host:
                    session_manager.mirror_host(original_domain, ip_host)
        i("  Origin IP applied to all scan targets")

    # Build auth headers from session manager for nuclei (domain-matched)
    nuclei_auth = session_manager.auth_headers_for(target) if session_manager else {}
            
    dalfox_headers = {}
    if origin_ip:
        nuclei_auth["Host"] = original_domain
        dalfox_headers["Host"] = original_domain

    # Collect tech tags for nuclei template selection
    tech_tags = []
    for service in services:
        tech_str = service.get("tech", "")
        if tech_str:
            tech_tags.extend(t.strip() for t in tech_str.split(",") if t.strip())

    async def _run_nuclei_tool():
        if focus_mode:
            return []
        # Proxy harus diteruskan: hunt_origin sudah memakai proxy aktif:,
        # tapi nuclei/dalfox dulu connect langsung dengan IP asli —
        # inkonsistensi opsec/routing pada scan ber-proxy.
        return await asyncio.to_thread(
            run_nuclei, targets, auth_headers=nuclei_auth or None,
            tech_tags=tech_tags or None, policy=policy,
            proxy=_current_proxy(),
        )

    # Batas pair: ~25 request/pair x 11k pair = 275k request vs budget 10000.
    # Audit contoh: 14.349 request (59%) mati sebagai policy_denied.
    # Injection cuma ambil maks separuh sisa budget — modul lain tetap kebagian.
    # Dulu ada floor max(50, ...) yang MEMAKSA ≥50 pair (~1.250 request)
    # walau sisa budget mendekati 0; kini 0 sisa = 0 pair, dengan pesan jelas.
    target_cap = PARAM_TARGET_CAP
    if policy and policy.requests_remaining is not None:
        target_cap = min(PARAM_TARGET_CAP, policy.requests_remaining // 50)
    d_targets = (build_param_scan_targets(scan_urls_origin, params,
                                          max_targets=target_cap)
                 if target_cap > 0 else [])
    if not d_targets and policy and policy.requests_remaining == 0:
        w("internal injection & dalfox skipped — request budget exhausted")
    dalfox_urls = [build_param_url(url, url, param) for url, param in d_targets]
    async def _run_dalfox_tool():
        if focus_mode:
            return []
        return await asyncio.to_thread(
            run_dalfox, dalfox_urls, headers=dalfox_headers or None,
            policy=policy, proxy=_current_proxy(),
        )

    async def _run_internal_injection():
        if focus_mode or not d_targets:
            return []
        i(f"Starting internal injection testing on {W}{len(d_targets)}{N} dynamic paths...")
        async_vuln_engine = AsyncVulnEngine(
            async_engine,
            session_manager=session_manager,
            concurrency=vuln_threads,
            allow_post=allow_post,
        )
        return await async_vuln_engine.scan_many(d_targets)

    async def _run_smuggling():
        smuggling_findings = []
        if focus_mode:
            return smuggling_findings
        if not allow_post:
            # h2_smuggle_check = POST-only probe (CL.TE/TE.CL bodies, bypass.py:530).
            # Aturan: POST-body hanya di mode 4.
            i("h2 smuggling check skipped — POST-only probe (POST terbatas mode 4)")
            return smuggling_findings
        if services:
            tasks = [
                asyncio.to_thread(WAFBypass.h2_smuggle_check, service["url"], policy)
                for service in services[:3]
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for service, result in zip(services[:3], results):
                if isinstance(result, BaseException):
                    w(f"smuggle check crashed for {service['url']}: "
                      f"{result.__class__.__name__}: {str(result)[:120]}")
                    continue
                if isinstance(result, dict) and result.get("vulnerable"):
                    s(f"{R}SMUGGLING VULNERABLE:{N} {W}{service['url']}{N}")
                    for test in result.get("tests", []):
                        smuggling_findings.append({
                            "type": "http_smuggling",
                            "title": f"HTTP Smuggling ({test['type']})",
                            "url": service["url"],
                            "detail": test["note"],
                            "waf": "",
                            "time": 0,
                            "status": test["status"],
                            "confidence": "confirmed",
                        })
        return smuggling_findings

    async def _run_oob_detector():
        if focus_mode:
            return []
        if services and params:
            oob_detector = OOBDetector(target, services, params, async_engine,
                                       session_manager=session_manager,
                                       allow_post=allow_post)
            # Satu sumber kebenaran: inner budget = backstop − 10s (dulu 60
            # hardcode di sini vs 70 di MODULE_TIMEOUTS, dua tempat rawan
            # beda). Saat timeout, salvage akumulator findings yang sudah
            # terkumpul, jangan dibuang mentah-mentah.
            limit = MODULE_TIMEOUTS["oob"] - 10
            try:
                return await asyncio.wait_for(oob_detector.run(), timeout=limit)
            except asyncio.TimeoutError:
                salvaged = [f for f in oob_detector.findings if isinstance(f, dict)]
                w(f"oob detector timed out after {limit}s — salvaged {len(salvaged)} finding(s)")
                return salvaged
        return []

    # Sesi 3: Web vuln modules (PARALLEL via gather)
    primary_url = services[0]["url"] if services else f"https://{target}/"

    from modules.web.api_auth.jwt_hunter import scan_jwt
    from modules.web.server_side.host_header import scan_host_header
    from modules.web.server_side.crlf import scan_crlf
    from modules.web.client_side.stored_xss import StoredXSSHunter
    from modules.web.server_side.idor import scan_idor

    async def _run_jwt():
        if not web_module_enabled("jwt"):
            return []
        return await scan_jwt(primary_url, async_engine, session_manager)

    async def _run_host_header():
        if not web_module_enabled("host"):
            return []
        return await scan_host_header(primary_url, async_engine, session_manager)

    async def _run_crlf():
        if not web_module_enabled("crlf"):
            return []
        return await scan_crlf(primary_url, async_engine, session_manager)

    async def _run_stored_xss():
        if not web_module_enabled("stored_xss"):
            return []
        # Gate `if not params: return []` dulu dipasang di sini tanpa alasan
        # fungsional — hunter hanya memakai target_urls, tidak memakai params.
        xss_hunter = StoredXSSHunter(scan_urls_origin if origin_ip else scan_urls,
                                     async_engine, session_manager,
                                     allow_post=allow_post)
        return await xss_hunter.run()

    async def _run_idor():
        if not web_module_enabled("idor"):
            return []
        idor_urls = (scan_urls_origin if origin_ip else scan_urls)[:20]
        # Outer 3 × inner 10 (idor.py) ≈ ≤30 IDOR request serentak — dulu
        # 10×10=100 memenuhi SELURUH kuota max_connections engine dan
        # modul lain kehabisan slot (banyak kena timeout → hasil dibuang).
        _sem = asyncio.Semaphore(3)
        async def _idor_one(url):
            async with _sem:
                return await scan_idor(url, async_engine, session_manager)
        idor_tasks = [_idor_one(u) for u in idor_urls]
        idor_results = await asyncio.gather(*idor_tasks, return_exceptions=True)
        results = []
        for u, r in zip(idor_urls, idor_results):
            if isinstance(r, list):
                results.extend(r)
            elif isinstance(r, BaseException):
                w(f"idor scan crashed for {u}: "
                  f"{r.__class__.__name__}: {str(r)[:120]}")
        return results

    async def _bounded(name, coro):
        limit = MODULE_TIMEOUTS[name]
        try:
            return await asyncio.wait_for(coro, timeout=limit)
        except asyncio.TimeoutError:
            w(f"module {name} timed out after {limit}s — results discarded")
            return []

    spin = Spinner("Assaulting target with all vulnerability modules...")
    spin.start()
    results = await asyncio.gather(
        _bounded("nuclei", _run_nuclei_tool()),
        _bounded("dalfox", _run_dalfox_tool()),
        _bounded("internal_injection", _run_internal_injection()),
        _bounded("smuggling", _run_smuggling()),
        _bounded("oob", _run_oob_detector()),
        _bounded("jwt", _run_jwt()),
        _bounded("host_header", _run_host_header()),
        _bounded("crlf", _run_crlf()),
        _bounded("stored_xss", _run_stored_xss()),
        _bounded("idor", _run_idor()),
        return_exceptions=True
    )
    spin.stop()

    module_names = (
        "nuclei", "dalfox", "internal_injection", "smuggling", "oob",
        "jwt", "host_header", "crlf", "stored_xss", "idor",
    )
    cleaned = []
    for name, res in zip(module_names, results):
        # BaseException (not just Exception): a CancelledError child can show
        # up in gather results — feeding it to findings.extend below would
        # TypeError OUTSIDE the return_exceptions guard and kill phase 3.
        if isinstance(res, BaseException):
            w(f"module {name} crashed — results skipped: "
              f"{res.__class__.__name__}: {str(res)[:120]}")
            cleaned.append([])
        elif not isinstance(res, list):
            w(f"module {name} returned {type(res).__name__} instead of list — results skipped")
            cleaned.append([])
        else:
            malformed = sum(1 for f in res if not isinstance(f, dict))
            if malformed:
                w(f"module {name}: dropped {malformed} malformed finding(s)")
            cleaned.append([f for f in res if isinstance(f, dict)])
    (
        n_res, d_res, injection_res, smuggling_res, oob_res,
        jwt_results, host_results, crlf_results, xss_results, idor_results
    ) = cleaned

    if n_res: findings.extend(n_res)
    if d_res: findings.extend(d_res)
    if injection_res: findings.extend(injection_res)
    if smuggling_res: findings.extend(smuggling_res)
    if oob_res: findings.extend(oob_res)

    if jwt_results:
        ph("JWT ANALYSIS")
        for f in jwt_results:
            if f.get("confidence") == "confirmed":
                s(f"{R}{f.get('title', '?')}{N} at {C}{str(f.get('url', ''))[:60]}{N}")
        findings.extend(jwt_results)

    if host_results:
        ph("HOST HEADER ANALYSIS")
        for f in host_results:
            s(f"{R}{f.get('title', '?')}{N} at {C}{str(f.get('url', ''))[:60]}{N}")
        findings.extend(host_results)

    if crlf_results:
        ph("CRLF ANALYSIS")
        for f in crlf_results:
            s(f"{R}{f.get('title', '?')}{N}")
        findings.extend(crlf_results)

    if xss_results:
        ph("STORED INPUT ANALYSIS")
        for f in xss_results:
            s(f"{R}{f.get('title', '?')}{N} at {C}{str(f.get('url', ''))[:60]}{N}")
        findings.extend(xss_results)

    if idor_results:
        ph("IDOR ANALYSIS")
        findings.extend(idor_results)

    return findings, list(target_wafs)
