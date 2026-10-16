import asyncio
from urllib.parse import urlparse

from modules.web.recon_crawlers.api_profiler import APIProfiler
from modules.extras.arjun import AsyncParamBruteforcer, ParamBruteforcer
from modules.auth.tester import AuthTester
from modules.web.recon_crawlers.browser_recon import BrowserRecon
from modules.web.recon_crawlers.crawler import DeepCrawler
from modules.web.client_side.dom_xss import DOMXSSScanner
from modules.web.client_side.csrf_verify import CSRFVerifier
from modules.web.client_side.postmessage_analyzer import PostMessageAnalyzer
from modules.web.client_side.clickjacking_verify import ClickjackingInspector
from modules.web.recon_crawlers.websocket_recon import WebSocketSniffer
from modules.web.client_side.proto_pollution_verify import ProtoPollutionVerifier
from modules.web.api_auth.oauth_auditor import OAuthAuditor
from modules.web.client_side.cors_verify import CORSVerifier
from modules.web.recon_crawlers.spa_crawler import SPACrawler
from modules.web.api_auth.graphql_profiler import GraphQLProfiler
from modules.recon import ParamExtractor
from runners.shared import merge_params, normalize_urls, validate_recon_urls


async def run_app_analysis(
    target: str,
    seed_url: str,
    services,
    scan_urls,
    scope_guard,
    session_manager,
    auth_headers,
    auth_headers2=None,
    async_engine=None,
    is_turbo=False,
    policy=None,
):
    """Option 2: light crawling, SPA discovery, param discovery, API/auth analysis.

    Katana TIDAK berjalan di sini (fase resmi mode 3/4/5 di runners/shared.py)
    — mode 2 memakai DeepCrawler sebagai crawl ringan Python.
    """
    from core.ui import ph

    if policy and policy.mode == "passive":
        ph("PHASE 2: APP ANALYSIS SKIPPED (PASSIVE POLICY)")
        return [], {}, list(scan_urls)

    ph("PHASE 2: APP ANALYSIS")
    findings = []
    urls = list(scan_urls)
    params = {}

    # OpenAPI / Swagger & Postman Spec Ingestion
    from modules.web.api_auth.openapi_parser import OpenAPIParser
    api_parser = OpenAPIParser(seed_url)

    spec_paths = [
        "/swagger.json", "/openapi.json", "/v2/api-docs",
        "/api/swagger.json", "/api/openapi.json", "/api-docs"
    ]
    for sp in spec_paths:
        try:
            spec_url = f"{seed_url.rstrip('/')}{sp}"
            resp = await async_engine.ahttp_send(spec_url, timeout=5) if async_engine else None
            # ahttp_send mengembalikan DICT — akses .status_code/.text pada
            # dict selalu AttributeError dan ditelan senyap, jadi ingest
            # Swagger/OpenAPI tidak pernah bekerja (dead code).
            if resp and resp.get("status") == 200:
                body = resp.get("body", "") or ""
                content_type = str(resp.get("headers", {}).get("content-type", "")).lower()
                if ("json" in content_type or "swagger" in body[:500].lower()
                        or "openapi" in body[:500].lower()):
                    spec_res = api_parser.parse_spec(body, spec_url)
                    if spec_res.get("endpoints"):
                        from core.ui import s
                        s(f"API SPEC INGESTION: Auto-parsed OpenAPI Spec ({len(spec_res['endpoints'])} endpoints)")
                        urls.extend(spec_res["endpoints"])
                        for p_path, p_keys in spec_res.get("params", {}).items():
                            merge_params(params, p_path, p_keys)
                        break
        except Exception as e:
            from core.ui import w
            w(f"OpenAPI spec fetch/parse failed for {sp}: "
              f"{e.__class__.__name__}: {str(e)[:80]}")

    async def _run_deep_crawl_task():
        """Crawl ringan Python — mode 2 tidak memakai Katana (mode 3-5)."""
        try:
            res = await DeepCrawler(seed_url, async_engine=async_engine).run()
            return res or {"endpoints": [], "params": []}
        except Exception as e:
            from core.ui import w
            w(f"DeepCrawler failed: {e.__class__.__name__}: {str(e)[:80]}")
            return {"endpoints": [], "params": []}

    async def _run_browser_recon_task():
        try:
            browser_recon = BrowserRecon(seed_url, session_manager)
            res = await browser_recon.run()
            return res or {"endpoints": []}
        except Exception:
            return {"endpoints": []}

    def _has_stage(keyword: str) -> bool:
        """True bila fase boleh dikirim ke dashboard.

        Pipe mode (dashborad tidak aktif) selalu boleh — tak ada pipeline
        yang bisa salah nyala. Di dashboard, fase DEEP CRAWL hanya dikirim
        bila stage-nya benar-benar ada: di mode FULL stage itu tidak ada
        (menyatu dengan "App & Param Discovery"), dan kalau dikirim, mapping
        crawl justru menyalakan ulang stage "Katana Crawl" yang sudah lewat.
        """
        try:
            from core.ui import ScanDashboard
            if not ScanDashboard.active():
                return True
            return any(keyword in st["name"].lower()
                       for st in ScanDashboard.get().pipeline)
        except Exception:
            return True

    if _has_stage("deep crawl"):
        ph("DEEP CRAWL: Mapping application endpoints (DeepCrawler + Browser)")
    from core.ui import Spinner
    spin = Spinner("Running DeepCrawler & Browser Recon...")
    spin.start()
    crawl_res, spa_results = await asyncio.gather(
        _run_deep_crawl_task(),
        _run_browser_recon_task(),
        return_exceptions=True
    )
    spin.stop()

    if isinstance(crawl_res, Exception):
        crawl_res = {"endpoints": [], "params": []}
    if isinstance(spa_results, Exception):
        spa_results = {"endpoints": []}

    if crawl_res and crawl_res.get("endpoints"):
        urls.extend(crawl_res["endpoints"])
        merge_params(params, "/", crawl_res.get("params", []))

    if spa_results and spa_results.get("endpoints"):
        urls.extend(scope_guard.filter_urls(spa_results["endpoints"]))

    urls = normalize_urls(urls, scope_guard=scope_guard)
    scan_urls = await validate_recon_urls(urls, scope_guard, async_engine, session_manager=session_manager)

    async def _run_param_extraction():
        return await ParamExtractor(scan_urls).run()

    async def _run_param_bruteforce():
        if not scan_urls: return []
        unique_paths = set()
        brute_targets = []
        for u in scan_urls:
            p = urlparse(u).path or "/"
            if p not in unique_paths:
                unique_paths.add(p)
                brute_targets.append(u)
                if len(brute_targets) >= 10:
                    break
                    
        async def _bruteforce_url(url):
            if async_engine:
                discovered = await AsyncParamBruteforcer(
                    url,
                    async_engine,
                    concurrency=15,
                    chunk_size=10,
                    session_manager=session_manager,
                ).run()
            else:
                discovered = await asyncio.to_thread(
                    ParamBruteforcer(url, threads=3, chunk_size=5, policy=policy).run
                )
            base_path = urlparse(url).path or "/"
            return (base_path, discovered)

        return await asyncio.gather(*[_bruteforce_url(u) for u in brute_targets], return_exceptions=True)

    # Run DOMXSS, APIProfiler, AuthTester, ParamExtraction, ParamBruteforce in PARALLEL
    async def _run_domxss():
        return await DOMXSSScanner(scan_urls, network_engine=async_engine).run()

    async def _run_apiprofiler():
        return await APIProfiler(
            scan_urls,
            network_engine=async_engine,
            auth_headers=auth_headers,
            session_manager=session_manager,
        ).run()

    async def _run_authtester():
        if not scan_urls:
            return []
        return await AuthTester(
            scan_urls,
            session_manager=session_manager,
            network_engine=async_engine,
            probe_bypass=True,
            auth_headers2=auth_headers2,
        ).run()

    async def _run_playwright_suite():
        pw_findings = []
        try:
            pw_findings.extend(await CSRFVerifier(seed_url, session_manager).run())
            pw_findings.extend(await PostMessageAnalyzer(seed_url).run())
            pw_findings.extend(await ClickjackingInspector(seed_url).run())
            pw_findings.extend(await WebSocketSniffer(seed_url).run())
            pw_findings.extend(await ProtoPollutionVerifier(seed_url).run())
            pw_findings.extend(await OAuthAuditor(seed_url).run())
            pw_findings.extend(await CORSVerifier(seed_url).run())
            spa_res = await SPACrawler(seed_url).run()
            if spa_res and spa_res.get("urls"):
                scan_urls.extend(spa_res["urls"])
        except Exception as ex:
            ph(f"Playwright suite error: {ex}")
        return pw_findings

    async def _run_graphql():
        return await GraphQLProfiler(seed_url, async_engine=async_engine).run()

    ph("APP DEEP ANALYSIS: Running parallel analysis suite")
    from core.ui import Spinner
    spin = Spinner("Running parallel App Analysis & Playwright Suite modules...")
    spin.start()
    results = await asyncio.gather(
        _run_param_extraction(),
        _run_param_bruteforce(),
        _run_domxss(),
        _run_apiprofiler(),
        _run_authtester(),
        _run_playwright_suite(),
        _run_graphql(),
        return_exceptions=True
    )
    spin.stop()
    
    extracted_params = results[0] if not isinstance(results[0], Exception) else {}
    for path, values in extracted_params.items():
        merge_params(params, path, values)
        
    brute_results = results[1] if not isinstance(results[1], Exception) else []
    for r in brute_results:
        if isinstance(r, Exception):
            ph(f"Param bruteforce error: {r}")
        elif isinstance(r, tuple):
            base_path, discovered = r
            merge_params(params, base_path, discovered)

    domxss_results = results[2]
    apiprofiler_results = results[3]
    authtester_results = results[4]
    playwright_suite_results = results[5]
    graphql_results = results[6]

    if isinstance(domxss_results, list):
        findings.extend(domxss_results)
    elif isinstance(domxss_results, Exception):
        ph(f"DOMXSS error: {domxss_results}")

    if isinstance(apiprofiler_results, list):
        findings.extend(apiprofiler_results)
    elif isinstance(apiprofiler_results, Exception):
        ph(f"APIProfiler error: {apiprofiler_results}")

    if isinstance(authtester_results, list):
        findings.extend(authtester_results)
    elif isinstance(authtester_results, Exception):
        ph(f"AuthTester error: {authtester_results}")

    if isinstance(playwright_suite_results, list):
        findings.extend(playwright_suite_results)
    elif isinstance(playwright_suite_results, Exception):
        ph(f"Playwright Suite error: {playwright_suite_results}")

    if isinstance(graphql_results, list):
        findings.extend(graphql_results)
    elif isinstance(graphql_results, Exception):
        ph(f"GraphQL error: {graphql_results}")

    return findings, params, scan_urls
