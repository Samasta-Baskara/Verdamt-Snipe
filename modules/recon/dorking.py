import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import re
import time
import random
from urllib.parse import quote, urlparse
from typing import List, Dict, Set
from core.network import thttp
from core.ui import ph, i, p, w, draw_table, Spinner, G, Y, R, N, GY, W, C, B

# GOOGLE DORK TEMPLATES

DORK_TEMPLATES = [
    # SQL / Database Exposure
    'site:{domain} filetype:sql',
    'site:{domain} filetype:sql "INSERT INTO"',
    'site:{domain} ext:sql | ext:db | ext:log',
    'site:{domain} inurl:db | inurl:database | inurl:backup',
    
    # Config Files
    'site:{domain} filetype:env "DB_PASSWORD"',
    'site:{domain} filetype:yml "password"',
    'site:{domain} filetype:xml "password"',
    'site:{domain} filetype:ini "[database]"',
    'site:{domain} filetype:conf "server"',
    'site:{domain} filetype:cfg',
    'site:{domain} filetype:bak',
    'site:{domain} filetype:old',
    'site:{domain} filetype:txt "password"',
    
    # Injection Vectors
    'site:{domain} inurl:?id=',
    'site:{domain} inurl:?page=',
    'site:{domain} inurl:?file=',
    'site:{domain} inurl:?url=',
    'site:{domain} inurl:?redirect=',
    'site:{domain} inurl:?cmd=',
    'site:{domain} inurl:?exec=',
    'site:{domain} inurl:?search=',
    'site:{domain} inurl:?q=',
    'site:{domain} filetype:php inurl:?',
    'site:{domain} filetype:asp inurl:?',
    'site:{domain} filetype:jsp inurl:?',
    
    # Admin / Login
    'site:{domain} inurl:admin',
    'site:{domain} inurl:login',
    'site:{domain} inurl:dashboard',
    'site:{domain} intitle:"admin" | intitle:"login" | intitle:"dashboard"',
    'site:{domain} intitle:"index of /"',
    
    # Sensitive Directories
    'site:{domain} intitle:"index of" "parent directory"',
    'site:{domain} intitle:"index of" ".git"',
    'site:{domain} inurl:/.git/',
    'site:{domain} inurl:/.env',
    'site:{domain} inurl:/.svn/',
    'site:{domain} inurl:/wp-config.php',
    'site:{domain} inurl:wp-content/debug.log',
    
    # Error / Debug
    'site:{domain} "Fatal error" | "Warning:" | "Parse error"',
    'site:{domain} "Stack Trace" | "Traceback"',
    'site:{domain} inurl:phpinfo.php',
    'site:{domain} inurl:server-status',
    'site:{domain} inurl:server-info',
    'site:{domain} "DEBUG = True"',
    
    # API / Endpoints
    'site:{domain} inurl:api',
    'site:{domain} inurl:/api/v1 | inurl:/api/v2',
    'site:{domain} filetype:json "api"',
    'site:{domain} filetype:yaml "openapi"',
    'site:{domain} inurl:swagger | inurl:graphql',
    
    # Credentials / Secrets
    'site:{domain} "api_key" | "apikey" | "api key"',
    'site:{domain} "secret_key" | "private_key"',
    'site:{domain} "AWS_ACCESS_KEY" | "AKIA"',
    'site:{domain} filetype:log "password"',
    'site:{domain} filetype:log "token"',
]

# User agents that look like normal browsers
SEARCH_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
]


class GoogleDorker:
    """Automated Google Dorking engine with scraping + fallback to manual queries.

    Scraping google/ddg from a datacenter, VPN or Tor exit IP is usually
    served a captcha/429 on the FIRST query. The engine detects that per
    request, stops hammering the engines immediately (instead of burning
    the whole dork list on a blocked IP) and always exports the full dork
    list to ``outputs/<target>_dorks.txt`` so the intel is not lost.
    """

    BLOCK_MARKERS = (
        "captcha", "unusual traffic", "our systems have detected",
        "not a robot", "detected unusual", "anomaly",
    )

    def __init__(self, domain: str, max_results: int = 50, delay: float = 1.0,
                 budget_seconds: float = 25.0):
        self.domain = domain
        self.max_results = max_results
        self.delay = delay  # Delay between requests to avoid rate limiting
        self.budget_seconds = budget_seconds
        self.dorks = [t.format(domain=domain) for t in DORK_TEMPLATES]
        self.findings: List[Dict] = []
        self.discovered_urls: Set[str] = set()
        self.google_blocked = False
        self.ddg_blocked = False
        self.net_errors = 0
        self.manual_dork_path: str = ""

    @staticmethod
    def _is_block_page(status: int, body: str) -> bool:
        """Captcha/rate-limit landing pages are a hard block, not 'no results'."""
        if status in (429, 503):
            return True
        low = (body or "").lower()
        return any(m in low for m in GoogleDorker.BLOCK_MARKERS)

    def _search_google(self, dork: str) -> List[str]:
        """Scrape Google search results for a dork query."""
        urls = []
        try:
            search_url = f"https://www.google.com/search?q={quote(dork)}&num=20"
            headers = {
                "User-Agent": random.choice(SEARCH_UAS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
            r = thttp(search_url, headers=headers, timeout=6)
            status = r.get("status", 0) or 0
            body = r.get("body") or ""

            if self._is_block_page(status, body):
                self.google_blocked = True
                return []

            if status == 200 and body:
                # Extract URLs from Google results
                # Google wraps results in <a href="/url?q=..."> or <a href="https://...">
                raw_urls = re.findall(r'href="/url\?q=(https?://[^&"]+)', body)
                raw_urls += re.findall(r'<a href="(https?://' + re.escape(self.domain) + r'[^"]*)"', body)

                for u in raw_urls:
                    # Filter: only target domain, skip google/cache
                    parsed = urlparse(u)
                    if self.domain in parsed.netloc and "google" not in parsed.netloc:
                        urls.append(u)

        except Exception:
            # Network hiccups are counted once — a datacenter/Tor IP raises
            # here (or gets a captcha page) nearly every dork; one summary
            # line at the end beats 50 per-dork warnings.
            self.net_errors += 1
        return urls

    def _search_duckduckgo(self, dork: str) -> List[str]:
        """Fallback: scrape DuckDuckGo (less aggressive anti-bot)."""
        urls = []
        try:
            # DuckDuckGo HTML version
            search_url = f"https://html.duckduckgo.com/html/?q={quote(dork)}"
            headers = {"User-Agent": random.choice(SEARCH_UAS)}
            r = thttp(search_url, headers=headers, timeout=6)
            status = r.get("status", 0) or 0
            body = r.get("body") or ""

            if self._is_block_page(status, body):
                self.ddg_blocked = True
                return []

            if status == 200 and body:
                raw_urls = re.findall(r'href="(https?://[^"]+)"', body)
                for u in raw_urls:
                    parsed = urlparse(u)
                    if self.domain in parsed.netloc and "duckduckgo" not in parsed.netloc:
                        urls.append(u)
        except Exception:
            self.net_errors += 1
        return urls

    def _export_manual_dorks(self) -> str:
        """Write the full dork list to outputs/<target>_dorks.txt for manual
        use (copy-paste into a browser / any search engine)."""
        from core.project import sanitize_filename
        os.makedirs("outputs", exist_ok=True)
        path = f"outputs/{sanitize_filename(self.domain)}_dorks.txt"
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(f"# Verdammt-Snipe dork queries for {self.domain}\n")
                fh.write("# Scraping was blocked/unavailable — run these manually.\n")
                for dork in self.dorks:
                    fh.write(dork + "\n")
            self.manual_dork_path = path
        except Exception:
            self.manual_dork_path = ""
        return path

    def run(self) -> Dict:
        """Execute dorking — returns discovered URLs and dork results."""
        ph("GOOGLE DORKING: Passive Intelligence")
        i(f"Target: {W}{self.domain}{N}")
        i(f"Loaded {W}{len(self.dorks)}{N} dork templates")

        # Phase 1: Try automated scraping (bounded by budget + block state)
        deadline = time.monotonic() + self.budget_seconds
        scrape_count = 0
        consecutive_fails = 0
        MAX_CONSECUTIVE_FAILS = 2
        budget_hit = False

        spin = Spinner("Executing dork queries...")
        for dork in self.dorks:
            if time.monotonic() > deadline:
                budget_hit = True
                break
            # Both engines already confirmed blocked — no point hammering
            # them for the remaining dorks (that used to burn ~30s+ every
            # run on IPs search engines block).
            if self.google_blocked and self.ddg_blocked:
                break
            spin.next()

            results = []
            if not self.google_blocked:
                try:
                    results = self._search_google(dork)
                except Exception:
                    results = []
            if not results and not self.ddg_blocked:
                try:
                    results = self._search_duckduckgo(dork)
                except Exception:
                    results = []

            if results:
                scrape_count += 1
                consecutive_fails = 0
                for url in results:
                    if url not in self.discovered_urls:
                        self.discovered_urls.add(url)
                        self.findings.append({
                            "type": "google_dork",
                            "title": f"Dork Discovery: {dork[:50]}",
                            "url": url,
                            "detail": f"Dork: {dork}",
                            "waf": "",
                            "time": 0,
                            "status": 200,
                        })
            else:
                consecutive_fails += 1
                # Bail early: scraping is blocked or target has no index
                if consecutive_fails >= MAX_CONSECUTIVE_FAILS:
                    break

            # Polite delay
            time.sleep(random.uniform(0.1, 0.3))

            # Cap results
            if len(self.discovered_urls) >= self.max_results:
                break
        spin.stop()

        scrape_failed = scrape_count == 0

        # Phase 2: If scraping failed, export dork queries for manual use
        if scrape_failed:
            path = self._export_manual_dorks()
            if self.google_blocked or self.ddg_blocked:
                w("Search engine scraping blocked (rate-limit/captcha) — "
                  "common from datacenter/VPN/Tor exit IPs.")
            elif self.net_errors:
                w(f"Dork scraping unavailable ({self.net_errors} network "
                  "error(s) talking to the search engines).")
            elif budget_hit:
                w(f"Dork budget hit ({int(self.budget_seconds)}s) before any "
                  "hit — saving queries for manual use.")
            i(f"{len(self.dorks)} dork queries exported for manual use → "
              f"{C}{path}{N}")

            print(f"\n  {B}{W}MANUAL DORK QUERIES (top 10):{N}")
            print(f"  {GY}{'─'*60}{N}")
            for dork in self.dorks[:10]:
                print(f"  {C}▸{N} {W}{dork}{N}")
            print(f"  {GY}{'─'*60}{N}")
            print(f"  {GY}Full list: {path} — paste into any search engine.{N}\n")

        # Summary
        if self.findings:
            rows = []
            for f in self.findings[:15]:  # Top 15
                short_dork = f["detail"].replace("Dork: ", "")[:40]
                short_url = f["url"][:50]
                rows.append([f"{R}HIT{N}", f"{Y}{short_dork}{N}", f"{C}{short_url}{N}"])
            draw_table(["TYPE", "DORK", "DISCOVERED URL"], rows, title="Google Dork Results")

        p(f"Dork URLs discovered: {G}{len(self.discovered_urls)}{N}")

        return {
            "urls": list(self.discovered_urls),
            "findings": self.findings,
            "scrape_failed": scrape_failed,
            "manual_dork_path": self.manual_dork_path,
        }
