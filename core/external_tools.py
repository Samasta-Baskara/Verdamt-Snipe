"""
External Tool Integration — Wrappers for ProjectDiscovery & community Go binaries.

Supports: subfinder, httpx, gau, katana, waybackurls, nuclei, dalfox
Falls back gracefully when tools are not installed.
"""

import json
import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from core.policy import ScanPolicy
from core.ui import ph, i, p, w, Spinner, G, Y, R, C, M, W, GY, N, draw_table

# TOOL DISCOVERY

# Common install locations for Go binaries
_GO_BIN_PATHS = [
    os.path.expanduser("~/go/bin"),
    "/usr/local/bin",
    "/usr/bin",
]


def _find_tool(name: str) -> Optional[str]:
    """Find executable path for a tool, checking PATH and common Go bin dirs.
    
    For known CLI tools (projectdiscovery Go binaries), check ~/go/bin FIRST
    before PATH — prevents pip-installed Python modules (like 'httpx') from
    shadowing the real Go binary.
    """
    # Known Go CLI tools that should NOT resolve to pip modules
    _GO_CLI_TOOLS = {"httpx", "subfinder", "gau", "katana", "waybackurls",
                     "nuclei", "dalfox", "ffuf", "gf"}
    
    if name in _GO_CLI_TOOLS:
        go_bin = os.path.expanduser("~/go/bin")
        if os.path.isdir(go_bin):
            candidate = os.path.join(go_bin, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    
    found = shutil.which(name)
    if found:
        return found
    for d in _GO_BIN_PATHS:
        candidate = os.path.join(d, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def check_tools() -> Dict[str, Optional[str]]:
    """Check availability of all supported external tools.
    Returns dict mapping tool name → absolute path or None.
    """
    tools = ["subfinder", "httpx", "gau", "katana", "waybackurls", "nuclei", "dalfox", "ffuf", "gf"]
    result = {}
    for t in tools:
        result[t] = _find_tool(t)
    return result


def _tool_proxy(proxy: Optional[str]) -> Optional[str]:
    """Normalisasi proxy URL untuk tool berbasis Go.

    `socks5h://` adalah alias khusus curl (resolve DNS lewat SOCKS); tool Go
    (nuclei, dsb.) menolaknya: "all proxies are dead: invalid proxy format"
    → exit instan tanpa findings, tanpa stats, tanpa charge. Nyata terjadi
    pada scan dengan VERDAMT_PROXY=socks5h://... (run demo.testfire.net).
    """
    if proxy and proxy.startswith("socks5h://"):
        return "socks5://" + proxy[len("socks5h://"):]
    return proxy


def _policy_allows_tool(policy: Optional[ScanPolicy], tool_name: str) -> bool:
    """Check policy before an external tool is invoked."""
    if not policy:
        return True
    decision = policy.check_tool(tool_name)
    if decision.allowed:
        return True
    w(f"Policy blocked {tool_name}: {decision.reason}")
    return False


# nuclei kini didebit NYATA via -stats-json (lihat run_nuclei); dalfox belum
# punya mekanisme serupa (tanpa flag max-requests, HAR terlalu besar untuk
# scan penuh) — jadi tetap pakai gerbang statis: jangan mulai tool berat
# saat budget nyaris habis. Naikkan hanya dengan mekanisme hitung nyata.
UNCOUNTED_TOOL_FLOOR = 200


def _uncounted_tool_allowed(policy: Optional[ScanPolicy], tool_name: str) -> bool:
    """Budget gate for external tools whose traffic is not debited."""
    if policy is None:
        return True
    remaining = policy.requests_remaining
    if remaining is None:
        return True
    if remaining < UNCOUNTED_TOOL_FLOOR:
        w(f"{tool_name} skipped — only {remaining} requests left "
          f"(<{UNCOUNTED_TOOL_FLOOR} budget floor)")
        return False
    return True


def print_tool_status():
    """Print a formatted table showing which tools are available."""
    status = check_tools()
    rows = []
    for name, path in status.items():
        if path:
            rows.append([f"{G}✓{N}", f"{W}{name}{N}", f"{GY}{path}{N}"])
        else:
            rows.append([f"{R}✗{N}", f"{GY}{name}{N}", f"{R}not found{N}"])
    draw_table(["", "TOOL", "PATH"], rows, title="External Tool Status")


def _run_tool(tool_name: str, args: List[str], timeout: int = 120,
              input_data: str = None, proxy: str = None) -> Tuple[int, str, str]:
    """Run an external tool and return (returncode, stdout, stderr).
    Raises FileNotFoundError if tool is not installed.
    
    Args:
        proxy: Proxy URL (e.g. 'socks5://ip:port'). Flag-only — no env fallback.
    """
    tool_path = _find_tool(tool_name)
    if not tool_path:
        raise FileNotFoundError(f"{tool_name} not found. Install: go install -v github.com/projectdiscovery/{tool_name}/v2/cmd/{tool_name}@latest")

    cmd = [tool_path] + args

    # Build env with proxy
    env = os.environ.copy()
    if proxy:
        env["ALL_PROXY"] = proxy
        env["HTTP_PROXY"] = proxy
        env["HTTPS_PROXY"] = proxy
        env["http_proxy"] = proxy
        env["https_proxy"] = proxy
        env["all_proxy"] = proxy

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
    except Exception as exc:  # same contract as old subprocess.run wrapper
        return -1, "", str(exc)
    with _PROCS_LOCK:
        _ACTIVE_PROCS.add(proc)
    try:
        out, err = proc.communicate(input=input_data, timeout=timeout)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        w(f"{tool_name} timed out after {timeout}s (salvaging partial output)")
        try:
            proc.kill()
        except Exception:
            pass
        # Bounded reap: communicate() tanpa timeout di sini bisa block
        # selamanya bila proses anak/pewaris masih memegang pipe stdout/
        # stderr — thread to_thread bocor permanen karena tak bisa
        # di-cancel. 10s grace, lalu pipe ditinggalkan.
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            for pipe in (proc.stdout, proc.stderr):
                try:
                    if pipe:
                        pipe.close()
                except Exception:
                    pass
            try:
                proc.wait(timeout=1)
            except Exception:
                pass
            out, err = "", ""
        return -1, out or "", f"timeout after {timeout}s: {err or ''}"
    except Exception as exc:
        try:
            proc.kill()
        except Exception:
            pass
        return -1, "", str(exc)
    finally:
        with _PROCS_LOCK:
            _ACTIVE_PROCS.discard(proc)


import threading as _threading

# External-tool subprocesses currently running. asyncio cancellation cannot
# stop a thread that is already inside subprocess.run — after --max-time
# the tools (nuclei timeout=300, dalfox 180) kept hitting the target and
# `asyncio.run` joined the executor at exit, so the process outlived
# "SCAN COMPLETE" (verdict A:521, verified 2026-10-06). Track every Popen
# so the deadline path can terminate them.
_PROCS_LOCK = _threading.Lock()
# Objects exposing kill()/terminate() — subprocess.Popen from _run_tool and
# curl_send, plus asyncio.subprocess.Process from origin_hunter (kill() yes,
# terminate() no — kill_active_procs tolerates that).
_ACTIVE_PROCS: "set" = set()


def track_proc(proc) -> None:
    """Register any external-tool subprocess so kill_active_procs can reach
    it from every exit path (--max-time, crash, interrupt)."""
    with _PROCS_LOCK:
        _ACTIVE_PROCS.add(proc)


def untrack_proc(proc) -> None:
    with _PROCS_LOCK:
        _ACTIVE_PROCS.discard(proc)


def kill_active_procs(reason: str = "scan deadline") -> int:
    """Terminate tracked tool subprocesses. Returns count terminated."""
    with _PROCS_LOCK:
        procs = list(_ACTIVE_PROCS)
        _ACTIVE_PROCS.clear()
    killed = 0
    for p in procs:
        try:
            p.terminate()
            killed += 1
        except Exception:
            pass
        try:
            p.kill()  # scanners don't need graceful shutdown
        except Exception:
            pass
    if killed:
        w(f"Killed {killed} in-flight tool process(es) ({reason})")
    return killed


# SUBFINDER — Subdomain Enumeration

def run_subfinder(domain: str, timeout: int = 30,
                  policy: Optional[ScanPolicy] = None,
                  proxy: str = None) -> List[str]:
    """Run subfinder for subdomain enumeration.
    Returns list of discovered subdomains.
    """
    if not _policy_allows_tool(policy, "subfinder"):
        return []
    if policy and not policy.allows_host(domain):
        w("Policy blocked subfinder target: out_of_scope_host")
        return []

    ph("SUBFINDER: Subdomain Enumeration")
    i(f"Target: {W}{domain}{N}")

    spin = Spinner("Running subfinder...")
    try:
        subfinder_args = [
            "-d", domain,
            "-silent",
            "-timeout", "10",
            "-max-time", str(max(5, timeout - 5)),
        ]
        if proxy:
            # Go binaries ignore ALL_PROXY for socks5 — subfinder needs -proxy
            subfinder_args += ["-proxy", _tool_proxy(proxy)]
        rc, stdout, stderr = _run_tool("subfinder", subfinder_args,
                                       timeout=timeout, proxy=proxy)
        spin.stop()

        if rc != 0 and not stdout.strip():
            w(f"subfinder returned non-zero: {stderr[:200]}")
            return [domain]

        subs = set()
        for line in stdout.strip().splitlines():
            line = line.strip().lower()
            if (line == domain or line.endswith(f".{domain}")) and (
                not policy or policy.allows_host(line)
            ):
                subs.add(line)
        subs.add(domain)

        p(f"Subdomains discovered: {G}{len(subs)}{N}")
        return sorted(subs)

    except FileNotFoundError as exc:
        spin.stop()
        w(str(exc))
        w("Falling back to built-in subdomain enumeration...")
        return []  # Caller should use fallback


# HTTPX — HTTP Probing & Tech Detection

def run_httpx(targets: List[str], timeout: int = 60, proxy: str = None,
              policy: Optional[ScanPolicy] = None) -> List[Dict]:
    """Run httpx to probe live HTTP services.
    Returns list of service dicts compatible with the existing pipeline.
    """
    if not _policy_allows_tool(policy, "httpx"):
        return []
    if policy:
        targets = policy.filter_urls(targets)
    if not targets:
        return []

    ph("HTTPX: HTTP Probing & Tech Detection")
    i(f"Probing {W}{len(targets)}{N} targets...")

    input_data = "\n".join(targets)
    spin = Spinner("Running httpx probe...")

    args = [
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-content-type",
        "-no-color",
        "-threads", "150",
        "-timeout", "3",
        "-retries", "1",
    ]

    # Redirects can leave the authorized boundary before we can inspect the
    # resulting URL. Keep them disabled whenever a policy is active.
    if not policy:
        args.insert(5, "-follow-redirects")

    # Add proxy flag (httpx supports -proxy)
    if proxy:
        args.extend(["-proxy", _tool_proxy(proxy)])

    try:
        rc, stdout, stderr = _run_tool("httpx", args,
                                        timeout=timeout, input_data=input_data,
                                        proxy=proxy)
        spin.stop()

        services = []
        seen_urls = set()
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = (data.get("url") or data.get("input") or "").rstrip("/")
            final_url = (data.get("final_url") or url).rstrip("/")
            if not url or url in seen_urls:
                continue
            if policy and (not policy.allows_url(url) or not policy.allows_url(final_url)):
                continue
            seen_urls.add(url)

            from urllib.parse import urlparse
            parsed = urlparse(final_url or url)
            status = data.get("status_code") or data.get("status-code") or 0
            title = data.get("title") or ""
            tech = data.get("tech") or []
            server = data.get("webserver") or data.get("web_server") or ""
            content_type = data.get("content_type") or data.get("content-type") or ""

            service = {
                "url": url,
                "final_url": final_url,
                "host": parsed.hostname or "",
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                "scheme": parsed.scheme or "https",
                "status": status,
                "status_code": status,
                "title": title[:100] if title else "",
                "tech": ", ".join(tech) if isinstance(tech, list) else str(tech or "Unknown"),
                "server": server,
                "content_type": content_type,
                "headers": data.get("header") or {},
                "body": data.get("body") or "",
                "waf": [],
            }
            services.append(service)

        # Display results
        if services:
            rows = []
            for sv in services:
                sc = sv["status_code"]
                c = G if sc < 300 else (Y if sc < 400 else (M if sc < 500 else R))
                tech_str = sv["tech"] if len(sv["tech"]) < 25 else sv["tech"][:22] + "..."
                rows.append([
                    f"{c}{sc}{N}",
                    f"{W}{sv['final_url'][:55]}{N}",
                    f"{GY}{tech_str}{N}",
                    f"{C}{sv['title'][:30]}{N}",
                ])
            draw_table(["CODE", "URL", "TECH", "TITLE"], rows, title="Live Services")

        p(f"Live services: {G}{len(services)}{N}")
        return services

    except FileNotFoundError as exc:
        spin.stop()
        w(str(exc))
        w("Falling back to built-in HTTP prober...")
        return []  # Caller should use fallback


# GAU — URL Collection (GetAllUrls)

def run_gau(domain: str, timeout: int = 90,
            policy: Optional[ScanPolicy] = None) -> List[str]:
    """Run gau to collect historical URLs from multiple sources.
    Returns list of URLs.
    """
    if not _policy_allows_tool(policy, "gau"):
        return []
    if policy and not policy.allows_host(domain):
        return []
    try:
        rc, stdout, stderr = _run_tool("gau", [
            domain,
            "--threads", "25",
            "--providers", "wayback,otx,urlscan",
            "--timeout", "5",
            "--subs",
        ], timeout=timeout)
        if rc != 0 and not stdout.strip():
            w(f"gau exited rc={rc} — no results (stderr: {stderr[:150]})")

        urls = set()
        for line in stdout.strip().splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls.add(line.split("#")[0])
        return policy.filter_urls(urls) if policy else sorted(urls)

    except FileNotFoundError:
        return []


# WAYBACKURLS — Wayback Machine URL Mining

def run_waybackurls(domain: str, timeout: int = 90,
                    policy: Optional[ScanPolicy] = None) -> List[str]:
    """Run waybackurls to mine archived URLs."""
    if not _policy_allows_tool(policy, "waybackurls"):
        return []
    if policy and not policy.allows_host(domain):
        return []
    try:
        rc, stdout, stderr = _run_tool("waybackurls", [
            domain,
        ], timeout=timeout)
        if rc != 0 and not stdout.strip():
            w(f"waybackurls exited rc={rc} — no results (stderr: {stderr[:150]})")

        urls = set()
        for line in stdout.strip().splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls.add(line.split("#")[0])
        return policy.filter_urls(urls) if policy else sorted(urls)

    except FileNotFoundError:
        return []


# KATANA — Deep Crawling

def run_katana(url: str, depth: int = 2, timeout: int = 60, proxy: str = None,
               policy: Optional[ScanPolicy] = None) -> Dict:
    """Run katana for deep endpoint crawling.
    Returns dict with 'endpoints' and 'params'.
    """
    result = {"endpoints": [], "params": []}

    if not _policy_allows_tool(policy, "katana"):
        return result
    # Katana dulu lolos total dari anggaran (tanpa gate, tanpa charge) —
    # crawl dalam bisa menambah ribuan request tak terhitung di tengah
    # scan yang budget-nya tinggal sedikit.
    if not _uncounted_tool_allowed(policy, "katana"):
        return result
    if policy:
        url = policy.canonical_url(url)
        if not url:
            return result

    try:
        katana_args = [
            "-u", url,
            "-d", str(depth),
            "-silent",
            "-jc",           # JavaScript crawl
            "-c", "20",      # Concurrency limit
            "-ct", "5",      # Crawl timeout per request
            "-rate-limit", "150",
            "-kf", "all",    # Known file discovery
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
            "-no-color",
        ]
        if policy:
            # Keep the external crawler inside the same host boundary as the
            # in-process transport. Output filtering alone is too late.
            katana_args.extend(["-cs", policy.root_host])
        # Add proxy flag (katana supports -proxy)
        effective_proxy = _tool_proxy(proxy)  # only from explicit arg, not env auto
        if effective_proxy:
            katana_args.extend(["-proxy", effective_proxy])

        rc, stdout, stderr = _run_tool("katana", katana_args,
                                        timeout=timeout, proxy=proxy)
        if rc != 0 and not stdout.strip():
            w(f"katana exited rc={rc} — no results (stderr: {stderr[:150]})")

        endpoints = set()
        params = set()
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            endpoint = line.split("#")[0]
            if policy and not policy.allows_url(endpoint):
                continue
            endpoints.add(endpoint)
            # Extract params from URLs
            if "?" in line:
                query = line.split("?", 1)[1]
                for part in query.split("&"):
                    if "=" in part:
                        param_name = part.split("=", 1)[0]
                        if param_name and len(param_name) < 40:
                            params.add(param_name)

        result["endpoints"] = sorted(endpoints)
        result["params"] = sorted(params)
        return result

    except FileNotFoundError:
        return result


# NUCLEI — Template-Based Vulnerability Scanning

def run_nuclei(targets: List[str], templates: str = None,
               severity: str = "medium,high,critical", timeout: int = 300,
               auth_headers: dict = None, tech_tags: List[str] = None,
               proxy: str = None, policy: Optional[ScanPolicy] = None) -> List[Dict]:
    """Run nuclei template scanner with optional auth injection and tech-aware templates.
    Returns list of finding dicts compatible with verdamt-snipe format.
    """
    if not _policy_allows_tool(policy, "nuclei"):
        return []
    if not _uncounted_tool_allowed(policy, "nuclei"):
        return []
    if policy:
        raw_count = len(targets)
        targets = policy.filter_urls(targets)
        if not targets and raw_count:
            # Dulu drop senyap: phase nampak normal padahal nuclei menerima
            # 0 target (port non-80/443 / out_of_scope_host).
            w(f"policy filtered ALL {raw_count} nuclei target(s) — "
              "check audit log for filter_urls:<reason> entries")
    if not targets:
        return []

    findings = []
    input_data = "\n".join(targets)

    args = [
        # -j/-jsonl, BUKAN -json: nuclei v3 menghapus -json sepenuhnya —
        # flag lama bikin nuclei modern langsung exit ("flag provided but not
        # defined: -json") sehingga SEMUA run mode 3 senyap 0 findings.
        "-j",
        # -silent ditiadakan: -silent mematikan output -sj (stats). Banner
        # dan [INF] tetap ke stderr, stdout tetap murni JSONL (verified).
        # -sj/-si = real counting mechanism: stats JSON berisi total request
        # nyata, didebit ke policy.max_requests setelah run.
        "-sj",
        "-si", "10",
        "-no-color",
        "-severity", severity,
    ]

    # Add proxy flag (nuclei supports -proxy)
    effective_proxy = _tool_proxy(proxy)  # only from explicit arg, not env auto
    if effective_proxy:
        args.extend(["-proxy", effective_proxy])

    # Inject auth headers as -H flags
    if auth_headers:
        for k, v in auth_headers.items():
            args.extend(["-H", f"{k}: {v}"])

    # Tech-aware template selection
    if tech_tags and not templates:
        tech_templates = {
            "react": ["technology/react", "exposure"],
            "angular": ["technology/angular"],
            "vue": ["technology/vue"],
            "jquery": ["technology/jquery"],
            "wordpress": ["wordpress"],
            "joomla": ["joomla"],
            "drupal": ["drupal"],
            "laravel": ["laravel"],
            "nginx": ["nginx"],
            "apache": ["apache"],
            "iis": ["iis"],
            "cloudflare": ["cloudflare"],
            "aws": ["cloud/aws"],
            "azure": ["cloud/azure"],
            "gcp": ["cloud/gcp"],
            "kubernetes": ["cloud/kubernetes"],
            "docker": ["cloud/docker"],
            "jenkins": ["jenkins"],
        }
        matched = set()
        tech_lower = [t.lower() for t in tech_tags]
        for tech, tpl_cats in tech_templates.items():
            if any(tech in t for t in tech_lower):
                for cat in tpl_cats:
                    matched.add(cat)
        if matched:
            args.extend(["-tags", ",".join(sorted(matched))])

    try:
        rc, stdout, stderr = _run_tool("nuclei", args,
                                        timeout=timeout, input_data=input_data)
    except FileNotFoundError:
        w("nuclei not installed — skipping nuclei scan, tool will continue with internal engine")
        return []
    except Exception as e:
        w(f"nuclei execution failed: {e}")
        return []

    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(data, dict):
            continue

        info = data.get("info")
        if not isinstance(info, dict):
            info = {}

        sev = str(info.get("severity") or "info").capitalize()
        template_id = str(data.get("template-id") or "unknown")
        matcher_name = str(data.get("matcher-name") or "")
        finding = {
            "type": f"nuclei_{template_id}",
            "title": f"Nuclei: {info.get('name') or template_id}",
            "url": str(data.get("matched-at") or data.get("host") or ""),
            "detail": f"{info.get('description') or f'Template: {template_id}'}",
            "waf": "",
            "time": 0,
            "status": info.get("status") or 0,
            "confidence": "confirmed",
            "cvss_score": _nuclei_severity_to_cvss(sev),
            "cvss_severity": sev,
            "cvss_vector": "N/A",
            "nuclei_template": template_id,
            "nuclei_matcher": matcher_name,
        }
        if policy and not policy.allows_url(finding["url"]):
            continue
        if matcher_name:
            finding["detail"] += f" [{matcher_name}]"
        findings.append(finding)

    # Real counting: debit jumlah request NYATA dari stats JSON (-sj) ke
    # budget scan. Dulu nuclei tak pernah di-charge sama sekali — total
    # trafik melebihi max_requests berkali-kali tanpa jejak (audit lama:
    # 59% request modul lain mati request_budget_exhausted). Jalur timeout
    # pun tetap punya stats parsial (granularitas 10s) — tetap didebit.
    if policy:
        stats_requests = re.findall(r'"requests":"(\d+)"', stderr or "")
        if stats_requests:
            n_used = int(stats_requests[-1])
            charged = policy.charge(
                n_used,
                reason="nuclei" if rc != -1 else "nuclei(timeout-partial)")
            if charged < n_used:
                w(f"nuclei consumed {n_used} requests but only {charged} "
                  f"fit the remaining budget (max_requests overflowed)")
        else:
            w("nuclei stats unavailable — this run's traffic not debited "
              "to max_requests")

    # Surface tool failures: rc/stderr were previously discarded right here,
    # making a crashed/failed run indistinguishable from a clean 0-finding
    # scan (false-negative operasional). Timeout is already logged by
    # _run_tool with partial-output salvage — don't double-report it.
    if rc != 0 and "timeout after" not in (stderr or ""):
        # Stderr tanpa -silent membawa banner/[INF] — buang baris stats
        # lalu ambil tail yang meaningful.
        stripped = "\n".join(
            ln for ln in (stderr or "").splitlines() if '"requests"' not in ln
        ).strip()
        tail = stripped[-150:] if stripped else "(no stderr)"
        note = f"{len(findings)} finding(s) salvaged" if findings else "0 findings"
        w(f"nuclei exited rc={rc} ({note}): {tail}")

    if findings:
        sev_counts = {}
        for f in findings:
            s = f["cvss_severity"]
            sev_counts[s] = sev_counts.get(s, 0) + 1
        count_str = " | ".join(f"{c} {s}" for s, c in sorted(sev_counts.items()))
        p(f"Nuclei findings: {count_str}")

    return findings


def _nuclei_severity_to_cvss(severity: str) -> float:
    """Map nuclei severity to approximate CVSS score."""
    return {
        "Critical": 9.8, "High": 7.5, "Medium": 5.3, "Low": 3.1, "Info": 0.0
    }.get(severity, 0.0)


# DALFOX — XSS Scanner

def run_dalfox(urls: List[str], timeout: int = 180, proxy: str = None,
               headers: dict = None, policy: Optional[ScanPolicy] = None) -> List[Dict]:
    """Run dalfox for XSS scanning.
    Returns list of XSS finding dicts.
    """
    if not _policy_allows_tool(policy, "dalfox"):
        return []
    if not _uncounted_tool_allowed(policy, "dalfox"):
        return []
    if policy:
        raw_count = len(urls)
        urls = policy.filter_urls(urls)
        if not urls and raw_count:
            w(f"policy filtered ALL {raw_count} dalfox target(s) — "
              "check audit log for filter_urls:<reason> entries")
    if not urls:
        return []

    findings = []
    input_data = "\n".join(urls)

    try:
        dalfox_args = [
            "pipe",
            "--silence",
            # jsonl, BUKAN json: --format json mencetak array pretty-print
            # multi-baris sementara parser kita per-baris (json.loads per
            # line) — setiap finding nyata gagal diparse dan dalfox selalu
            # terlihat "0 findings".
            "--format", "jsonl",
            "--skip-bav",
            "--no-color",
        ]
        if headers:
            for k, v in headers.items():
                dalfox_args.extend(["--header", f"{k}: {v}"])
        # Add proxy flag (dalfox supports --proxy)
        effective_proxy = _tool_proxy(proxy)  # only from explicit arg, not env auto
        if effective_proxy:
            dalfox_args.extend(["--proxy", effective_proxy])

        rc, stdout, stderr = _run_tool("dalfox", dalfox_args,
                                        timeout=timeout, input_data=input_data,
                                        proxy=proxy)
    except FileNotFoundError:
        w("dalfox not installed — skipping dalfox XSS scan, tool will continue with internal engine")
        return []
    except Exception as e:
        w(f"dalfox execution failed: {e}")
        return []

    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(data, dict):
            continue

        if data.get("type") == "Verified" or data.get("poc"):
            param = str(data.get("param") or "unknown")
            payload = str(data.get("payload") or "")[:80]
            finding = {
                "type": "reflected_xss",
                "title": f"XSS (dalfox): {param}",
                "url": str(data.get("poc") or data.get("data") or ""),
                "detail": f"Param: {param}, Payload: {payload}",
                "waf": "",
                "time": 0,
                "status": 0,
                "confidence": "confirmed",
            }
            if not policy or policy.allows_url(finding["url"]):
                findings.append(finding)

    # Same contract as run_nuclei: never hide a failed tool behind a clean
    # "0 findings" (timeout already logged by _run_tool).
    if rc != 0 and "timeout after" not in (stderr or ""):
        note = f"{len(findings)} finding(s) salvaged" if findings else "0 findings"
        w(f"dalfox exited rc={rc} ({note}): {(stderr or '').strip()[:150]}")

    return findings


# TOOL INIT / INSTALL CHECK
