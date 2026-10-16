import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import asyncio
from urllib.parse import urlencode

from core.client import AsyncNetworkEngine
from core.ui import B, G, N, Spinner, W, draw_table, i, p, ph, w

# EMBEDDED WORDLIST — 500+ high-value params from Arjun/ParamSpider/SecLists
PARAM_WORDLIST = [
    # Injection Hotspots
    "id", "page", "url", "file", "path", "dir", "search", "query", "q",
    "cmd", "exec", "command", "ping", "ip", "host", "hostname",
    "redirect", "redir", "dest", "destination", "to", "return", "returnTo",
    "next", "target", "rurl", "return_url", "redirect_url", "redirect_uri",
    "callback", "cb", "continue", "goto", "out", "view", "ref",
    "uri", "u", "link", "base", "site", "html", "val", "data",
    
    # Auth / Session
    "user", "username", "login", "email", "pass", "password", "passwd",
    "token", "auth", "key", "api_key", "apikey", "api-key", "secret",
    "session", "sid", "ssid", "csrf", "csrf_token", "nonce",
    "access_token", "refresh_token", "jwt", "bearer",
    "admin", "role", "group", "permission", "privilege", "level",
    
    # Database / CRUD
    "sort", "order", "orderby", "sortby", "column", "col", "field",
    "limit", "offset", "count", "num", "start", "end", "from", "to",
    "filter", "where", "select", "table", "db", "database",
    "insert", "update", "delete", "action", "do", "type", "mode",
    "cat", "category", "item", "product", "article", "post",
    "name", "title", "content", "body", "text", "message", "msg",
    "description", "desc", "comment", "note", "label", "tag",
    
    # File / Path
    "filename", "filepath", "file_path", "upload", "download",
    "doc", "document", "template", "tpl", "theme", "skin", "style",
    "lang", "language", "locale", "l", "i18n", "charset", "encoding",
    "include", "require", "load", "read", "fetch", "get", "source",
    "src", "img", "image", "pic", "photo", "avatar", "icon",
    "media", "video", "audio", "attachment", "asset",
    
    # Network / SSRF
    "proxy", "proxy_url", "proxyUrl", "request", "url_to", "domain",
    "endpoint", "api", "server", "service", "backend", "origin",
    "forward", "fwd", "port", "schema", "protocol",
    "webhook", "hook", "notify", "notification", "ping_url",
    
    # Format / Output
    "format", "fmt", "output", "response", "accept", "content_type",
    "render", "display", "show", "hide", "debug", "verbose", "log",
    "xml", "json", "csv", "pdf", "raw", "export", "import",
    
    # Pagination / Navigation
    "p", "pg", "page_num", "pagenum", "pn", "pagesize", "per_page",
    "size", "rows", "max", "min", "step", "index", "idx", "pos",
    "prev", "previous", "back", "forward", "first", "last",
    
    # Search / Filter
    "s", "keyword", "keywords", "term", "terms", "find", "lookup",
    "match", "pattern", "regex", "contains", "like", "prefix", "suffix",
    "year", "month", "day", "date", "time", "timestamp", "since", "until",
    "before", "after", "range", "between", "status", "state",
    
    # User / Profile
    "uid", "user_id", "userid", "member", "member_id", "account",
    "profile", "bio", "age", "gender", "phone", "mobile", "address",
    "city", "country", "region", "zip", "postal", "location", "geo",
    "lat", "lng", "latitude", "longitude", "coord",
    
    # Payment / E-commerce
    "price", "amount", "total", "subtotal", "tax", "discount", "coupon",
    "promo", "code", "voucher", "cart", "checkout", "order_id", "invoice",
    "payment", "method", "currency", "qty", "quantity", "sku",
    
    # Technical / Debug
    "config", "conf", "setting", "settings", "option", "options", "param",
    "params", "arg", "args", "env", "environment", "version", "ver", "v",
    "test", "dev", "staging", "prod", "production", "beta", "alpha",
    "trace", "track", "monitor", "metrics", "stat", "stats",
    "cache", "nocache", "no_cache", "refresh", "reload", "flush",
    "timeout", "delay", "wait", "sleep", "interval", "retry",
    "error", "err", "exception", "warning", "warn", "info",
    
    # Misc High-Value
    "class", "obj", "object", "model", "module", "plugin", "ext",
    "extension", "addon", "widget", "component", "handler", "controller",
    "method", "func", "function", "procedure", "call", "invoke",
    "event", "trigger", "signal", "channel", "topic", "queue",
    "scope", "namespace", "context", "ctx", "ref", "reference",
    "hash", "checksum", "signature", "sign", "verify", "validate",
    "encode", "decode", "encrypt", "decrypt", "compress", "extract",
    "width", "height", "w", "h", "x", "y", "z", "r", "color", "bg",
    
    # API Specific
    "client_id", "client_secret", "grant_type", "response_type",
    "scope", "state", "redirect_uri", "code_challenge",
    "assertion", "audience", "issuer", "subject", "claim",
    "fields", "expand", "include", "exclude", "embed", "populate",
    "projection", "aggregation", "pipeline", "cursor", "marker",
    "continuation", "page_token", "next_token", "scroll_id",
    
    # CMS / Framework
    "wp_nonce", "wp_action", "post_type", "taxonomy",
    "controller", "action", "route", "area", "namespace",
    "_method", "_token", "_format", "_locale", "_fragment",
]


class ParamBruteforcer:
    """Sync façade over AsyncParamBruteforcer for legacy sync callers.

    All probe logic lives in AsyncParamBruteforcer — this wrapper only
    spins up a private event loop + engine so `to_thread`-style callers
    keep working without duplicating the diffing implementation.
    """

    def __init__(self, url: str, wordlist: list[str] | None = None, threads: int = 15,
                 chunk_size: int = 10, policy=None):
        self.url = url.split("?")[0]  # Strip existing params
        self.wordlist = wordlist or PARAM_WORDLIST
        self.threads = threads
        self.chunk_size = chunk_size  # Params per request for bulk phase
        self.policy = policy
        self.found: set[str] = set()

    async def _run_inner(self) -> list[str]:
        engine = AsyncNetworkEngine(policy=self.policy)
        try:
            return await AsyncParamBruteforcer(
                self.url,
                engine,
                wordlist=self.wordlist,
                concurrency=max(self.threads, 3),
                chunk_size=self.chunk_size,
            ).run()
        finally:
            await engine.close()

    def run(self) -> list[str]:
        self.found = set(asyncio.run(self._run_inner()))
        return sorted(self.found)


class AsyncParamBruteforcer:
    """Async Arjun-style parameter discovery backed by AsyncNetworkEngine."""

    def __init__(
        self,
        url: str,
        network_engine: AsyncNetworkEngine,
        wordlist: list[str] | None = None,
        concurrency: int = 25,
        chunk_size: int = 10,
        session_manager=None,
    ):
        self.url = url.split("?")[0]
        self.engine = network_engine
        self.wordlist = wordlist or PARAM_WORDLIST
        self.concurrency = concurrency
        self.chunk_size = chunk_size
        self.session_manager = session_manager
        self.found: set[str] = set()
        self.baseline = None
        self.rate_limited = 0
        self._sem = asyncio.Semaphore(concurrency)

    async def _send(self, url: str, timeout: int = 8) -> dict:
        async with self._sem:
            return await self.engine.ahttp_send(
                url,
                timeout=timeout,
                state_context=self.session_manager,
            )

    async def _get_baseline(self) -> dict:
        r = await self._send(self.url, timeout=10)
        body = r.get("body") or ""
        return {
            "status": r.get("status", 0),
            "length": len(body),
            "body_hash": hash(body[:500]),
            "headers": set((r.get("headers") or {}).keys()),
        }

    def _is_different(self, response: dict) -> bool:
        if not self.baseline:
            return False

        body = response.get("body") or ""
        status = response.get("status", 0)
        if status != self.baseline["status"] and status > 0:
            return True

        if self.baseline["length"] > 0:
            diff_ratio = abs(len(body) - self.baseline["length"]) / max(self.baseline["length"], 1)
            if diff_ratio > 0.05:
                return True

        if hash(body[:500]) != self.baseline["body_hash"]:
            return True

        new_headers = set((response.get("headers") or {}).keys()) - self.baseline["headers"]
        return bool(new_headers)

    async def _test_single(self, param: str) -> str | None:
        target = f"{self.url}?{urlencode({param: 'FUZZ'})}"
        r = await self._send(target)
        if r.get("status") == 429:
            self.rate_limited += 1
            return None
        if r.get("status", 0) > 0 and self._is_different(r):
            return param
        return None

    async def _test_chunk(self, params: list[str]) -> list[str]:
        query = "&".join(f"{p}=FUZZ{i}" for i, p in enumerate(params))
        target = f"{self.url}?{query}"
        r = await self._send(target)
        if r.get("status") == 429:
            self.rate_limited += 1
            return []
        if r.get("status", 0) <= 0 or not self._is_different(r):
            return []

        hits = await asyncio.gather(*(self._test_single(param) for param in params))
        return [h for h in hits if h]

    async def run(self) -> list[str]:
        ph("ARJUN ENGINE: Async Hidden Parameter Discovery")
        i(f"Target: {W}{self.url}{N}")
        i(f"Wordlist: {W}{len(self.wordlist)}{N} params | Chunk size: {self.chunk_size} | Concurrency: {self.concurrency}")

        spin = Spinner("Capturing baseline response...")
        self.baseline = await self._get_baseline()
        spin.stop()

        if self.baseline["status"] == 0:
            w("Target unreachable. Skipping param bruteforce.")
            return []

        i(f"Baseline: Status={self.baseline['status']}, Length={self.baseline['length']}")

        chunks = [self.wordlist[i:i + self.chunk_size] for i in range(0, len(self.wordlist), self.chunk_size)]
        p(f"Phase 1: Async bulk scanning {B}{len(chunks)}{N} chunks...")
        spin = Spinner("Scanning params...")
        spin.start()

        tasks = [self._test_chunk(chunk) for chunk in chunks]
        for coro in asyncio.as_completed(tasks):
            if self.rate_limited >= 3:
                spin.stop()
                w("Rate limit detected repeatedly. Stopping parameter bruteforce early.")
                break
            try:
                hits = await coro
            except Exception:
                continue
            for hit in hits:
                if hit not in self.found:
                    self.found.add(hit)

        spin.stop()

        if self.found:
            rows = [[f"{G}FOUND{N}", f"{W}{param}{N}"] for param in sorted(self.found)]
            draw_table(["STATUS", "PARAMETER"], rows, title="Discovered Hidden Parameters")
        else:
            w("No hidden parameters discovered.")

        p(f"Hidden params found: {G}{len(self.found)}{N}")
        return sorted(self.found)
