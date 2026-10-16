import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import asyncio
from typing import List, Dict
from core.ui import ph, i, p, draw_table, Spinner, Y, R, N, W, B

class TakeoverChecker:
    """Check for dangling CNAMEs and potential subdomain takeovers (async)."""

    SERVICES = {
        "amazonaws.com": "AWS/S3",
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "bitbucket.io": "Bitbucket",
        "cloudfront.net": "Cloudfront",
        "azurewebsites.net": "Azure",
        "wpengine.com": "WPEngine",
        "zendesk.com": "Zendesk",
        "readme.io": "Readme.io",
        "myshopify.com": "Shopify"
    }

    def __init__(self, subdomains: List[str], concurrency: int = 20):
        self.subdomains = subdomains
        self.concurrency = concurrency
        self.findings = []

    async def _check_cname(self, sub: str) -> Dict:
        try:
            # 'host -t CNAME' is the portable way to resolve CNAME chains
            # without a dnspython dependency.
            proc = await asyncio.create_subprocess_exec(
                "host", "-t", "CNAME", sub,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            res = (await proc.communicate())[0].decode()
            if "is an alias for" in res:
                cname = res.split("is an alias for")[-1].strip().rstrip(".")
                for sig, name in self.SERVICES.items():
                    if sig in cname:
                        return {"sub": sub, "cname": cname, "service": name, "risk": "High"}
        except Exception:
            pass
        return None

    async def run(self) -> List[Dict]:
        ph("TAKEOVER ENGINE: Hunting Dangling CNAMEs")
        i(f"Checking {W}{len(self.subdomains)}{N} subdomains for takeover risks...")
        
        results = []
        spin = Spinner("Analyzing CNAME records...")
        sem = asyncio.Semaphore(self.concurrency)

        async def _bounded(sub: str) -> Dict:
            async with sem:
                spin.next()
                return await self._check_cname(sub)

        tasks = [asyncio.create_task(_bounded(s)) for s in self.subdomains]
        try:
            for coro in asyncio.as_completed(tasks):
                r = await coro
                if r:
                    spin.stop()
                    results.append(r)
                    print(f"  {R}[!!]{N} {B}{R}POTENTIAL TAKEOVER:{N} {W}{r['sub']}{N} -> {Y}{r['cname']}{N} ({r['service']})")
        finally:
            for t in tasks:
                t.cancel()
        spin.stop()
        
        if results:
            rows = [[f"{R}HIGH{N}", r["sub"], r["service"]] for r in results]
            draw_table(["RISK", "SUBDOMAIN", "SERVICE"], rows, title="Subdomain Takeover Findings")
        else:
            p("No dangling CNAMEs found.")

        self.findings = results
        return results
