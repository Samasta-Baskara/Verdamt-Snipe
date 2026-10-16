"""curl-based HTTP sender with --resolve support for origin IP scanning.

Resolves SNI issue: when scanning origin IP via HTTPS, curl --resolve
sends the domain as SNI while routing traffic to the origin IP.
"""

import os
import subprocess
import tempfile
from typing import Dict, Optional
from urllib.parse import urlparse


def curl_send(url: str, resolve_domain: str = None, resolve_ip: str = None,
              method: str = "GET", headers: dict = None, data: str = None,
              timeout: int = 10, proxy: str = None, policy=None) -> Dict:
    """HTTP request via curl with optional --resolve for origin IP scan.

    When resolve_domain + resolve_ip are set, uses curl's --resolve flag:
      curl --resolve domain:443:origin_ip https://domain/path
    This sends the domain as SNI (correct TLS), but routes to origin IP.

    Uses a single curl call (body saved to temp file, metadata via -w).

    policy: saat diberikan, request melewati authorize_request yang SAMA
    dengan jalur ahttp_send — scope check, debit max_requests (1 request
    persis per panggilan) dan audit trail. Dulu jalur origin-IP ini lolos
    total dari kebijakan/anggaran.
    """
    if policy:
        decision = policy.authorize_request(url, method=method,
                                            headers=headers, body=data)
        if not decision.allowed:
            return {"status": 0, "error": f"policy_denied:{decision.reason}",
                    "body": "", "headers": {}, "time": 0}
        if getattr(policy, "dry_run", False):
            policy.refund_request(reason="dry_run", url=url)
            return {"status": 200, "error": None,
                    "body": "[DRY RUN] Request authorized but not dispatched to network.",
                    "headers": {}, "time": 0.001}

    fd, body_file = tempfile.mkstemp(suffix=".curl_body")
    os.close(fd)
    cmd = ["curl", "-s", "--max-time", str(timeout), "-o", body_file,
           "-w", "%{http_code}:%{time_total}:%{size_download}"]

    # Proxy
    if proxy:
        cmd.extend(["--proxy", proxy])

    # Resolve: domain -> origin IP (fixes SNI issue)
    if resolve_domain and resolve_ip:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        cmd.extend(["--resolve", f"{resolve_domain}:{port}:{resolve_ip}"])
        cmd.extend(["-k"])  # Skip cert verification (IP != domain)

    # Method
    if method != "GET":
        cmd.extend(["-X", method])

    # Headers
    for k, v in (headers or {}).items():
        cmd.extend(["-H", f"{k}: {v}"])

    # Data
    if data:
        cmd.extend(["--data", data])

    cmd.append(url)

    # Popen (bukan subprocess.run) + registry: subprocess.run tak terjangkau
    # kill_active_procs — jalur origin-IP internal injection tetap menembak
    # target melewati --max-time/crash.
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except Exception as e:
        return {"status": 0, "error": str(e)[:100], "body": "", "headers": {}, "time": 0}
    from core.external_tools import track_proc, untrack_proc
    track_proc(proc)
    try:
        out, err_out = proc.communicate(timeout=timeout + 2)
        if proc.returncode != 0:
            return {"status": 0, "error": (err_out or "").strip()[:100], "body": "", "headers": {}, "time": 0}

        parts = (out or "").strip().split(":")
        code = int(parts[0]) if parts and parts[0].isdigit() else 0
        elapsed = float(parts[1]) if len(parts) > 1 else 0
        size = int(parts[2]) if len(parts) > 2 else 0

        # Read body from temp file
        body = ""
        if os.path.exists(body_file):
            try:
                with open(body_file, "r", errors="replace") as f:
                    body = f.read()
            except Exception:
                body = ""

        return {
            "status": code,
            "body": body,
            "headers": {},
            "time": elapsed,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        return {"status": 0, "error": "timeout", "body": "", "headers": {}, "time": timeout}
    except Exception as e:
        return {"status": 0, "error": str(e)[:100], "body": "", "headers": {}, "time": 0}
    finally:
        untrack_proc(proc)
        # Clean up temp file
        if os.path.exists(body_file):
            try:
                os.unlink(body_file)
            except Exception:
                pass
