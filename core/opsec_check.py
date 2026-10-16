"""OPSEC Checklist — Pre/post scan operational security for VDP hunting.

Usage:
    python3 -m core.opsec_check              # Full checklist
    python3 -m core.opsec_check --quick      # Quick check (IP + DNS only)
    python3 -m core.opsec_check --proxy socks5://ip:port  # Check through proxy
"""

import os
import socket
import subprocess
import sys


def check_ip(proxy: str | None = None) -> dict:
    """Check current IP address (direct vs through proxy).

    A working proxy MUST yield a different egress IP than the direct one —
    that difference is what proves the proxy actually routes traffic. If
    both match, the proxy is transparent/broken and traffic leaves from the
    real IP (leak). With no proxy configured there is nothing to compare:
    scanning direct is a deliberate choice, not a leak.
    """
    result = {"direct_ip": None, "proxy_ip": None, "ip_leak": None,
              "proxy_configured": bool(proxy)}

    # Direct IP
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "5", "https://api.ipify.org"],
            capture_output=True, text=True, timeout=8, check=False,
        )
        if r.returncode == 0:
            result["direct_ip"] = r.stdout.strip()
    except Exception:
        pass

    # Proxy IP
    if proxy:
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "5", "--proxy", proxy, "https://api.ipify.org"],
                capture_output=True, text=True, timeout=8, check=False,
            )
            if r.returncode == 0:
                result["proxy_ip"] = r.stdout.strip()
        except Exception:
            pass

        # Leak only when a proxy is configured AND its egress equals the
        # direct IP (proxy not routing). Incomplete data -> None (unknown),
        # never a false "leak".
        if result["direct_ip"] and result["proxy_ip"]:
            result["ip_leak"] = result["direct_ip"] == result["proxy_ip"]

    return result


def check_dns(proxy: str | None = None) -> dict:
    """Check for DNS leaks."""
    result = {"local_dns": [], "doh_dns": [], "dns_leak": True}

    # Local DNS
    try:
        _, _, ips = socket.gethostbyname_ex("dnsleaktest.com")
        result["local_dns"] = ips
    except Exception:
        pass

    # DoH DNS
    try:
        from core.doh_resolve import doh_resolve
        result["doh_dns"] = doh_resolve("dnsleaktest.com", proxy=proxy)
    except Exception:
        pass

    # Check for leak
    if result["local_dns"] and result["doh_dns"]:
        result["dns_leak"] = result["local_dns"] != result["doh_dns"]

    return result


def check_websocket_leak() -> dict:
    """Check if WebRTC/WebSocket can leak IP."""
    result = {"webRTC_risk": True, "note": ""}

    # Check if Firefox WebRTC is disabled
    try:
        firefox_prefs = os.path.expanduser("~/.mozilla/firefox")
        if os.path.exists(firefox_prefs):
            for profile in os.listdir(firefox_prefs):
                prefs_file = os.path.join(firefox_prefs, profile, "prefs.js")
                if os.path.exists(prefs_file):
                    with open(prefs_file) as f:
                        # Firefox writes the pref WITH a space after the comma
                        content = f.read().replace(" ", "")
                        if '"media.peerconnection.enabled",false' in content:
                            result["webRTC_risk"] = False
                            result["note"] = "WebRTC disabled in Firefox profile"
                            return result
    except Exception:
        pass

    result["note"] = "WebRTC may leak IP — run: python3 -m core.browser_harden"
    return result


def check_env_leak() -> dict:
    """Check if proxy env vars are set correctly."""
    result = {"env_set": False, "vars": {}}

    proxy_vars = ["VERDAMT_PROXY", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY",
                   "http_proxy", "https_proxy", "all_proxy"]

    for var in proxy_vars:
        val = os.environ.get(var)
        if val:
            result["env_set"] = True
            result["vars"][var] = val

    return result


def run_full_check(proxy: str | None = None) -> dict:
    """Run full OPSEC checklist."""
    from core.proxy_manager import resolve_proxy, verify_proxy_reachable
    active_proxy = proxy or resolve_proxy()
    results = {
        "ip": check_ip(active_proxy),
        "dns": check_dns(active_proxy),
        "webrtc": check_websocket_leak(),
        "env": check_env_leak() if not proxy else {"env_set": True, "vars": {"VERDAMT_PROXY": proxy}},
        # Pre-flight proxy health: True when no proxy (scanning direct on
        # purpose) or the proxy daemon answers TCP. False = proxy set but
        # dead -> every request will fail-closed (safe, but wasted scan).
        "proxy_reachable": verify_proxy_reachable(active_proxy) if active_proxy else True,
        "active_proxy": active_proxy,
    }

    # Overall status
    issues = []
    if results["ip"]["ip_leak"] is True:
        issues.append("IP LEAK: Proxy is NOT routing — traffic leaves from your real IP")
    if results["ip"]["proxy_configured"] and results["ip"]["ip_leak"] is None:
        issues.append("IP CHECK INCONCLUSIVE: proxy set but egress IP could not be retrieved (proxy down?)")
    if results["dns"]["dns_leak"]:
        issues.append("DNS LEAK: DNS queries visible to ISP")
    if results["webrtc"]["webRTC_risk"]:
        issues.append("WebRTC RISK: Browser may leak IP behind proxy")
    if active_proxy and not results["proxy_reachable"]:
        issues.append(f"PROXY DOWN: {active_proxy} not answering — requests will fail (no leak, but scan will find nothing)")

    results["issues"] = issues
    # "safe" == no anonymity issues. Scanning direct (no proxy) is NOT a
    # "leak" (it's deliberate) but it is also NOT "hidden" — so it is not
    # safe. Only a routed proxy with no other issues counts as safe.
    results["safe"] = len(issues) == 0 and bool(active_proxy)

    return results


def print_results(results: dict):
    """Print OPSEC check results."""
    print("\n" + "=" * 50)
    print("  OPSEC CHECKLIST — verdamt-snipe")
    print("=" * 50)

    # IP Check
    ip = results["ip"]
    print("\n  [IP ADDRESS]")
    print(f"  Direct IP:  {ip['direct_ip'] or 'N/A'}")
    print(f"  Proxy IP:   {ip['proxy_ip'] or 'N/A'}")
    if ip["ip_leak"] is True:
        print("  Status:     !! IP LEAK — proxy not routing, traffic leaves from real IP !!")
    elif ip["ip_leak"] is False:
        print("  Status:     OK — egress differs from direct IP (proxy is routing)")
    elif ip["proxy_configured"]:
        print("  Status:     ?? INCONCLUSIVE — proxy set but egress IP not retrieved")
    else:
        print("  Status:     DIRECT — no proxy configured, traffic leaves from real IP")

    # DNS Check
    dns = results["dns"]
    print("\n  [DNS LEAK]")
    print(f"  Local DNS:  {', '.join(dns['local_dns'][:3]) or 'N/A'}")
    print(f"  DoH DNS:    {', '.join(dns['doh_dns'][:3]) or 'N/A'}")
    if dns["dns_leak"]:
        print("  Status:     !! DNS LEAK DETECTED !!")
    else:
        print("  Status:     OK — DNS routed through DoH/proxy")

    # WebRTC Check
    webrtc = results["webrtc"]
    print("\n  [WebRTC]")
    if webrtc["webRTC_risk"]:
        print("  Status:     !! WebRTC MAY LEAK IP !!")
    else:
        print("  Status:     OK — WebRTC disabled")
    print(f"  Note:       {webrtc['note']}")

    # Env Check
    env = results["env"]
    print("\n  [ENVIRONMENT]")
    if env["env_set"]:
        print("  Proxy env:  SET")
        for var, val in env["vars"].items():
            print(f"    {var} = {val}")
    else:
        print("  Proxy env:  NOT SET")

    # Proxy reachability (pre-flight health-check)
    if results.get("active_proxy"):
        print("\n  [PROXY HEALTH]")
        print(f"  Proxy:      {results['active_proxy']}")
        if results.get("proxy_reachable"):
            print("  Status:     OK — proxy answering")
        else:
            print("  Status:     !! PROXY NOT ANSWERING !!")
            print("              (requests fail-closed: no IP leak, but scan finds nothing)")

    # Issues
    print(f"\n  {'=' * 46}")
    if results["safe"]:
        print("  STATUS: ALL CLEAR — No leaks detected")
    else:
        print(f"  STATUS: {len(results['issues'])} ISSUE(S) FOUND")
        for issue in results["issues"]:
            print(f"    !! {issue}")

    print(f"\n  {'=' * 46}")

    # Recommendations
    if not results["safe"]:
        print("\n  RECOMMENDATIONS:")
        if ip["ip_leak"]:
            print("    1. Set proxy: --proxy socks5://vps_ip:1080")
            print("    2. Or export: export ALL_PROXY=socks5://vps_ip:1080")
        if dns["dns_leak"]:
            print("    3. Use DoH: enabled automatically with --proxy")
            print("    4. Or set: network.proxy.socks_remote_dns = true in Firefox")
        if webrtc["webRTC_risk"]:
            print("    5. Harden browser: python3 -m core.browser_harden")

    print()


def print_anonymous_email_guide():
    """Print guide for anonymous email setup."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║              ANONYMOUS EMAIL GUIDE — VDP DISCLOSURE         ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  JANGAN PAKAI:                                               ║
║  ✗ Gmail/Yahoo/Outlook — linked ke identitas lo              ║
║  ✗ Email kantor/kampus — linked ke institusi                 ║
║  ✗ Email yang pernah lo pake di sosmed                       ║
║                                                              ║
║  PAKAI INI:                                                  ║
║                                                              ║
║  1. ProtonMail (protonmail.com)                              ║
║     ✅ End-to-end encrypted                                  ║
║     ✅ Bisa daftar tanpa recovery email                      ║
║     ✅ Tor onion address tersedia                            ║
║     ✅ Swiss jurisdiction (privacy-friendly)                 ║
║     ⚠️  Daftar lewat Tor/VPN (jangan dari IP lo)            ║
║                                                              ║
║  2. Tutanota (tutanota.com)                                  ║
║     ✅ End-to-end encrypted                                  ║
║     ✅ German jurisdiction (GDPR)                            ║
║     ✅ Bisa daftar anonymous                                 ║
║                                                              ║
║  3. Guerrilla Mail (guerrillamail.com)                       ║
║     ✅ Temporary/disposable                                  ║
║     ✅ Gak perlu daftar                                      ║
║     ⚠️  Gak bisa terima reply (1 arah)                      ║
║     ⚠️  Email expired dalam 1 jam                            ║
║                                                              ║
║  4. SimpleLogin / AnonAddy                                   ║
║     ✅ Email alias/forwarding                                ║
║     ✅ 1 email utama → banyak alias                          ║
║     ✅ Reply bisa lewat alias                                ║
║                                                              ║
║  CARA SETUP:                                                 ║
║  1. Aktifkan Tor/VPN                                         ║
║  2. Buka Tor Browser                                         ║
║  3. Daftar ProtonMail (pilih "I don't have recovery")        ║
║  4. Jangan isi nama/nomor HP beneran                         ║
║  5. Simpan credentials di password manager offline           ║
║  6. Pakai email ini untuk SEMUA disclosure                   ║
║                                                              ║
║  TEMPLATE DISCLOSURE EMAIL:                                  ║
║  ────────────────────────────────────────────                ║
║  Subject: Vulnerability Disclosure — [target]                ║
║                                                              ║
║  Dear Security Team,                                         ║
║                                                              ║
║  I am a security researcher. During routine                   ║
║  testing, I identified a vulnerability in your               ║
║  application. Details attached.                              ║
║                                                              ║
║  This report is submitted in good faith under                ║
║  responsible disclosure principles.                          ║
║                                                              ║
║  Regards,                                                    ║
║  [Pseudonym]                                                 ║
║  ────────────────────────────────────────────                ║
╚══════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    args = sys.argv[1:]

    if "--email-guide" in args:
        print_anonymous_email_guide()
    else:
        proxy = None
        if "--proxy" in args:
            idx = args.index("--proxy")
            if idx + 1 < len(args):
                proxy = args[idx + 1]

        results = run_full_check(proxy)
        print_results(results)
