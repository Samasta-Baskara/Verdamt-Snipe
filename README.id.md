<h1 align="center">🎯 Verdamt-Snipe v1.4.5 NEXUS</h1>
<h4 align="center">Framework Keamanan Web Async-First, TLS Impersonation, Playwright Automation Engine & Vulnerability Assault</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.4.5%20NEXUS-crimson.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.12%2B-blue.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/Architecture-AsyncIO%20%2B%20Go%20Native-00ADD8.svg" alt="Dual Engine (AsyncIO + Go Native)">
  <img src="https://img.shields.io/badge/TLS%20Spoofing-curl__cffi%20%7C%20JA3-purple.svg" alt="TLS Spoofing">
  <img src="https://img.shields.io/badge/Playwright-10--Module%20Suite-success.svg" alt="Playwright Suite">
  <img src="https://img.shields.io/badge/UI-Tactical%20Rich%20TUI%20(15%20FPS)-gold.svg" alt="Tactical TUI">
  <img src="https://img.shields.io/badge/OOB%20Engine-Interactsh%20Client-blueviolet.svg" alt="OOB Interactsh">
  <img src="https://img.shields.io/badge/WAF%20Bypass-Origin%20Hunter%20%2B%20Obfuscator-red.svg" alt="WAF Bypass">
  <img src="https://img.shields.io/badge/Protocols-HTTP%2F2%20%7C%20HTTP%2F1.1%20%7C%20WS-orange.svg" alt="Protocols">
  <img src="https://img.shields.io/badge/Scan%20Modes-7%20Tactical%20Pipelines-darkgreen.svg" alt="Scan Modes">
  <img src="https://img.shields.io/badge/Scoring-CVSS%20v3.1-critical.svg" alt="CVSS v3.1">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License MIT">
</p>

<p align="center">
  🌐 <a href="README.md">English</a> · <b>Bahasa Indonesia</b> · <a href="README.ja.md">日本語</a> · <a href="README.zh.md">简体中文</a>
</p>

<p align="center">
  <a href="#-ringkasan-cepat">Ringkasan</a> •
  <a href="#-screenshots--live-demo">Demo Visual</a> •
  <a href="#-teknologi--tenaga-penggerak">Teknologi</a> •
  <a href="#-arsitektur-sistem">Arsitektur</a> •
  <a href="#-pipeline-flowchart">Flowchart</a> •
  <a href="#%EF%B8%8F-cara-kerja-how-it-works">Cara Kerja</a> •
  <a href="#-7-mode-pemindaian">Mode Scan</a> •
  <a href="#-playwright-security-suite-10-modul">Playwright Suite</a> •
  <a href="#%EF%B8%8F-attack-surface-matrix">Attack Surface</a> •
  <a href="#-benchmark-highlights">Benchmark</a> •
  <a href="#%EF%B8%8F-cara-install">Instalasi</a> •
  <a href="#-cara-penggunaan">Penggunaan</a> •
  <a href="#-dokumentasi-lengkap">Dokumentasi</a>
</p>

---

## ⚡ Ringkasan Cepat

**Verdamt-Snipe v1.4.5 NEXUS** adalah framework audit keamanan web asinkron (*async-first*) berkinerja tinggi yang menggabungkan kecepatan **Python AsyncIO**, kecepatan eksekusi native **Go Engine Bridge**, penyamaran sidik jari TLS **`curl_cffi` (JA3/JA4)**, serta otomasi browser headless **Playwright Chromium**:

1. **Apa ini?** — Alat pemindaian, pengintaian (*recon*), dan eksploitasi terverifikasi serba asinkron dengan antarmuka konsol taktis militer (*Tactical Rich TUI 15 FPS*) dan laporan interaktif otomatis (HTML & PDF).
2. **Untuk siapa?** — Dirancang khusus untuk **Penetration Tester**, **Red Team**, dan **Bug Bounty Hunter** yang membutuhkan kecepatan tinggi, akurasi tinggi, serta kapabilitas menembus proteksi WAF/Bot Protection tanpa kebocoran memori.
3. **Fitur Unggulan**:
   - **Triple-Engine Throughput**: Koordinasi AsyncIO Python, **Go Engine internal** (`verdamt-engine` via IPC Unix Socket, auto-compile saat toolchain Go tersedia), dan binary Go eksternal (`subfinder`, `httpx`, `katana`, `nuclei`, `dalfox`, `gau`, `waybackurls`, `ffuf`, `gf`).
   - **WAF Bypass & Origin Hunting**: Mengungkap IP origin di balik Cloudflare/Akamai, payload mutator adaptif, serta penyamaran fingerprint TLS browser asli (Chrome, Firefox, Safari).
   - **Shared Browser Singleton Pool**: Menjalankan 10 modul audit browser (DOM XSS, PostMessage, CORS, Prototype Pollution, dll.) secara efisien dan stabil.
   - **Poisoning & OOB Engine**: Wave-loop poisoning (cache, smuggling, flood bruteforce) dan deteksi Blind XSS/SSRF/RCE via callback interactsh.
   - **OpSec & Audit Trail Ketat**: Proteksi batas scope otomatis (`ScanPolicy`), simulasi `--dry-run`, dan log audit `.jsonl` yang siap di-replay menjadi perintah `curl`.

---

## 📸 Screenshots & Live Demo

Tangkapan layar langsung antarmuka terminal interaktif dan artefak laporan yang dihasilkan:

### 1. Tactical Terminal TUI Dashboard
Dasbor terminal taktis 3-kolom berbasis `Rich` (15 FPS) dengan status pipeline, metrik hardware, sparkline RPS, dan pemantauan temuan kerentanan secara *real-time*.

Dasbor kini berjalan pada *alternate screen buffer* — kanvas tetap: seluruh output (log fase, tabel hasil, bahkan `print` liar) dialihkan ke dalam panel **Recent Activity**, dan scroll terminal tidak lagi mampu mendorong dasbor keluar layar. Feed aktivitas memiliki **scrollbar** sendiri:

- `↑` / `↓` atau **roda mouse** — gulir riwayat aktivitas ke atas / bawah
- `PgUp` / `PgDn` — lompat satu halaman riwayat
- `End` — kembali ke mode *live follow* (badge berubah menjadi `↕ SCROLLED · End` saat bebas gulir)

> Seleksi teks dengan mouse tetap bisa dilakukan dengan menahan `Shift`.

![Verdamt-Snipe Tactical TUI Dashboard](assets/terminal_tui_dashboard.jpg)

### 2. Interactive HTML Vulnerability Report
Laporan audit keamanan interaktif modern dengan tab filter keparahan OWASP, kartu ringkasan eksekutif, diagram distribusi risiko, skor CVSS v3.1, dan snippet kode remediasi otomatis:

![Verdamt-Snipe HTML Security Report](assets/html_security_report.jpg)

---

## ⚡ Teknologi & Tenaga Penggerak

| Komponen / Engine | Teknologi | Peran & Keunggulan |
| :--- | :--- | :--- |
| **Async Network Engine** | `Python AsyncIO` + `httpx` [HTTP/2] | Concurrency tinggi non-blocking, multiplexing HTTP/2, host rate-limiting & circuit breaker. |
| **TLS Impersonation** | `curl_cffi` (JA3/JA4 Spoofing) | Memalsukan handshake TLS agar identik dengan browser asli untuk menembus WAF & anti-bot. |
| **Go Engine Bridge** | `core/go_bridge.py` + `go/cmd/engine` | Engine native JSON-over-Unix-Socket untuk probing massal & JS scanning; auto-compile saat Go terpasang, fallback mulus ke Python. |
| **External Go Tooling** | ProjectDiscovery & komunitas | Integrasi `subfinder`, `httpx`, `katana`, `nuclei`, `dalfox`, `gau`, `waybackurls`, `ffuf`, `gf` dengan degradasi anggun bila tidak terpasang. |
| **Browser Automation** | `Playwright Chromium` + `SharedPool` | 10 modul otomasi deep-browser bebas memory leak via singleton pool context terisolasi. |
| **Tactical TUI Dashboard** | `rich` Live Engine (15 FPS) + `psutil` | Dasbor konsol 3-kolom informatif: pipeline phase, sparkline RPS, temuan vuln, metrik hardware — kanvas tetap (alternate screen) dengan feed aktivitas ber-scrollbar. |
| **Policy & Audit Engine** | `ScanPolicy` + `AuditLogger` (`.jsonl`) | Scope enforcer, limitasi anggaran request, serta perekaman seluruh transaksi HTTP untuk PoC `curl`. |
| **State Management** | `SessionManager` + `ProjectState` | Manajemen multi-token (Bearer/Cookie jar) & mekanisme save/resume sesi pemindaian (`.state`). |
| **OOB / Interactsh Engine** | `python-interactsh` + `modules/extras/oob_detector.py` | Callback domain untuk Blind SSRF/XSS/RCE dengan logging hit *real-time*. |
| **Wordlist Provider** | `modules/wordlists.py` | Auto-deteksi wordlist lokal (`~/.wordlists`) dengan fallback unduh SecLists/Assetnote via `--setup-wordlists`. |

---

## 📐 Arsitektur Sistem

Framework ini mengadopsi arsitektur 4-layer modular berkecepatan tinggi:

```mermaid
graph TD
    subgraph Layer1 ["1. Entry Points & CLI Layer"]
        CLI["verd.py (CLI Entry)"]
        Launcher["snipe (Bash Launcher)"]
        Parser["core/cli_parser.py"]
        CLI --> Parser
        Launcher --> CLI
    end

    subgraph Layer2 ["2. Core Engine & Runtime"]
        Engine["AsyncNetworkEngine (httpx HTTP/2)"]
        GoBridge["GoEngineBridge (verdamt-engine, IPC Unix Socket)"]
        GoTools["Binary Go Eksternal (subfinder, httpx, katana, nuclei, dalfox, gau, waybackurls)"]
        TLS["curl_cffi Transport (JA3/JA4 TLS Spoofing)"]
        BrowserPool["SharedBrowserPool (Playwright Singleton)"]
    end

    subgraph CrossCutting ["Cross-Cutting Services"]
        Scope["ScopeGuard & ScanPolicy"]
        Rate["RateLimiter & CircuitBreaker"]
        Session["SessionManager (Cookies & Bearer)"]
        Proxy["ProxyManager (SOCKS5/HTTP Rotation)"]
    end

    subgraph Layer3 ["3. Runners & Security Modules"]
        Runners["runners/ (surface, recon_intel, recon_light, app_analysis, vuln_assault, full_assault, poison)"]
        Scanners["modules/scanners/ (AsyncVulnEngine 12 Checks)"]
        ClientSide["modules/web/client_side/ (DOM XSS, Proto Pollution, CORS, PostMessage, CSRF, Clickjacking)"]
        ServerSide["modules/web/server_side/ (SQLi, SSRF, IDOR, CRLF, Host Header, Cache Poisoning, Smuggling)"]
        ApiAuth["modules/web/api_auth/ (JWT, OAuth, GraphQL, OpenAPI)"]
        WAF["modules/waf/ (WAFBypass & Origin Hunter)"]
        ReconMods["modules/recon/ + modules/extras/ (Dorking, JSScanner, Takeover, Arjun, OOB)"]
    end

    subgraph Layer4 ["4. Output & State"]
        RepEngine["reports/ ReportEngine (HTML JS Tabs & WeasyPrint PDF)"]
        Audit["AuditLogger (.jsonl + cURL Replay)"]
        State["ProjectState (.state Checkpoints)"]
        TUI["Tactical Rich TUI Dashboard"]
    end

    Parser --> Scope & Session & Proxy & Runners
    Runners --> Engine & GoBridge & GoTools & BrowserPool
    Engine -.-> TLS
    Engine --> Scanners & ServerSide & WAF & ReconMods
    BrowserPool --> ClientSide & ApiAuth
    Scanners & ClientSide & ServerSide & ApiAuth --> RepEngine
    Engine --> Audit & State & TUI
```

> 📖 **Arsitektur Lengkap:** Rincian 14 komponen internal, alur data sekvensial, dan security architecture tersedia di [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🔄 Pipeline Flowchart

Alur eksekusi multi-fase deterministik dengan percabangan 7 mode pemindaian:

```mermaid
flowchart TD
    Start(["Mulai Pemindaian"]) --> Parse["Parsing CLI & Scope Policy"]
    Parse --> CheckResume{"Resume Sesi?<br>(--resume file.state)"}

    CheckResume -- "Ya" --> LoadState["Restore ProjectState"] --> ModeSelect
    CheckResume -- "Tidak" --> Phase0["Phase 0: Surface Scan<br>(DNS, Scope Check, Port Probing)"] --> ModeSelect

    ModeSelect{"Pilihan Mode Pemindaian"}
    ModeSelect -- "1: recon" --> Phase1["Phase 1: Recon Intel (GAU, Wayback, JS Secrets, Dorking, Takeover)"] --> Phase5Report
    ModeSelect -- "2: app" --> Phase2App["App Analysis (WAF/Origin Hunt, DeepCrawler, SPA, OpenAPI/GraphQL, Param Discovery)"] --> Phase5Report
    ModeSelect -- "3: assault" --> PhaseEnrich["Auto-Enrich resmi (Auto-Recon → Katana Crawl → Auto-App)<br>hanya bila korpus/param kosong"] --> Phase3Assault["Vuln Assault (AsyncVulnEngine + DalFox/Nuclei + OOB)"] --> Phase4Verify["Phase 4: PoC Verification"] --> Phase5Report
    ModeSelect -- "4: poisoning" --> PoisonRunner["Poisoning Runner (Seed Crawl bila tipis, Wave Loop, Flood & Blind XSS OOB)"] --> Phase5Report
    ModeSelect -- "5: full" --> Phase1Full["Recon Intel"] --> KatanaFull["Katana Crawl"] --> Phase2Full["App Analysis"] --> WAFull["WAF / Origin Hunt"] --> Phase3Full["Vuln Assault"] --> PoisonFull["Poisoning Wave Loop"] --> Phase4Verify --> Phase5Report
    ModeSelect -- "6: recon-light" --> LightRecon["Crawl Ringan, HTTPX Probing & Baseline Header"] --> Phase5Report
    ModeSelect -- "7: nuclei" --> NucleiEngine["Nuclei Template Scanning"] --> Phase5Report

    Phase5Report["Phase 5: Reporting Engine"] --> GenReport["Generate HTML (JS Tabs) & PDF (WeasyPrint)"]
    GenReport --> SaveState["Save State (.state)"] --> Done(["Selesai"])
```

---

## ⚙️ Cara Kerja (How It Works)

1. **Stage 1: Target Resolution** — Validasi cakupan (`ScopeGuard`), evaluasi `ScanPolicy`, resolusi DNS, probing HTTP/2 aktif, dan penguncian host terotorisasi.
2. **Stage 2: Intelligence Gathering** — Pengumpulan pasif via Wayback Machine, `gau` & `waybackurls`, pemindaian rahasia/endpoint pada bundel JS (`JSScanner`), Google dorking, deteksi subdomain takeover, dan baseline fingerprint keamanan.
3. **Stage 3: Application Mapping** — Crawl ringan via `DeepCrawler` + rekognisi SPA via Playwright (XHR/Fetch & token `LocalStorage`), ingestion spesifikasi OpenAPI/GraphQL, serta penemuan parameter (ParamExtractor + bruteforce Arjun). Crawl berat **Katana** adalah fase resmi mode assault-class (`--assault`/`--poisoning`/`--full`), bukan bagian mode `--app`.
4. **Stage 4: Vulnerability Assault** — Uji kerentanan paralel via **AsyncVulnEngine** (12 pemeriksaan), modul web fokus (JWT, IDOR, CRLF, Host Header, Stored XSS), pembongkar Origin IP WAF, fuzzer DalFox, template Nuclei, ekstraksi Blind SQLi, dan deteksi OOB interactsh. Probe POST-body (HTTP/2 smuggling `CL.TE`, stored-XSS form, blind XXE) hanya berjalan di mode poisoning — sama seperti flood/connection-exhaust.
5. **Stage 5: Verification & Reporting** — Validasi ulang temuan di browser terisolasi (*confidence upgrade*), pembuatan perintah `curl` replay, serta generasi laporan HTML dan PDF.

---

## 🔍 7 Mode Pemindaian

| No | Flag CLI | Shortcut | Deskripsi Mode |
| :---: | :--- | :---: | :--- |
| **1** | `--recon` | `1` | **Passive Intel**: `gau`/`waybackurls`, pemindaian rahasia JS (`JSScanner`), Google dorking, cek subdomain takeover, & baseline header. |
| **2** | `--app` | `2` | **App Analysis**: Pemburu Origin IP (WAF bypass), crawl ringan `DeepCrawler` + rekognisi SPA (Playwright), API spec (OpenAPI/GraphQL), discovery parameter (ParamExtractor + Arjun). Crawl berat Katana **tidak** di sini. |
| **3** | `--assault` | `3` | **Vuln Assault**: auto-enrich resmi bila korpus/param kosong (Auto-Recon → Katana Crawl → Auto-App, tampil sebagai stage), WAF/Origin Hunt, lalu 12 pemeriksaan AsyncVulnEngine + modul web fokus (JWT, IDOR, CRLF, Host Header, Stored XSS) + DalFox + Nuclei + ekstraksi Blind SQLi + OOB. |
| **4** | `--poisoning` | `4` | **Poisoning**: seed crawl `Katana` (hanya bila korpus tipis, tampil sebagai stage) + wave-loop *Connection Exhaust*, *Web Cache Poisoning*, *HTTP Request Smuggling*, flood param/payload, & Blind XSS via OOB interactsh. |
| **5** | `--full` | `5` | **Full Pipeline**: `--recon` → Katana Crawl → `--app` → WAF/Origin Hunt → `--assault` → `--poisoning` — komposisi end-to-end kelas exploit. |
| **6** | `--recon-light` | `6` | **Recon Light**: Crawl homepage $\rightarrow$ ekstraksi link $\rightarrow$ validasi $\rightarrow$ audit baseline keamanan dasar (<60 detik). |
| **7** | `--nuclei` | `7` | **Nuclei Engine**: Eksekusi pemindaian berbasis template Nuclei secara efisien dan terarah. |

### 🗺️ Peta Fase & Modul per Mode (batas resmi)

Satu modul, satu rumah. Fase bertanda `*`/`**` bersifat kondisional dan tetap tampil sebagai stage resmi di dashboard (dengan tanda `— SKIPPED` bila tidak dijalankan).

| Mode | Urutan fase | Modul kunci | Batas / eksklusi |
| :--- | :--- | :--- | :--- |
| **1 RECON** | gau ∥ wayback ∥ dork ∥ takeover ∥ JS ∥ baseline → validasi | `gau`, `waybackurls`, `JSScanner`, `GoogleDorker`, `TakeoverChecker`, baseline (config/header/CORS) | pasif + arsip; tanpa crawl aktif, param, atau eksploitasi; boleh `--passive` |
| **2 APP** | WAF/origin`*` → API spec → crawl ringan → param → suite analisis | `DeepCrawler`, `BrowserRecon` (SPA), `OpenAPIParser`, `ParamExtractor` + Arjun, `DOMXSS`, `APIProfiler`, `GraphQLProfiler`, suite Playwright (CSRF/CORS/OAuth/PostMessage/WebSocket/Clickjacking/Proto-Pollution/SPA), `AuthTester` | **tanpa Katana**, tanpa arsip/dork; tanpa payload injeksi |
| **3 ASSAULT** | auto-recon`**` → katana crawl`**` → auto-app`**` → WAF/origin`*` → assault paralel | `Katana`, `nuclei`, `dalfox`, AsyncVulnEngine injection, `OOBDetector`, JWT/Host/CRLF/Stored-XSS/IDOR | enrichment hanya bila korpus/param kosong; probe POST-body khusus mode 4 |
| **4 POISONING** | WAF bypass`*` → seed crawl (bila tipis) → wave loop A/B/C/D | cache poison, smuggling, brute + param flood, connection exhaust, payload flood, OOB, assault POST | flood/DoS + POST-body (h2 `CL.TE`, form stored-XSS, blind XXE) hanya di sini |
| **5 FULL** | 1 → Katana → 2 → WAF → 3 → 4 | gabungan seluruh mode di atas | komposisi 1+2+3+4; probe POST aktif |
| **6 LIGHT** | link-crawl → validasi → baseline | tanpa tool eksternal | <60 detik; tanpa gau/wayback/dork/takeover/JS/Katana; boleh `--passive` |
| **7 NUCLEI** | resolusi target → nuclei | `nuclei` | template murni; **diblok saat `--passive`** |

`*` hanya dijalankan bila WAF/indikasinya terdeteksi · `**` hanya dijalankan bila korpus URL/param masih kosong.

---

## 🎭 Playwright Security Suite (10 Modul)

| No | Modul | File (`modules/web/…`) | Deskripsi Singkat |
| :---: | :--- | :--- | :--- |
| **1** | **DOM XSS PoC Verifier** | `client_side/dom_xss.py` | Verifikasi live eksekusi sink JS (`eval`, `innerHTML`, `document.write`). |
| **2** | **SPA Recon Engine** | `recon_crawlers/browser_recon.py` | Mengurai rute SPA, intersepsi endpoint XHR/Fetch, & ekstraksi token `LocalStorage`. |
| **3** | **CSRF Live Verifier** | `client_side/csrf_verify.py` | Simulasi penyerahan form cross-origin otomatis dengan kredensial sesi aktif. |
| **4** | **PostMessage Inspector** | `client_side/postmessage_analyzer.py` | Interseptor `window.postMessage()`, audit `event.origin`, dan kebocoran wildcard `*`. |
| **5** | **Clickjacking Inspector** | `client_side/clickjacking_verify.py` | Pengecekan rendering iframe live dan evaluasi `X-Frame-Options` / `frame-ancestors`. |
| **6** | **WebSocket Sniffer** | `recon_crawlers/websocket_recon.py` | Perekam handshake `wss://`/`ws://`, header autentikasi, dan frame streaming. |
| **7** | **Proto Pollution Verifier** | `client_side/proto_pollution_verify.py` | Injeksi dinamis `__proto__` dan deteksi modifikasi `Object.prototype` di runtime browser. |
| **8** | **OAuth / OIDC Auditor** | `api_auth/oauth_auditor.py` | Inspeksi redirect URI chain dan deteksi kebocoran token otorisasi via `Referer`. |
| **9** | **CORS Live Verifier** | `client_side/cors_verify.py` | Uji fetch cross-origin live dari domain terisolasi dengan `credentials: include`. |
| **10** | **Dynamic SPA Crawler** | `recon_crawlers/spa_crawler.py` | Simulasi klik tombol interaktif, pengisian input form, dan navigasi router SPA otomatis. |

---

## 🕸️ Attack Surface Matrix

Berikut ringkasan vektor kerentanan utama yang diuji secara otomatis:

| Kerentanan | Vektor & Indikator Deteksi | Keparahan (CVSS v3.1) |
| :--- | :--- | :---: |
| **Reflected / DOM XSS** | Refleksi unescaped string pada response body & verifikasi sink DOM via Playwright | **Medium (6.1)** |
| **Stored XSS** | Injeksi terverifikasi tersimpan & tereksekusi di browser terisolasi | **High (7.2)** |
| **Error / Time / Blind SQLi** | Sinyal error, differential latency (*response time differential* >5 detik) & binary search extract | **Critical (9.8)** |
| **RCE / Command Injection** | Refleksi output eksekusi command dengan payload WAF-aware | **Critical (9.8)** |
| **SSTI** | Evaluasi ekspresi template engine (`{{7*7}}`, `${...}`) pada parameter | **Critical (9.8)** |
| **LFI / Path Traversal** | Traversal pola `../../etc/passwd` pada parameter file/path | **High (7.5)** |
| **XXE** | Injeksi external entity pada body XML (refleksi file & OOB callback) | **High (7.5)** |
| **SSRF (Cloud Metadata)** | Ekstraksi endpoint internal loopback/metadata cloud & DNS callback interactsh | **High (8.8)** |
| **Web Cache Poisoning** | Injeksi unkeyed header (`X-Forwarded-Host`) & verifikasi respons `X-Cache: HIT` | **High** |
| **HTTP Request Smuggling** | Socket timeout / respons abnormal pada varian desinkronisasi `CL.TE`, `TE.CL`, & `CL.0` | **High (8.1)** |
| **Subdomain Takeover** | Fingerprint halaman *unclaimed* pada CNAME yatim (S3, GitHub Pages, dsb.) | **High (8.1)** |
| **JWT Weakness** | Algoritma `none`, weak secret brute-force, & injeksi `kid` pada token | **High (7.5–8.1)** |
| **Client-Side Proto Pollution** | Modifikasi atribut objek JavaScript global (`window.isAdmin` / `Object.prototype`) | **Medium / High** |
| **CORS Misconfiguration** | Refleksi `Origin: evil.com` dengan izin `Access-Control-Allow-Credentials: true` | **Medium (6.1)** |
| **Host Header Injection** | Refleksi `Host`/`X-Forwarded-Host` palsu & *password reset poisoning* | **Medium–High (5.3–8.1)** |
| **CRLF Injection** | Injeksi sequence `\r\n` yang menghasilkan header baru seperti `Set-Cookie` | **Medium (5.3)** |
| **IDOR / BOLA** | Akses sumber daya lintas-akun (token Role-2) & enumerasi ID massal | **Medium–High (5.3–8.1)** |
| **Sensitive File Exposure** | Paparan `.git`, `.env`, backup config, private key, & directory listing | **High (7.5–9.1)** |

---

## 📊 Benchmark Highlights

### Metrik Kinerja Antar Mode
| Mode Pemindaian | Kecepatan Target | Peak RPS | Rata-rata Durasi | Konsumsi Memori |
| :--- | :---: | :---: | :---: | :---: |
| **Recon Light** | ~50 targets/min | ~200 RPS | ~2 menit | ~150 MB |
| **Recon** | ~30 targets/min | ~150 RPS | ~5 menit | ~250 MB |
| **App Analysis** | ~20 targets/min | ~120 RPS | ~8 menit | ~400 MB |
| **Assault** | ~15 targets/min | ~100 RPS | ~12 menit | ~500 MB |
| **Full Pipeline** | ~10 targets/min | ~80 RPS | ~20 menit | ~600 MB |
| **Turbo Full (`--turbo`)** | ~25 targets/min | ~300 RPS | ~8 menit | ~1.2 GB |

### Perbandingan Efisiensi: Python AsyncIO vs Go Native Bridge
- **Subdomain Enumeration**: **~3.7x lebih cepat** menggunakan Go Native `subfinder` (~450+ sub/detik).
- **Archive URL Crawling**: **~4.0x lebih cepat** menggunakan Go Native `gau` (~1,200+ URL/detik).
- **Endpoint Probing**: **~3.2x lebih cepat** menggunakan Go Native `httpx` (~800+ probe/detik).
- **Headless Browser Execution**: Bebas memory leak (<400 MB stabil) berkat *SharedBrowserPool*.

> 📊 **Laporan Benchmark Penuh:** Analisis throughput, uji konkurensi, dan metodologi lengkap di [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

---

## 🎯 Typical Use Cases

1. **🏹 Bug Bounty Recon**: Pengumpulan kilat ribuan subdomain & endpoint tersembunyi dengan filter duplikasi otomatis.
2. **🛡️ WAF Bypass & Origin Hunt**: Mengungkap alamat IP origin server asli di balik Cloudflare/Akamai via modul `hunt_origin`.
3. **🖥️ Single Page App (SPA) Audit**: Ekstraksi token JWT dari `LocalStorage` dan audit mendalam alur REST API frontend.
4. **🔄 Otomasi CI/CD DevSecOps**: Evaluasi postur keamanan otomatis pada pipeline CI dengan mode `--passive` & batasan `--max-requests`.
5. **👁️ Blind Vulnerability Hunting**: Deteksi celah Out-Of-Band (Blind SSRF, Blind RCE, Blind XXE) via interactsh server.
6. **🔐 Multi-Context Auth Testing**: Pengujian otorisasi silang (User A vs User B) untuk menemukan celah BOLA/IDOR otomatis.

---

## ⚙️ Cara Install

**Persyaratan Sistem:** Linux / macOS, **Python 3.12+**, RAM 2GB+ (4GB disarankan untuk Playwright).

```bash
# 1. Clone repositori & masuk ke direktori
git clone https://github.com/Samasta-Baskara/Verdamt-Snipe.git
cd Verdamt-Snipe

# 2. Buat virtual environment & install dependensi
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Pasang Chromium Driver untuk modul browser
playwright install chromium

# 4. (Opsional) Bootstrap wordlist SecLists/Assetnote ke ~/.wordlists
python3 verd.py --setup-wordlists
```

> **Catatan engine:**
> - **Go Engine internal** (`go/cmd/engine`) otomatis di-compile saat toolchain Go tersedia; tanpa Go, framework tetap berjalan penuh via fallback Python AsyncIO.
> - **Binary Go eksternal** (`subfinder`, `httpx`, `katana`, `nuclei`, `dalfox`, `gau`, `waybackurls`, `ffuf`, `gf`) bersifat opsional — tool yang tidak terpasang dilewati dengan degradasi anggun.
> - Launcher `snipe` otomatis memakai interpreter dari `.venv` bila tersedia.

---

## 🚀 Cara Penggunaan

### 1. Menggunakan Launcher Praktis (`snipe`)
```bash
# Buka Menu Interaktif TUI
./snipe target.com

# Mode 5 (Full Pipeline) dengan TLS Impersonation Chrome
./snipe 5 target.com -i chrome

# Mode 3 (Vuln Assault) dengan mode Stealth & Proxy SOCKS5
./snipe 3 target.com -s -p socks5://127.0.0.1:9050

# Mode 4 (Poisoning) dengan seluruh flag fokus modul web
./snipe 4 target.com -a
```

**Shortcut Launcher:** `1`–`7` (mode) · `-s` stealth · `-t` turbo · `-r` resume · `-p` proxy · `-i` impersonation · `-j` JWT · `-x` stored XSS · `-id` IDOR · `-c` CRLF · `-hi` host injection · `-a` kelima flag fokus sekaligus.

### 2. Menggunakan Python CLI Langsung (`verd.py`)
```bash
# Pemindaian interaktif
python3 verd.py target.com

# Full Scan dengan batas scope ketat & limit request
python3 verd.py target.com --full --allowed-hosts target.com,api.target.com --max-requests 5000

# Pemindaian terotentikasi aman (tanpa terlihat di ps aux / riwayat shell)
python3 verd.py target.com --full --bearer env:API_TOKEN
python3 verd.py target.com --full --bearer-file /path/to/token.txt

# Fokus modul web tertentu (JWT / IDOR / CRLF / host header / stored XSS)
python3 verd.py target.com --assault --jwt --idor --stored-xss

# Stealth scan dengan anggaran waktu global 10 menit
python3 verd.py target.com --full -s --max-time 600

# Melanjutkan pemindaian yang terhenti (Resume)
python3 verd.py --resume outputs/target.com.state
python3 verd.py --resume target.com        # shorthand: pakai outputs/target.com.state
```

---

## 🛡️ OpSec & Safety Policy

Setiap operasi dilindungi oleh kontrol kebijakan yang ketat:

| Flag | Fungsi | Default |
| :--- | :--- | :---: |
| `--dry-run` | Merender payload & memvalidasi kebijakan tanpa mengirim paket ke jaringan target. | — |
| `--passive` | Membatasi pengujian hanya pada metode aman (`GET`, `HEAD`, `OPTIONS`) & melewati fase intrusif. | — |
| `--max-time <sec>` | Anggaran waktu global pemindaian (state ikut tersimpan saat budget habis). | — |
| `--max-requests N` | Kuota total request HTTP terhadap target (termasuk debit tool eksternal). | `30000` |
| `--max-concurrency N` | Batas request paralel terhadap target. | `100` |
| `--request-timeout <sec>` | Timeout per-request terhadap target. | `30` |
| `--allowed-hosts H1,H2` | Mengunci target hanya pada host yang memiliki otorisasi tertulis. | target saja |
| `--allowed-ports p,p` | Port yang diizinkan untuk probe aktif. | `80,443` |
| `--archive-timeout <sec>` | Anggaran waktu mining URL historis (`gau` + `waybackurls`) — target besar butuh lebih dari 30 detik. | `90` |
| `--no-dork` | Melewati scraping search engine (Google/DDG); daftar dork tetap diekspor ke `outputs/<target>_dorks.txt`. | scraping aktif |
| `--audit-log PATH` | Menyimpan log `.jsonl` lengkap yang dapat di-replay menjadi perintah `curl`. | otomatis |
| `--proxy-list` / `--proxy-rotate` / `--no-proxy` | Manajemen proxy bergilir & escape-hatch env `VERDAMT_PROXY`. | — |

---

## 📚 Dokumentasi Lengkap

Untuk panduan teknis mendalam, arsitektur, dan referensi lainnya:
- 📐 **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Arsitektur teknis lengkap, diagram 4-layer, & spesifikasi 14 komponen.
- 📊 **[docs/BENCHMARKS.md](docs/BENCHMARKS.md)** — Metrik performa, throughput profiling, & panduan tuning efisiensi.
- 📖 **[docs/tutorial.md](docs/tutorial.md)** — Tutorial taktis, panduan skenario nyata, & konfigurasi lanjutan.
- 🤝 **[CONTRIBUTING.md](CONTRIBUTING.md)** — Panduan kontribusi, alur kerja git, & standar kualitas kode.
- 🔒 **[SECURITY.md](SECURITY.md)** — Kebijakan pelaporan keamanan, analisis ancaman, & panduan tanggung jawab.

---

## ⚠️ Perhatian Legal

> **Verdamt-Snipe adalah framework pengujian keamanan berorientasi profesional.**  
> Gunakan alat ini **HANYA** pada sistem yang Anda miliki atau yang telah memberikan otorisasi tertulis resmi (Bug Bounty Program / Penetration Testing Agreement). Selalu patuhi batas cakupan (*scope*) dan regulasi hukum yang berlaku.

<p align="center"><i>"Silent · Precise · Relentless."</i> — <b>Samasta Baskara</b></p>
