# Security policy

## Supported versions

Security fixes are applied to the latest version on the `main` branch.

## Reporting a vulnerability in Verdamt-Snipe

Do not open a public issue for a vulnerability in this repository. Use the
repository's **Security** tab to create a private vulnerability report, and
include:

- a clear description of the issue and its impact;
- reproducible, non-destructive steps or a minimal proof of concept;
- the affected commit, release, or installation method; and
- any proposed mitigation, if available.

Please do not use this process to report vulnerabilities discovered in a scan
target. Report those to the target owner or through the relevant bug-bounty
program instead.

We will acknowledge valid reports, investigate them privately, and coordinate
disclosure after a fix is available.

## Permukaan Serangan Alat (Attack Surface of the Tool Itself)

Sebagai kerangka kerja pengujian keamanan ofensif dan defensif, Verdamt-Snipe sendiri memiliki permukaan serangan yang harus dipahami dan dimitigasi oleh operator:

1. **Rantai Pasok Dependensi (Dependency Supply Chain)**:
   - Tool bergantung pada pustaka pihak ketiga seperti `httpx` (HTTP/2), `playwright` (Chromium driver), `curl_cffi` (impersonasi TLS), dan klien OOB (`interactsh`).
   - Risiko: Kerentanan pada pustaka upstream dapat disalahgunakan jika memproses payload berbahaya dari server target.
   - Mitigasi: Versi dependensi dikunci dan dianjurkan melakukan audit dependensi berkala (`pip audit`).
2. **Penanganan Kredensial (Credential Handling)**:
   - Penggunaan token bearer atau cookie otentikasi melalui argumen CLI langsung (`--bearer`, `--cookie`) berisiko terekspos pada tabel proses OS (`ps aux`) atau riwayat shell (`.bash_history`).
   - Mitigasi: Selalu gunakan opsi aman `--bearer-file <path>` atau variabel lingkungan dengan prefix `env:` (contoh: `--bearer env:API_TOKEN`).
3. **Konfigurasi Proxy & Rahasia (Proxy Configuration)**:
   - Menyertakan kredensial proxy pada flag `--proxy http://user:pass@host:port` dapat mengekspos kata sandi. Gunakan proxy lokal terotentikasi atau variabel lingkungan `HTTPS_PROXY`.
4. **Sensitivitas Log Audit (Audit Log Sensitivity)**:
   - Berkas audit log (`.jsonl`) mencatat detail lalu lintas HTTP lengkap, yang mungkin mencakup header `Authorization`, cookie sesi, atau respon berisi data pribadi (PII).
   - Mitigasi: Terapkan izin berkas ketat (`chmod 600`) dan simpan di penyimpanan terenkripsi.
5. **Eksekusi Biner Go (Go Binary Execution)**:
   - Modul eksternal memanggil biner pembantu (seperti `subfinder`, `nuclei`, `katana`) melalui `subprocess`.
   - Risiko: Pembajakan biner jika direktori `$PATH` atau `~/go/bin` tidak tepercaya.
   - Mitigasi: Validasi jalur mutlak biner dan pastikan biner diunduh dari rilis resmi ProjectDiscovery.
6. **Konteks & Cache Peramban (Browser Context)**:
   - Sesi Playwright headless dapat menyimpan status DOM, cookie, atau cache sesi di memori atau disk lokal.
   - Mitigasi: Isolasi konteks dijamin melalui `SharedBrowserPool` yang membersihkan state konteks setelah evaluasi selesai atau saat proses berhenti.

---

## Diagram Arsitektur Keamanan (Security Architecture Diagram)

Aliran kontrol keamanan internal Verdamt-Snipe memastikan bahwa setiap permintaan jaringan divalidasi, dibatasi, dan diaudit sebelum dikirim ke target:

```mermaid
flowchart TD
    UserInput["Input Pengguna (CLI / Config)"] --> ScopeValidation{"ScopeGuard<br/>(Validasi Host & IP Scope)"}
    
    ScopeValidation -- "Di Luar Scope" --> DropScope["Tolak & Hentikan (Scope Error)"]
    ScopeValidation -- "Dalam Scope / --allowed-hosts" --> PolicyCheck{"ScanPolicy<br/>(Budget Permintaan & Mode)"}
    
    PolicyCheck -- "--passive Aktif" --> PassiveMode["Batasi Hanya Analisis Pasif<br/>(Tanpa Injeksi Aktif)"]
    PolicyCheck -- "--dry-run Aktif" --> DryRunMode["Bypass Jaringan<br/>(Simulasi Logika / Print Only)"]
    PolicyCheck -- "Mode Aktif Normal" --> RateControl["RateLimiter<br/>(Token Bucket Throttling)"]
    
    RateControl --> ProxyRouting["ProxyManager<br/>(Rotasi / Tor / Upstream Proxy)"]
    ProxyRouting --> AuditLog["AuditLogger<br/>(Pencatatan Permintaan .jsonl)"]
    AuditLog --> NetworkEngine["Network Engine / TLS Transport"]
    NetworkEngine --> TargetSite["Target Server"]
```

---

## Model Ancaman (Threat Model)

Analisis ancaman, dampak, mekanisme mitigasi, dan status implementasi pada Verdamt-Snipe:

| Ancaman (Threat) | Dampak (Impact) | Mekanisme Mitigasi (Mitigation) | Status |
| :--- | :--- | :--- | :--- |
| **Scanning out-of-scope targets** | Pertanggungjawaban hukum (*legal liability*), pelanggaran aturan *bug bounty*. | `ScopeGuard` memvalidasi domain induk, sub-domain, CIDR, dan flag `--allowed-hosts`. | ✅ Mitigated |
| **Credential exposure via CLI args** | Pencurian token/kredensial melalui inspeksi proses OS (`ps aux`) atau history bash. | Dukungan pembacaan berkas `--bearer-file` dan referensi environment variable via prefix `env:`. | ✅ Mitigated |
| **Excessive traffic triggering IDS** | Gangguan ketersediaan target (DoS tak disengaja), pemblokiran IP penguji. | `RateLimiter` adaptif, mode senyap `--stealth`, dan pembatasan batas atas kuota `--max-requests`. | ✅ Mitigated |
| **Audit log data leakage** | Kebocoran token sesi atau data sensitif klien yang tersimpan di berkas log. | Pembatasan hak akses berkas (*file permissions*) dan panduan tanggung jawab pengguna untuk enkripsi log. | ⚠️ User-dependent |
| **Malicious Go binary in PATH** | Eksekusi kode arbitrer jika dependensi biner pihak ketiga dipalsukan di sistem lokal. | Verifikasi penemuan biner di jalur resmi dan tanggung jawab pengguna memasang biner rilis resmi. | ⚠️ User-dependent |
| **Dependency vulnerability** | Serangan rantai pasok (*supply chain attack*) melalui paket Python yang dieksploitasi. | Peninjauan dependensi secara berkala (`pip audit`) dan penguncian versi (*pinned versions*) di `requirements.txt`. | ✅ Mitigated |
| **Browser data persistence** | Penyimpanan kredensial atau cookie sesi target di cache peramban headless. | Pembersihan otomatis konteks peramban melalui siklus hidup `SharedBrowserPool` saat keluar. | ✅ Mitigated |
| **POST-body injection side effects** | Modifikasi data yang tidak diinginkan pada basis data target (*data corruption*). | POST-gate aktif secara default (`allow_post=False`); permintaan bermetode POST memerlukan konfirmasi eksplisit. | ✅ Mitigated |

---

## Panduan Penggunaan yang Bertanggung Jawab (Responsible Use Guidelines)

Framework ini memiliki kemampuan ofensif yang kuat. Setiap operator diwajibkan mematuhi panduan etis dan operasional berikut:

1. **Otorisasi Tertulis**: Selalu pastikan Anda memiliki izin tertulis (*Rules of Engagement* atau cakupan program Bug Bounty resmi) sebelum memindai target apa pun.
2. **Validasi Scope dengan `--dry-run`**: Selalu jalankan pemindaian pertama kali dengan flag `--dry-run` untuk memverifikasi domain, parameter, dan modul yang akan diuji tanpa mengirim paket jaringan berbahaya.
3. **Mulai dari Mode Pasif (`--passive`)**: Lakukan reconnaissance awal dengan flag `--passive` untuk memetakan infrastruktur dan teknologi tanpa menimbulkan beban lalu lintas aktif.
4. **Batasi Volume Lalu Lintas (`--max-requests`)**: Tetapkan batas aman permintaan dengan `--max-requests` serta sesuaikan tingkat kecepatan dengan `--rate-limit` agar tidak membebani server target atau memicu DoS.
5. **Amankan Berkas Log Audit**: Simpan berkas log `.jsonl` di direktori aman dengan restriksi perizinan (`chmod 600`) dan hapus atau redaksikan data sebelum membagikan laporan.
6. **Hapus Berkas State yang Mengandung Kredensial**: Hapus berkas checkpoint `.state` setelah pengujian selesai jika pengujian melibatkan token otentikasi atau cookie sesi sensitif.

