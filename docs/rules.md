# Heuristic & Scoring Rules - LinkTester

Dokumen ini memaparkan aturan (*rules*) deteksi heuristik, bobot nilai penalti risiko (*Risk Penalty*), dan ambang batas kesimpulan (*Verdict Thresholds*).

---

## 1. Ambang Batas Kesimpulan (Verdict Thresholds)

Total **Risk Score** berkisar dari **0 sampai 100**:

| Rentang Skor | Status / Verdict | Warna UI | Keterangan |
| :---: | :---: | :---: | :--- |
| **0 – 25** | **SAFE (Aman)** | Hijau (`#10b981`) | Link normal, domain mapan, tidak ditemukan indikator berbahaya. |
| **26 – 60** | **SUSPICIOUS (Waspada)** | Kuning (`#f59e0b`) | Terdapat beberapa anomali (misal: domain baru terbit, TLD tidak umum, atau redirection chain). Disarankan tidak memasukkan password/data pribadi. |
| **61 – 100** | **DANGEROUS (Bahaya)** | Merah (`#ef4444`) | Terdeteksi kuat sebagai situs phishing, penyebar malware/APK, tercatat di blacklist global, atau impersonasi brand resmi. |

---

## 2. Aturan & Bobot Heuristik (Local Heuristic Engine)

| Kode Rule | Kriteria Deteksi | Bobot Skor | Severity |
| :--- | :--- | :---: | :---: |
| `IP_AS_HOST` | Hostname adalah alamat IP mentah (misal: `http://45.12.33.1/login`) | **+40** | High |
| `IDN_HOMOGLYPH` | Domain menggunakan karakter Punycode (`xn--`) atau aksara campuran non-latin | **+35** | High |
| `SUBDOMAIN_DECEPTION` | Subdomain meniru nama domain populer (misal: `paypal.com.account-update.xyz`) | **+40** | High |
| `SUSPICIOUS_TLD` | Menggunakan TLD yang sering diasosiasikan dengan scam (`.xyz`, `.top`, `.tk`, `.icu`, `.work`, `.click`, `.buzz`, dll) | **+20** | Medium |
| `PHISH_KEYWORDS` | URL mengandung kata kunci sensitif (`login`, `verify`, `account`, `bca`, `mandiri`, `banking`, `apk`, `hadiah`, `klaim`, `wallet`) pada domain yang tidak resmi | **+25** | Medium |
| `EXCESSIVE_DASHES` | Terdapat lebih dari 3 tanda hubung `-` pada nama domain | **+15** | Low |
| `AT_SYMBOL_URL` | Terdapat karakter `@` di dalam URL (teknik penipuan URL browser lama) | **+30** | Medium |
| `NON_STANDARD_PORT` | Port web selain 80, 443, 8080, atau 8443 (misal: `:8888`, `:65432`) | **+20** | Low |
| `HTTP_NO_SSL` | Halaman login / pembayaran menggunakan `http://` tanpa enkripsi SSL | **+15** | Low |
| `SUSPICIOUS_FILE_EXT`| URL mengarah langsung ke file eksekusi / APK (`.apk`, `.exe`, `.bat`, `.scr`, `.vbs`, `.iso`) | **+50** | Critical |
| `CROSS_DOMAIN_REDIRECT` | Pengalihan diam-diam ke domain berbeda (Teknik Cloaking / Malvertising) | **+35** | High |
| `EXCESSIVE_REDIRECTS` | Rantai lompatan URL berturut-turut ($\ge 2$ kali) | **+25** | Medium |

---

## 3. Aturan Domain Intelligence & WHOIS

| Kode Rule | Kriteria Deteksi | Bobot Skor | Severity |
| :--- | :--- | :---: | :---: |
| `DOMAIN_VERY_NEW` | Domain terdaftar kurang dari 14 hari | **+35** | High |
| `DOMAIN_NEW` | Domain terdaftar antara 15 sampai 30 hari | **+20** | Medium |
| `DOMAIN_ESTABLISHED`| Domain telah aktif lebih dari 365 hari (1 tahun) | **-15** (Diskon risiko) | Info |

---

## 4. Aturan Threat Intelligence API

| Kode Rule | Kriteria Deteksi | Bobot Skor | Severity |
| :--- | :--- | :---: | :---: |
| `GOOGLE_SAFE_BROWSING_HIT` | Terdaftar positif di Google Safe Browsing (Malware / Social Engineering) | **+80** (Otomatis Dangerous) | Critical |
| `VIRUSTOTAL_MALICIOUS` | Dinyatakan berbahaya oleh $\ge 3$ engine antivirus di VirusTotal | **+80** (Otomatis Dangerous) | Critical |
| `URLHAUS_MALICIOUS` | Terdaftar dalam blacklist aktif URLhaus | **+80** (Otomatis Dangerous) | Critical |
| `LOCAL_BLACKLIST_HIT` | Terdaftar dalam blacklist database internal | **+100** | Critical |
| `LOCAL_WHITELIST_HIT` | Terdaftar dalam whitelist resmi (Google, Microsoft, Domain Pemerintahan `.go.id`, Bank Resmi) | **Skor diturunkan ke 0** | Safe |
