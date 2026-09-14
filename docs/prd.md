# Product Requirements Document (PRD) - LinkTester

## 1. Overview & Problem Statement
Serangan siber berbasis rekayasa sosial (*social engineering*) seperti link phishing, pencurian kredensial, typo-squatting, penyebaran malware/APK undangan palsu, dan deceptive redirect semakin marak. Banyak pengguna awam maupun analis keamanan pemula membutuhkan sarana cepat untuk menguji keabsahan dan tingkat risiko suatu link tanpa harus membuka link tersebut secara langsung di browser mereka.

**LinkTester** adalah aplikasi web investigasi dan deteksi dini link phishing/berbahaya yang menganalisis URL melalui pendekatan multi-lapis (*Heuristic Analysis*, *Domain Intelligence*, *Redirect Tracing*, dan *Threat Intel Integration*).

---

## 2. Tujuan Proyek (Goals)
1. **Pencegahan Risiko Dini**: Memberikan analisis keamanan instan terhadap URL yang dicurigai sebelum diklik oleh pengguna.
2. **Multi-Platform Portability**: Berjalan mulus di berbagai lingkungan hosting:
   - **Lokal**: XAMPP / WampServer (Windows / Linux)
   - **Development / Staging**: aaPanel + Docker Container
   - **Production**: cPanel (Shared Hosting / Cloud VPS standar LAMP)
3. **Graceful Degradation**: Sistem tetap mampu mendeteksi pola ancaman secara akurat melalui *Heuristic Engine* dan analisis domain lokal meskipun API pihak ketiga (Google Safe Browsing / VirusTotal) tidak dikonfigurasi.
4. **User Experience Edukatif**: Hasil pemindaian menampilkan indikator visual *Risk Score* (0–100%) dan ringkasan penjelasan bahasa manusia mengapa link tersebut dianggap aman, mencurigakan, atau berbahaya.

---

## 3. Sasaran Pengguna (Target Audience)
- Pengguna umum yang menerima tautan mencurigakan via WhatsApp, SMS, Telegram, atau Email.
- Tim IT Helpdesk & Keamanan Informasi internal kantor/organisasi.
- Webmaster dan developer yang ingin memvalidasi link eksternal yang diunggah pengguna.

---

## 4. Fitur Utama (Core Features)

### 4.1 URL Parsing & Unshortening
- Normalisasi URL (protokol, domain, path, query strings).
- Ekstraksi nama domain, subdomain, dan Top-Level Domain (TLD).
- Deteksi IDN / Punycode / Homograph Attack (mengganti huruf alfabet dengan karakter aksara asing serupa).
- **HTTP Redirect Follower**: Melacak rantai pengalihan URL pendek (misal Bit.ly, TinyURL, s.id) hingga menemukan URL akhir (*final destination*).

### 4.2 Heuristic Risk Engine
- **IP as Hostname**: Deteksi penggunaan IP langsung (misal: `http://192.168.1.1/...`).
- **Subdomain Deception**: Meniru brand resmi di subdomain (misal: `bca.co.id.login-auth.xyz`).
- **Keyword Phishing**: Mendeteksi kombinasi kata kunci sensitif (`login`, `secure`, `verify`, `account`, `banking`, `apk`, `wallet`, `hadiah`).
- **Suspicious TLDs**: Menandai ekstensi domain berisiko tinggi (`.xyz`, `.top`, `.tk`, `.icu`, `.work`, dll).
- **Karakter Mencurigakan**: Simbol `@`, tanda dash `-` berlebihan (>3), atau port non-standar.

### 4.3 Domain Intelligence & WHOIS
- Pemeriksaan umur domain (*Domain Age*): Menandai domain baru terbit (< 14 - 30 hari).
- Informasi Registrar dan ketersediaan HTTPS / SSL.

### 4.4 Threat Intelligence API Integration
- **Google Safe Browsing API v4**: Deteksi malware, phishing, dan unwanted software.
- **VirusTotal API**: Agregasi hasil deteksi dari puluhan vendor antivirus.
- **URLhaus Database**: Deteksi tautan penyebar malware aktif.

### 4.5 Caching & Database History
- Caching hasil pemindaian di MySQL untuk menghemat kuota API dan memberikan respons instan pada link yang sama.
- Riwayat scan publik/terbaru untuk transparansi dan tren ancaman.

---

## 5. Non-Functional Requirements
- **Response Time**: < 1.5 detik untuk scan lokal/cached; < 3.5 detik untuk scan lengkap dengan external API.
- **Portabilitas**: Menggunakan PHP murni (PHP 7.4 - 8.3+) tanpa ketergantungan framework berat atau daemon sistem operasi yang terikat.
- **Keamanan Aplikasi**: Bebas dari celah SSRF (Server-Side Request Forgery) dengan memblokir IP internal/private range (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`).
