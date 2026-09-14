# Architecture & Deployment Guide - LinkTester

Dokumen ini menjelaskan arsitektur teknis, alur data pemindaian (*scan pipeline*), strategi keamanan, serta panduan deployment lintas lingkungan: **XAMPP**, **aaPanel / Docker**, dan **cPanel**.

---

## 1. Desain Arsitektur Sistem

LinkTester dirancang menggunakan pola **Modular Layered Architecture** dengan bahasa PHP murni berorientasi objek (Pure PHP 8.x OOP) dan PDO MySQL.

```
[ Browser / Frontend Client ]
        │
        │ AJAX / REST Request (URL)
        ▼
   [ api/scan.php ]
        │
        ├─► [ Database Cache Check ] ── (Hit) ──► Kembalikan Cached Result
        │
        ▼ (Miss)
   [ core/UrlParser.php ] ──────────────► Normalisasi, Unshorten (Redirect Chain), Anti-SSRF
        │
        ├─► [ core/HeuristicEngine.php ] ──► Analisis Pola URL, Keyword, TLD, Punycode
        ├─► [ core/WhoisLookup.php ] ──────► Cek Registrasi & Umur Domain (RDAP/WHOIS)
        └─► [ core/ThreatIntel.php ] ──────► External APIs (Google Safe Browsing, VT, URLhaus)
        │
        ▼
   [ core/ScoreEngine.php ] ────────────► Pembobotan Risiko, Risk Score (0-100), Mitigasi
        │
        ├─► [ Database Save ] ──────────► Simpan ke tabel `scans` & `scan_details`
        │
        ▼
   [ JSON Response ] ──────────────────► Render di UI Dashboard
```

---

## 2. Pencegahan SSRF (Server-Side Request Forgery)
Karena server melakukan permintaan HTTP keluar untuk menelusuri redirect URL dan query API, `UrlParser.php` mengimplementasikan validasi IP:
- Memeriksa alamat IP tujuan sebelum cURL dieksekusi.
- Memblokir rentang IP private dan loopback (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`).
- Mencegah penyerang menggunakan scanner ini untuk memindai port jaringan internal server/localhost.

---

## 3. Strategi Portabilitas & Deployment

### 3.1 Lingkungan 1: XAMPP (Localhost Windows/Linux)
- **Web Server**: Apache bawaan XAMPP.
- **Database**: MySQL/MariaDB (`localhost`, port 3306, user `root`, password `""`).
- **Path**: `c:\xampp\htdocs\link-tester` diakses melalui `http://localhost/link-tester`.
- **Ekstensi PHP**: Pastikan ekstensi `curl`, `pdo_mysql`, `openssl`, `mbstring` aktif di `php.ini`.

### 3.2 Lingkungan 2: aaPanel & Docker (Dev / Staging VPS)
- Menggunakan `docker-compose.yml` untuk memutar container PHP 8.2 Apache + MySQL 8.0 dalam 1 perintah:
  ```bash
  docker-compose up -d --build
  ```
- Port default: `http://ip-server:8080`.
- Konfigurasi database otomatis membaca variabel lingkungan (*Environment Variables*).

### 3.3 Lingkungan 3: cPanel (Shared Hosting / Managed VPS)
- **Upload**: Upload seluruh file ke folder `public_html` atau subdomain (misal `public_html/link-tester`).
- **Database**:
  1. Buat database & user baru via cPanel MySQL Database Wizard.
  2. Import file `database.sql` melalui phpMyAdmin cPanel.
  3. Sesuaikan user, database, dan password pada `config/database.php`.
- **PHP Version**: Pastikan versi PHP di *Select PHP Version* cPanel minimal **PHP 7.4** atau direkomendasikan **PHP 8.1 - 8.3**.
- Tidak memerlukan akses root terminal (*SSH root*), cron daemon, atau node.js background process.
