# LinkTester - Phishing & Malicious Link Detection System

Sistem inspeksi dan pendeteksi dini link phishing, malware, dan URL berbahaya berbasis multi-lapis (*Heuristic Analysis, Threat Intelligence, Domain Age, & Redirect Tracking*).

Dirancang khusus agar **100% portabel** dan dapat berjalan tanpa konfigurasi rumit di:
1. **XAMPP** (Localhost Windows/macOS/Linux)
2. **aaPanel / Docker Container** (Dev Server)
3. **cPanel** (Shared Hosting / VPS)

---

## ⚡ Fitur Utama
- **Heuristic Rule Engine**: Deteksi alamat IP mentah, teknik *subdomain deception*, karakter homograph/punycode, TLD mencurigakan, dan kata kunci phish sensitif.
- **Deteksi Ekstensi Berbahaya**: Menandai link yang berujung pada file berbahaya seperti `.apk` (modus penipuan surat/undangan nikah), `.exe`, `.bat`, dll.
- **Unshortener & Redirect Tracing**: Melacak rantai pengalihan URL pendek (Bit.ly, TinyURL, s.id) hingga menemukan tautan asli dengan aman.
- **Anti-SSRF Protection**: Mencegah request berbahaya ke jaringan internal / localhost server.
- **Domain Age & WHOIS**: Memeriksa tanggal lahir domain untuk mendeteksi situs phishing yang baru berumur beberapa hari.
- **Multi Threat Intelligence**: Mendukung Google Safe Browsing, VirusTotal, dan URLhaus (tetap berfungsi akurat secara offline/heuristik jika API key belum diisi).
- **Modern Cyber Dashboard**: Tampilan visual bertema cybersecurity dengan indikator *Risk Score* (0–100%) dan animasi tahapan scanning.

---

## 🚀 Panduan Instalasi

### A. Menjalankan di XAMPP (Windows)
1. Letakkan folder proyek di `C:\xampp\htdocs\link-tester`.
2. Buka **XAMPP Control Panel** dan nyalakan **Apache** & **MySQL**.
3. Buka browser ke `http://localhost/phpmyadmin`:
   - Buat database baru bernama `link_tester`.
   - Pilih tab **Import**, pilih file `database.sql` yang ada di root proyek ini, lalu klik **Import**.
4. Buka file `config/database.php` dan pastikan konfigurasinya sesuai (secara default sudah tersetting untuk user `root` tanpa password):
   ```php
   define('DB_HOST', 'localhost');
   define('DB_NAME', 'link_tester');
   define('DB_USER', 'root');
   define('DB_PASS', '');
   ```
5. Akses aplikasi melalui browser:
   ```
   http://localhost/link-tester
   ```

---

### B. Menjalankan di aaPanel / Docker
1. Masuk ke direktori proyek di terminal server Anda:
   ```bash
   cd /www/wwwroot/link-tester
   ```
2. Jalankan docker-compose:
   ```bash
   docker-compose up -d --build
   ```
3. Aplikasi akan berjalan di `http://ip-server:8080` lengkap dengan container MySQL bawaan yang otomatis mengimpor `database.sql`.

---

### C. Menjalankan di cPanel (Shared Hosting)
1. Compress seluruh isi folder `link-tester` menjadi file `.zip`.
2. Login ke cPanel, buka **File Manager**, dan ekstrak ke `public_html` (atau folder subdomain Anda).
3. Buat database & user baru via **MySQL® Databases** di cPanel, lalu hubungkan user ke database dengan hak akses *ALL PRIVILEGES*.
4. Buka **phpMyAdmin** di cPanel, pilih database yang baru dibuat, lalu import file `database.sql`.
5. Edit file `config/database.php` menggunakan File Manager cPanel, masukkan nama database, user, dan password yang tadi dibuat.
6. Aplikasi langsung aktif dan siap digunakan!

---

## ⚙️ Konfigurasi API Keys (Opsional)
Untuk mengaktifkan hasil pemeriksaan reputasi eksternal yang lebih dalam, edit file `config/config.php`:
```php
'threat_intel' => [
    'google_safe_browsing_api_key' => 'MASUKKAN_GOOGLE_API_KEY_DI_SINI',
    'virustotal_api_key'           => 'MASUKKAN_VIRUSTOTAL_API_KEY_DI_SINI',
    'urlhaus_enabled'              => true, // Tidak memerlukan API key
]
```
*Catatan: Sistem tetap berjalan optimal dan mendeteksi phishing secara akurat menggunakan Heuristic Engine jika API key belum diisi.*

---

## 📖 Dokumentasi Lengkap
- [Product Requirements Document (PRD)](file:///c:/xampp/htdocs/link-tester/docs/prd.md)
- [Arsitektur Teknis](file:///c:/xampp/htdocs/link-tester/docs/architecture.md)
- [Skema Database](file:///c:/xampp/htdocs/link-tester/docs/schema.md)
- [Aturan & Bobot Heuristik](file:///c:/xampp/htdocs/link-tester/docs/rules.md)
- [Catatan Versi (Changelog)](file:///c:/xampp/htdocs/link-tester/docs/changelog.md)
