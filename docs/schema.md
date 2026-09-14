# Database Schema Documentation - LinkTester

Basis data LinkTester menggunakan **MySQL / MariaDB** dengan struktur yang efisien dan telah dilengkapi indeks untuk performa cepat pada jutaan baris data pemindaian.

---

## 1. Tabel: `scans`
Menyimpan riwayat utama setiap URL yang diperiksa.

| Kolom | Tipe Data | Keterangan |
| :--- | :--- | :--- |
| `id` | BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY | ID unik pemindaian |
| `url_hash` | CHAR(64) NOT NULL | SHA-256 hash dari URL input untuk lookup cache cepat |
| `original_url` | TEXT NOT NULL | URL asli yang dimasukkan pengguna |
| `final_url` | TEXT NOT NULL | URL tujuan akhir setelah mengikuti semua redirect |
| `domain` | VARCHAR(255) NOT NULL | Nama domain utama (misal: `example.com`) |
| `ip_address` | VARCHAR(45) DEFAULT NULL | Alamat IPv4 atau IPv6 server tujuan |
| `risk_score` | TINYINT UNSIGNED NOT NULL DEFAULT 0 | Nilai risiko (0 - 100) |
| `verdict` | ENUM('safe', 'suspicious', 'dangerous') NOT NULL | Kesimpulan status keamanan |
| `is_redirected` | TINYINT(1) DEFAULT 0 | 1 jika link mengalami pengalihan (shortener/cloaking) |
| `redirect_count`| INT DEFAULT 0 | Jumlah lompatan redirect |
| `domain_age_days`| INT DEFAULT NULL | Umur domain dalam hari (dari WHOIS/RDAP) |
| `created_at` | TIMESTAMP DEFAULT CURRENT_TIMESTAMP | Waktu pemindaian dilakukan |

**Indeks:**
- `INDEX idx_url_hash (url_hash)`
- `INDEX idx_domain (domain)`
- `INDEX idx_verdict (verdict)`
- `INDEX idx_created_at (created_at)`

---

## 2. Tabel: `scan_details`
Menyimpan detail temuan/indikator risiko per pemindaian.

| Kolom | Tipe Data | Keterangan |
| :--- | :--- | :--- |
| `id` | BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY | ID temuan |
| `scan_id` | BIGINT UNSIGNED NOT NULL | Relasi ke `scans.id` (ON DELETE CASCADE) |
| `category` | VARCHAR(50) NOT NULL | `heuristic`, `threat_intel`, `whois`, `network` |
| `rule_name` | VARCHAR(100) NOT NULL | Kode/nama aturan (misal: `ip_as_host`, `idn_homoglyph`) |
| `severity` | ENUM('info', 'low', 'medium', 'high', 'critical') | Tingkat keparahan |
| `score_impact` | INT NOT NULL DEFAULT 0 | Poin penambah risiko |
| `description` | TEXT NOT NULL | Penjelasan temuan dalam bahasa manusia |

---

## 3. Tabel: `domain_reputation`
Tabel cache agregasi reputasi domain agar menghemat pemanggilan API luar.

| Kolom | Tipe Data | Keterangan |
| :--- | :--- | :--- |
| `domain` | VARCHAR(255) PRIMARY KEY | Nama domain (misal: `google.com`) |
| `is_whitelisted` | TINYINT(1) DEFAULT 0 | 1 jika masuk daftar putih domain tepercaya |
| `is_blacklisted` | TINYINT(1) DEFAULT 0 | 1 jika masuk daftar hitam domain phishing |
| `registrar` | VARCHAR(255) DEFAULT NULL | Nama registrar domain |
| `registered_date` | DATE DEFAULT NULL | Tanggal pembuatan domain |
| `last_checked` | TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | Waktu sinkronisasi terakhir |
| `notes` | VARCHAR(255) DEFAULT NULL | Catatan manual tim analis |
