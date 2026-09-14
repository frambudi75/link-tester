<?php
/**
 * LinkTester - URL Threat & Phishing Inspector
 * Professional Security Analyst Interface
 */
require_once __DIR__ . '/core/Database.php';
$isDbConnected = Database::isConnected();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinkTester - URL Threat & Phishing Inspector</title>
    <meta name="description" content="Alat inspeksi teknis keamanan URL, deteksi heuristik phishing, umur domain, dan pelacakan redirect.">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>

    <!-- Header Navigation -->
    <header class="app-header">
        <div class="container nav-row">
            <a href="index.php" class="brand">
                <div class="brand-icon">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    </svg>
                </div>
                <div class="brand-text">
                    <h1>LinkTester <span class="brand-badge">v1.0</span></h1>
                </div>
            </a>

            <div class="nav-meta">
                <?php if ($isDbConnected): ?>
                    <div class="badge-status">
                        <span class="status-dot"></span>
                        <span>DB: CONNECTED</span>
                    </div>
                <?php else: ?>
                    <div class="badge-status">
                        <span class="status-dot offline"></span>
                        <span>DB: STANDALONE MODE</span>
                    </div>
                <?php endif; ?>
                <div class="badge-status">
                    <span>ENGINE: ACTIVE</span>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <main class="container">
        <!-- Page Intro -->
        <section class="page-intro">
            <h2>Inspeksi Keamanan Tautan & Deteksi Phishing</h2>
            <p>Analisis struktur URL, anomali domain, pelacakan redirect hop, umur registrasi, dan verifikasi ancaman siber.</p>
        </section>

        <!-- Search Box -->
        <section class="search-panel">
            <form id="scan-form" class="search-form">
                <div class="input-container">
                    <span class="url-prefix">TARGET:</span>
                    <input type="text" id="url-input" class="url-input" placeholder="Masukkan URL lengkap (misal: https://example.com/login atau link pendek)" required autocomplete="off" spellcheck="false">
                </div>
                <button type="submit" id="btn-submit" class="btn-submit">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="11" cy="11" r="8"></circle>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                    </svg>
                    Mulai Analisis
                </button>
            </form>

            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px;">
                <!-- Quick Samples -->
                <div class="samples-bar">
                    <span>Contoh Uji Coba:</span>
                    <span class="sample-tag" data-url="https://google.com">google.com (Clean)</span>
                    <span class="sample-tag" data-url="http://videy.tv/d/70Eocpiw">videy.tv (TDS Cloaking)</span>
                    <span class="sample-tag" data-url="http://bca.co.id.login-auth.xyz/update">bca.co.id.login-auth.xyz (Spoofing)</span>
                    <span class="sample-tag" data-url="http://192.168.1.1/undangan.apk">IP + APK (Malware)</span>
                    <span class="sample-tag" data-url="http://xn--gogle-pqa.com">Punycode (Homograph)</span>
                </div>

                <label style="display:inline-flex; align-items:center; gap:6px; font-size:12px; font-family:var(--font-mono); color:var(--text-muted); cursor:pointer; user-select:none;">
                    <input type="checkbox" id="fresh-scan" style="cursor:pointer; accent-color:var(--color-blue);">
                    <span>Bypass Cache</span>
                </label>
            </div>

            <!-- Progress Bar -->
            <div id="scan-progress" class="scan-progress">
                <div class="progress-header">
                    <span id="progress-status">Memeriksa tautan dan menjalankan analisis heuristik...</span>
                    <span>PROCESSING</span>
                </div>
                <div class="progress-line">
                    <div class="progress-fill"></div>
                </div>
            </div>
        </section>

        <!-- Results Area -->
        <section id="results-area" class="results-area">
            <!-- Verdict Banner -->
            <div id="verdict-banner" class="verdict-banner verdict-safe">
                <div class="score-display">
                    <div id="score-val" class="score-num">0</div>
                    <div class="score-label">Risk Score / 100</div>
                </div>
                <div class="verdict-text">
                    <h3>
                        <span id="verdict-title">Status: Aman</span>
                        <span id="verdict-pill" class="badge-pill pill-safe">SAFE</span>
                    </h3>
                    <p id="verdict-desc">Tautan ini tidak menunjukkan indikasi ancaman siber yang diketahui.</p>
                </div>
            </div>

            <!-- URL Routing Details -->
            <div class="url-inspect">
                <div class="inspect-line">
                    <span class="inspect-tag">URL ASLI</span>
                    <span id="res-original-url" class="inspect-val">-</span>
                </div>
                <div id="redirect-chain-wrap" style="display:none; flex-direction:column; gap:4px; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.03);">
                    <span class="inspect-tag" style="width:auto; color:var(--color-warning);">RANTAI PENGALIHAN (REDIRECT CHAIN):</span>
                    <div id="res-chain-list" style="display:flex; flex-direction:column; gap:4px; margin-left:12px; font-family:var(--font-mono); font-size:12px; color:var(--text-secondary);"></div>
                </div>
                <div class="inspect-line">
                    <span class="inspect-tag">URL TUJUAN</span>
                    <span id="res-final-url" class="inspect-val" style="color:#38bdf8; font-weight:600;">-</span>
                </div>
            </div>

            <!-- Technical Breakdown Panels -->
            <div class="tech-grid">
                <!-- Panel 1: Domain & Host -->
                <div class="panel">
                    <div class="panel-title">
                        <span>Domain & Identitas Host</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
                    </div>
                    <table class="data-table">
                        <tr>
                            <td class="label">Apex Domain</td>
                            <td id="res-domain" class="val">-</td>
                        </tr>
                        <tr>
                            <td class="label">Subdomain</td>
                            <td id="res-subdomain" class="val">-</td>
                        </tr>
                        <tr>
                            <td class="label">Alamat IP Host</td>
                            <td id="res-ip" class="val">-</td>
                        </tr>
                    </table>
                </div>

                <!-- Panel 2: Network & Lifecycle -->
                <div class="panel">
                    <div class="panel-title">
                        <span>Siklus & Jaringan</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                    </div>
                    <table class="data-table">
                        <tr>
                            <td class="label">Umur Domain</td>
                            <td id="res-age" class="val">-</td>
                        </tr>
                        <tr>
                            <td class="label">Pengalihan (Redirect)</td>
                            <td id="res-redirect" class="val">-</td>
                        </tr>
                        <tr>
                            <td class="label">Waktu Eksekusi</td>
                            <td id="res-exec-time" class="val">-</td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Security Checks Matrix Table -->
            <div class="checks-panel">
                <div class="panel-title">
                    <span>Hasil Pemeriksaan Aturan Keamanan (Checks Matrix)</span>
                </div>
                <table class="checks-table">
                    <thead>
                        <tr>
                            <th style="width: 15%;">Severity</th>
                            <th style="width: 25%;">Aturan / Rule</th>
                            <th style="width: 15%;">Kategori</th>
                            <th style="width: 45%;">Deskripsi Temuan</th>
                        </tr>
                    </thead>
                    <tbody id="checks-tbody">
                        <tr>
                            <td colspan="4" style="color: var(--text-muted);">Tidak ada data pemindaian.</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Action Advice Panel -->
            <div class="advice-panel">
                <div class="panel-title">
                    <span>Panduan Tindakan Pengguna</span>
                </div>
                <ul id="advice-list" class="advice-list">
                    <li>Tidak ada tindakan khusus yang diperlukan.</li>
                </ul>
            </div>
        </section>

        <!-- Scan History Section -->
        <section class="history-section">
            <div class="history-header">
                <h3>Log Riwayat Pemindaian Terkini</h3>
                <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">LIVE REPOSITORY</span>
            </div>
            <table class="history-table">
                <thead>
                    <tr>
                        <th>Domain Target</th>
                        <th>Verdict</th>
                        <th>Risk Score</th>
                        <th>Redirect</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody id="history-tbody">
                    <tr>
                        <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 14px;">Memuat riwayat pemindaian...</td>
                    </tr>
                </tbody>
            </table>
        </section>
    </main>

    <!-- Footer -->
    <footer>
        <div class="container" style="display: flex; justify-content: space-between; width: 100%;">
            <span>LinkTester v1.0 &bull; Modul Analisis Keamanan Tautan</span>
            <span style="display: flex; gap: 14px;">
                <a href="docs/prd.md">PRD</a>
                <a href="docs/architecture.md">Arsitektur</a>
                <a href="docs/rules.md">Matriks Aturan</a>
                <a href="docs/schema.md">Skema DB</a>
                <a href="docs/readme.md">Panduan</a>
            </span>
        </div>
    </footer>

    <script src="assets/js/app.js"></script>
</body>
</html>
