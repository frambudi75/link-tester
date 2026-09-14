<?php
/**
 * LinkGuard v2.0 - URL Threat & Phishing Inspector
 * Professional Security Analyst Interface
 */
require_once __DIR__ . '/core/EnvLoader.php';
EnvLoader::load(__DIR__ . '/.env');
require_once __DIR__ . '/core/Database.php';

$appName = getenv('APP_NAME') ?: 'LinkGuard';
$isDbConnected = Database::isConnected();
?>
<!DOCTYPE html>
<html lang="id" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($appName) ?> - URL Threat & Phishing Inspector</title>
    <link rel="icon" type="image/svg+xml" href="assets/img/favicon.svg?v=<?= @filemtime(__DIR__ . '/assets/img/favicon.svg') ?: time() ?>">
    <link rel="apple-touch-icon" href="assets/img/favicon.svg">
    <meta name="description" content="Alat inspeksi teknis keamanan URL, deteksi heuristik phishing, SSL check, content analysis, DNS records, dan pelacakan redirect.">
    <link rel="stylesheet" href="assets/css/style.css?v=<?= @filemtime(__DIR__ . '/assets/css/style.css') ?: time() ?>">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
</head>
<body>

    <!-- Header Navigation -->
    <header class="app-header">
        <div class="container nav-row">
            <a href="./" class="brand">
                <div class="brand-icon">
                    <img src="assets/img/favicon.svg?v=<?= @filemtime(__DIR__ . '/assets/img/favicon.svg') ?: time() ?>" width="22" height="22" alt="Logo" style="display:block;">
                </div>
                <div class="brand-text">
                    <h1><?= htmlspecialchars($appName) ?> <span class="brand-badge">v2.0</span></h1>
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
                    <span>ENGINE: v2.0</span>
                </div>
                <button id="theme-toggle" class="theme-toggle" title="Toggle Light/Dark Mode">
                    <svg id="icon-sun" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="5"></circle>
                        <line x1="12" y1="1" x2="12" y2="3"></line>
                        <line x1="12" y1="21" x2="12" y2="23"></line>
                        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                        <line x1="1" y1="12" x2="3" y2="12"></line>
                        <line x1="21" y1="12" x2="23" y2="12"></line>
                        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
                    </svg>
                    <svg id="icon-moon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none;">
                        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                    </svg>
                </button>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <main class="container">
        <!-- Tab Navigation -->
        <nav class="tab-nav">
            <button class="tab-btn active" data-tab="scanner">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                Scanner
            </button>
            <button class="tab-btn" data-tab="bulk">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect></svg>
                Bulk Scan
            </button>
            <button class="tab-btn" data-tab="dashboard">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10"></path><path d="M12 20V4"></path><path d="M6 20v-6"></path></svg>
                Dashboard
            </button>
        </nav>

        <!-- TAB: Scanner -->
        <div id="tab-scanner" class="tab-content active">
            <!-- Page Intro -->
            <section class="page-intro">
                <h2>Inspeksi Keamanan Tautan & Deteksi Phishing</h2>
                <p>Analisis multi-lapis: heuristik URL, sertifikat SSL, konten halaman, DNS records, umur domain, dan verifikasi ancaman siber.</p>
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
                        <span id="progress-status">Memeriksa tautan dan menjalankan analisis multi-lapis...</span>
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

                <!-- Results Action Toolbar (View Modes + Exports) -->
                <div class="results-toolbar">
                    <div class="view-mode-selector">
                        <button type="button" class="btn-view-mode active" id="view-mode-standard" data-mode="standard">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect></svg>
                            Standard Inspector
                        </button>
                        <button type="button" class="btn-view-mode" id="view-mode-investigation" data-mode="investigation">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
                            Investigation Mode (Forensic Terminal)
                        </button>
                    </div>

                    <!-- Export Buttons -->
                    <div id="export-bar" class="export-bar">
                        <button id="btn-export-json" class="btn-export" title="Download laporan JSON">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                            Export JSON
                        </button>
                        <button id="btn-export-pdf" class="btn-export" title="Buka laporan cetak PDF">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                            Export PDF
                        </button>
                    </div>
                </div>

                <!-- Investigation Terminal View -->
                <div id="investigation-terminal-wrap" class="investigation-terminal-wrap" style="display:none;">
                    <div class="terminal-header">
                        <div class="terminal-dots">
                            <span class="dot dot-red"></span>
                            <span class="dot dot-yellow"></span>
                            <span class="dot dot-green"></span>
                        </div>
                        <span class="terminal-title"><?= strtoupper(htmlspecialchars($appName)) ?> // URL THREAT INTELLIGENCE &amp; FORENSIC INSPECTOR</span>
                        <button type="button" id="btn-copy-terminal" class="btn-copy-terminal" title="Salin Raw Report">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                            Salin Report
                        </button>
                    </div>
                    <pre id="investigation-terminal-content" class="investigation-terminal-content"></pre>
                </div>

                <!-- Standard View Container -->
                <div id="standard-view-container">

                <!-- URL Routing Details -->
                <div class="url-inspect">
                    <div class="inspect-line">
                        <span class="inspect-tag">URL ASLI</span>
                        <span id="res-original-url" class="inspect-val">-</span>
                    </div>
                    <div class="inspect-line">
                        <span class="inspect-tag">URL TUJUAN</span>
                        <span id="res-final-url" class="inspect-val" style="color:var(--color-link); font-weight:600;">-</span>
                    </div>
                </div>

                <!-- Visual Redirect Chain Flow (Hop Stepper) -->
                <div id="redirect-flow-panel" class="panel redirect-flow-panel" style="display:none;">
                    <div class="panel-title">
                        <span>Alur Pengalihan (Redirect Chain Flow Forensics)</span>
                        <span id="redirect-flow-badge" class="badge-pill">0 HOPS</span>
                    </div>
                    <div id="redirect-flow-stepper" class="redirect-flow-stepper"></div>
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

                    <!-- Panel 3: SSL/TLS (NEW v2.0) -->
                    <div class="panel">
                        <div class="panel-title">
                            <span>Sertifikat SSL/TLS</span>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                        </div>
                        <table class="data-table">
                            <tr>
                                <td class="label">Status SSL</td>
                                <td id="res-ssl-status" class="val">-</td>
                            </tr>
                            <tr>
                                <td class="label">Penerbit (Issuer)</td>
                                <td id="res-ssl-issuer" class="val">-</td>
                            </tr>
                            <tr>
                                <td class="label">Masa Berlaku</td>
                                <td id="res-ssl-expires" class="val">-</td>
                            </tr>
                        </table>
                    </div>

                    <!-- Panel 4: DNS Records (NEW v2.0) -->
                    <div class="panel">
                        <div class="panel-title">
                            <span>DNS Records</span>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                        </div>
                        <table class="data-table">
                            <tr>
                                <td class="label">SPF Record</td>
                                <td id="res-dns-spf" class="val">-</td>
                            </tr>
                            <tr>
                                <td class="label">DMARC Record</td>
                                <td id="res-dns-dmarc" class="val">-</td>
                            </tr>
                            <tr>
                                <td class="label">MX Record</td>
                                <td id="res-dns-mx" class="val">-</td>
                            </tr>
                        </table>
                    </div>
                </div>

                <!-- Content Analysis Panel (NEW v2.0) -->
                <div id="content-panel" class="panel content-analysis-panel" style="display:none;">
                    <div class="panel-title">
                        <span>Analisis Konten Halaman</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                    </div>
                    <div id="content-badges" class="content-badges"></div>
                </div>

                <!-- Screenshot Preview (NEW v2.0) -->
                <div id="screenshot-panel" class="panel" style="display:none;">
                    <div class="panel-title">
                        <span>Preview Halaman (Screenshot Aman)</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                    </div>
                    <div class="screenshot-container">
                        <div class="screenshot-fallback" style="padding:24px; text-align:center; color:var(--text-muted); font-size:12px;">Preview halaman aman</div>
                    </div>
                </div>

                <!-- Security Checks Matrix Table -->
                <div class="checks-panel">
                    <div class="panel-title">
                        <span>Hasil Pemeriksaan Aturan Keamanan (Checks Matrix)</span>
                    </div>
                    <div class="table-responsive">
                        <table class="checks-table">
                            <thead>
                                <tr>
                                    <th style="width: 12%;">Severity</th>
                                    <th style="width: 22%;">Aturan / Rule</th>
                                    <th style="width: 12%;">Kategori</th>
                                    <th style="width: 54%;">Deskripsi Temuan</th>
                                </tr>
                            </thead>
                            <tbody id="checks-tbody">
                                <tr>
                                    <td colspan="4" style="color: var(--text-muted);">Tidak ada data pemindaian.</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
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

                </div> <!-- End #standard-view-container -->
            </section>

            <!-- Scan History Section -->
            <section class="history-section">
                <div class="history-header">
                    <h3>Log Riwayat Pemindaian Terkini</h3>
                    <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">LIVE REPOSITORY</span>
                </div>
                <div class="table-responsive">
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
                </div>
            </section>
        </div>

        <!-- TAB: Bulk Scan -->
        <div id="tab-bulk" class="tab-content">
            <section class="page-intro">
                <h2>Bulk Scan — Pemindaian Multi-URL</h2>
                <p>Masukkan hingga 10 URL sekaligus (satu per baris) untuk dianalisis secara berurutan.</p>
            </section>

            <section class="search-panel">
                <form id="bulk-form">
                    <textarea id="bulk-urls" class="bulk-textarea" rows="8" placeholder="https://example1.com&#10;https://example2.com&#10;https://example3.com&#10;&#10;(Satu URL per baris, maksimal 10 URL)" spellcheck="false"></textarea>
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-top:12px; flex-wrap:wrap; gap:10px;">
                        <span id="bulk-count" style="font-family:var(--font-mono); font-size:12px; color:var(--text-muted);">0 / 10 URL</span>
                        <button type="submit" id="btn-bulk-submit" class="btn-submit">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect></svg>
                            Scan Semua
                        </button>
                    </div>
                </form>

                <!-- Bulk Progress -->
                <div id="bulk-progress" class="scan-progress">
                    <div class="progress-header">
                        <span id="bulk-progress-status">Memproses URL...</span>
                        <span>BATCH PROCESSING</span>
                    </div>
                    <div class="progress-line">
                        <div class="progress-fill"></div>
                    </div>
                </div>
            </section>

            <!-- Bulk Results -->
            <section id="bulk-results" class="history-section" style="display:none;">
                <div class="history-header">
                    <h3>Hasil Bulk Scan</h3>
                    <span id="bulk-summary" style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);"></span>
                </div>
                <div class="table-responsive">
                    <table class="history-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>URL</th>
                                <th>Domain</th>
                                <th>Verdict</th>
                                <th>Risk Score</th>
                                <th>Redirect</th>
                                <th>Waktu</th>
                            </tr>
                        </thead>
                        <tbody id="bulk-tbody"></tbody>
                    </table>
                </div>
            </section>
        </div>

        <!-- TAB: Dashboard -->
        <div id="tab-dashboard" class="tab-content">
            <section class="page-intro">
                <h2>Dashboard Statistik</h2>
                <p>Ringkasan data pemindaian, distribusi ancaman, tren harian, dan domain paling sering di-scan.</p>
            </section>

            <!-- Stats Cards -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-val" id="stat-total">-</div>
                    <div class="stat-label">Total Scan</div>
                </div>
                <div class="stat-card">
                    <div class="stat-val" id="stat-today">-</div>
                    <div class="stat-label">Scan Hari Ini</div>
                </div>
                <div class="stat-card">
                    <div class="stat-val" id="stat-avg">-</div>
                    <div class="stat-label">Rata-rata Risk Score</div>
                </div>
                <div class="stat-card">
                    <div class="stat-val" id="stat-detection">-</div>
                    <div class="stat-label">Detection Rate</div>
                </div>
            </div>

            <!-- Charts -->
            <div class="chart-grid">
                <div class="panel chart-panel">
                    <div class="panel-title"><span>Distribusi Verdict</span></div>
                    <div class="chart-container">
                        <canvas id="chart-verdict"></canvas>
                    </div>
                </div>
                <div class="panel chart-panel">
                    <div class="panel-title"><span>Tren Scan 7 Hari Terakhir</span></div>
                    <div class="chart-container">
                        <canvas id="chart-trend"></canvas>
                    </div>
                </div>
            </div>

            <!-- Top Domains -->
            <section class="history-section">
                <div class="history-header">
                    <h3>Top 10 Domain Paling Sering Di-Scan</h3>
                </div>
                <div class="table-responsive">
                    <table class="history-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Domain</th>
                                <th>Jumlah Scan</th>
                                <th>Verdict Terakhir</th>
                            </tr>
                        </thead>
                        <tbody id="top-domains-tbody">
                            <tr>
                                <td colspan="4" style="text-align:center; color:var(--text-muted); padding:14px;">Memuat data...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    </main>

    <!-- Footer -->
    <footer>
        <div class="container footer-content">
            <span><?= htmlspecialchars($appName) ?> v2.0 &bull; Modul Analisis Keamanan Tautan</span>
            <div class="footer-links">
                <a href="docs/prd.md">PRD</a>
                <a href="docs/architecture.md">Arsitektur</a>
                <a href="docs/rules.md">Matriks Aturan</a>
                <a href="docs/schema.md">Skema DB</a>
                <a href="docs/readme.md">Panduan</a>
            </div>
        </div>
    </footer>

    <script src="assets/js/app.js?v=<?= @filemtime(__DIR__ . '/assets/js/app.js') ?: time() ?>"></script>
</body>
</html>
