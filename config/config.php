<?php
/**
 * Application Settings & Configuration - LinkTester v2.0
 */

require_once __DIR__ . '/../core/EnvLoader.php';
EnvLoader::load(__DIR__ . '/../.env');

return [
    'app' => [
        'name'        => (getenv('APP_NAME') ?: 'LinkGuard') . ' - Phishing & Malicious Link Detector',
        'version'     => '2.0.0',
        'base_url'    => getenv('APP_URL') ?: '',
        'timezone'    => 'Asia/Jakarta',
        'cache_hours' => 6, // Cache hasil scan selama 6 jam untuk link yang sama
    ],

    // Threat Intelligence API Keys (Opsional - Graceful Degradation jika kosong)
    'threat_intel' => [
        'google_safe_browsing_api_key' => getenv('GSB_API_KEY') ?: '',
        'virustotal_api_key'           => getenv('VIRUSTOTAL_API_KEY') ?: '',
        'phishtank_api_key'            => getenv('PHISHTANK_API_KEY') ?: '',
        'urlhaus_enabled'              => true, // Tidak memerlukan API key
        'phishtank_enabled'            => true, // Bisa tanpa API key (rate limited)
    ],

    // Scanner Thresholds
    'thresholds' => [
        'safe_max'       => 25,
        'suspicious_max' => 60,
        'dangerous_min'  => 61,
    ],

    // Rate Limiting
    'rate_limit' => [
        'enabled'      => true,
        'max_requests' => 20,   // Maks request per IP
        'window_sec'   => 60,   // Dalam window (detik)
    ],

    // Content Analysis
    'content_analysis' => [
        'enabled'           => true,
        'detect_login_form' => true,
        'detect_iframe'     => true,
        'detect_miner'      => true,
        'detect_obfuscation'=> true,
        'detect_download'   => true,
    ],

    // SSL Check
    'ssl_check' => [
        'enabled' => true,
    ],

    // DNS Analysis
    'dns_analysis' => [
        'enabled' => true,
    ],

    // Audit Logging
    'audit_log' => [
        'enabled' => true,
    ],

    // Screenshot Preview (thum.io - gratis)
    'screenshot' => [
        'enabled'  => true,
        'provider' => 'thum.io', // API screenshot gratis
        'base_url' => 'https://image.thum.io/get/',
    ],

    // Bulk Scan
    'bulk_scan' => [
        'max_urls' => 10, // Maksimal URL per batch
    ],

    // Daftar TLD berisiko tinggi yang sering dipakai phisher
    'suspicious_tlds' => [
        'xyz', 'top', 'tk', 'icu', 'work', 'click', 'buzz', 'gq', 'ml', 'cf', 
        'ga', 'rest', 'fit', 'monster', 'beauty', 'hair', 'skin', 'quest', 'lat'
    ],

    // Kata kunci phishing sensitif
    'phishing_keywords' => [
        'login', 'signin', 'verify', 'verification', 'secure', 'account', 'banking',
        'wallet', 'update', 'confirm', 'bca', 'mandiri', 'bri', 'bni', 'cimb',
        'undangan', 'paket', 'hadiah', 'klaim', 'prakerja', 'dana', 'gopay', 'ovo',
        'shopeepay', 'paypal', 'appleid', 'microsoft', 'support', 'billing'
    ],

    // Ekstensi file berbahaya yang sering didownload otomatis
    'dangerous_extensions' => [
        'apk', 'exe', 'bat', 'scr', 'vbs', 'msi', 'jar', 'cmd', 'ps1', 'iso', 'bin'
    ],
];
