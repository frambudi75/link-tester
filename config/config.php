<?php
/**
 * Application Settings & Configuration - LinkTester
 */

return [
    'app' => [
        'name'        => 'LinkTester - Phishing & Malicious Link Detector',
        'version'     => '1.0.0',
        'base_url'    => getenv('APP_URL') ?: '',
        'timezone'    => 'Asia/Jakarta',
        'cache_hours' => 6, // Cache hasil scan selama 6 jam untuk link yang sama
    ],

    // Threat Intelligence API Keys (Opsional - Graceful Degradation jika kosong)
    'threat_intel' => [
        'google_safe_browsing_api_key' => getenv('GSB_API_KEY') ?: '',
        'virustotal_api_key'           => getenv('VIRUSTOTAL_API_KEY') ?: '',
        'urlhaus_enabled'              => true, // Tidak memerlukan API key
    ],

    // Scanner Thresholds
    'thresholds' => [
        'safe_max'       => 25,
        'suspicious_max' => 60,
        'dangerous_min'  => 61,
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
