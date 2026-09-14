<?php
/**
 * Content Analyzer - LinkTester v2.0
 * Inspeksi konten HTML halaman target untuk mendeteksi elemen berbahaya:
 * form login palsu, iframe tersembunyi, crypto miner, obfuscated JS, auto-download.
 */

class ContentAnalyzer
{
    /**
     * Analisis body HTML halaman
     * @param string $htmlBody Body HTML (dibatasi 32KB dari traceRedirects)
     * @param string $url URL yang sedang dianalisis
     */
    public static function analyze(string $htmlBody, string $url = ''): array
    {
        $findings = [];
        $penalty = 0;

        if (empty(trim($htmlBody))) {
            return ['findings' => $findings, 'penalty' => 0, 'details' => []];
        }

        $details = [
            'has_login_form'     => false,
            'has_password_field' => false,
            'has_hidden_iframe'  => false,
            'has_crypto_miner'   => false,
            'has_obfuscated_js'  => false,
            'has_auto_download'  => false,
            'external_form_action' => null,
            'suspicious_scripts' => [],
        ];

        $bodyLower = strtolower($htmlBody);

        // 1. Deteksi Form Login Palsu
        $formResult = self::detectLoginForm($htmlBody, $bodyLower, $url);
        if ($formResult['detected']) {
            $details['has_login_form'] = true;
            $details['has_password_field'] = $formResult['has_password'];
            $details['external_form_action'] = $formResult['external_action'];

            $severity = $formResult['has_password'] ? 'high' : 'medium';
            $impact = $formResult['has_password'] ? 35 : 15;

            $desc = 'Halaman ini mengandung form login';
            if ($formResult['has_password']) {
                $desc .= ' dengan field password';
            }
            if ($formResult['external_action']) {
                $desc .= '. Data form dikirim ke domain EKSTERNAL (' . $formResult['external_action'] . ')';
                $impact += 15;
                $severity = 'critical';
            }
            $desc .= '. Ini adalah teknik umum halaman phishing untuk mencuri kredensial.';

            $findings[] = [
                'rule_name'    => 'PHISHING_LOGIN_FORM',
                'category'     => 'content',
                'severity'     => $severity,
                'score_impact' => $impact,
                'description'  => $desc,
            ];
            $penalty += $impact;
        }

        // 2. Deteksi Hidden Iframe
        if (self::detectHiddenIframe($bodyLower)) {
            $details['has_hidden_iframe'] = true;
            $findings[] = [
                'rule_name'    => 'HIDDEN_IFRAME',
                'category'     => 'content',
                'severity'     => 'high',
                'score_impact' => 30,
                'description'  => 'Ditemukan iframe tersembunyi (invisible iframe). Teknik ini biasa digunakan untuk memuat konten berbahaya tanpa sepengetahuan pengguna, seperti drive-by download atau clickjacking.',
            ];
            $penalty += 30;
        }

        // 3. Deteksi Crypto Mining Scripts
        $minerResult = self::detectCryptoMiner($bodyLower);
        if ($minerResult['detected']) {
            $details['has_crypto_miner'] = true;
            $details['suspicious_scripts'] = array_merge($details['suspicious_scripts'], $minerResult['scripts']);
            $findings[] = [
                'rule_name'    => 'CRYPTO_MINER',
                'category'     => 'content',
                'severity'     => 'critical',
                'score_impact' => 40,
                'description'  => 'SCRIPT PENAMBANGAN KRIPTO TERDETEKSI: Halaman ini memuat skrip mining (' . implode(', ', $minerResult['scripts']) . '). Skrip ini menggunakan CPU/GPU perangkat Anda secara diam-diam untuk menambang cryptocurrency.',
            ];
            $penalty += 40;
        }

        // 4. Deteksi Obfuscated JavaScript
        $obfResult = self::detectObfuscatedJs($htmlBody, $bodyLower);
        if ($obfResult['detected']) {
            $details['has_obfuscated_js'] = true;
            $findings[] = [
                'rule_name'    => 'OBFUSCATED_JAVASCRIPT',
                'category'     => 'content',
                'severity'     => 'medium',
                'score_impact' => 20,
                'description'  => 'Ditemukan JavaScript yang di-obfuskasi (disembunyikan/disamarkan): ' . $obfResult['technique'] . '. Teknik ini sering dipakai untuk menyembunyikan kode berbahaya dari antivirus dan analisis keamanan.',
            ];
            $penalty += 20;
        }

        // 5. Deteksi Auto-Download
        if (self::detectAutoDownload($bodyLower)) {
            $details['has_auto_download'] = true;
            $findings[] = [
                'rule_name'    => 'AUTO_DOWNLOAD_TRIGGER',
                'category'     => 'content',
                'severity'     => 'high',
                'score_impact' => 30,
                'description'  => 'Halaman ini mencoba memicu UNDUHAN OTOMATIS file. Ini adalah modus umum penyebaran malware, di mana file berbahaya langsung diunduh saat halaman dibuka.',
            ];
            $penalty += 30;
        }

        return [
            'findings' => $findings,
            'penalty'  => min(100, $penalty),
            'details'  => $details,
        ];
    }

    /**
     * Deteksi form login dan field password
     */
    private static function detectLoginForm(string $html, string $lower, string $currentUrl): array
    {
        $result = ['detected' => false, 'has_password' => false, 'external_action' => null];

        // Cek ada field password
        $hasPassword = (bool) preg_match('/<input[^>]*type\s*=\s*["\']password["\']/i', $html);

        if (!$hasPassword) {
            return $result;
        }

        $result['detected'] = true;
        $result['has_password'] = true;

        // Cek apakah form action mengarah ke domain eksternal
        if (preg_match('/<form[^>]*action\s*=\s*["\'](https?:\/\/[^"\']+)["\']/i', $html, $m)) {
            $actionUrl = $m[1];
            $actionHost = parse_url($actionUrl, PHP_URL_HOST) ?? '';
            $currentHost = parse_url($currentUrl, PHP_URL_HOST) ?? '';

            if (!empty($actionHost) && !empty($currentHost) && strtolower($actionHost) !== strtolower($currentHost)) {
                $result['external_action'] = $actionHost;
            }
        }

        return $result;
    }

    /**
     * Deteksi iframe tersembunyi
     */
    private static function detectHiddenIframe(string $lower): bool
    {
        $patterns = [
            '/<iframe[^>]*style\s*=\s*["\'][^"\']*display\s*:\s*none/i',
            '/<iframe[^>]*style\s*=\s*["\'][^"\']*visibility\s*:\s*hidden/i',
            '/<iframe[^>]*width\s*=\s*["\']?0["\']?/i',
            '/<iframe[^>]*height\s*=\s*["\']?0["\']?/i',
            '/<iframe[^>]*style\s*=\s*["\'][^"\']*position\s*:\s*absolute[^"\']*(?:left|top)\s*:\s*-\d+/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $lower)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Deteksi script crypto mining
     */
    private static function detectCryptoMiner(string $lower): array
    {
        $miners = [
            'coinhive'       => 'coinhive',
            'coin-hive'      => 'coinhive',
            'cryptonight'    => 'CryptoNight',
            'cryptoloot'     => 'CryptoLoot',
            'minero.cc'      => 'Minero',
            'webminepool'    => 'WebMinePool',
            'jsecoin'        => 'JSECoin',
            'authedmine'     => 'AuthedMine',
            'ppoi.org'       => 'PPOI Miner',
            'monerominer'    => 'MoneroMiner',
            'gridcash'       => 'GridCash',
            'worker.js'      => 'Generic Web Worker Miner',
        ];

        $detected = [];
        foreach ($miners as $pattern => $name) {
            if (str_contains($lower, $pattern)) {
                $detected[] = $name;
            }
        }

        // Deteksi WebAssembly mining (generic)
        if (str_contains($lower, 'webassembly') && str_contains($lower, 'miner')) {
            $detected[] = 'WebAssembly Miner';
        }

        return [
            'detected' => !empty($detected),
            'scripts'  => array_unique($detected),
        ];
    }

    /**
     * Deteksi JavaScript obfuscation
     */
    private static function detectObfuscatedJs(string $html, string $lower): array
    {
        $result = ['detected' => false, 'technique' => ''];
        $techniques = [];

        // eval + atob (Base64 decode lalu execute)
        if (preg_match('/eval\s*\(\s*atob\s*\(/i', $html)) {
            $techniques[] = 'eval(atob(...))';
        }

        // eval + unescape (URL encoded JS)
        if (preg_match('/eval\s*\(\s*unescape\s*\(/i', $html)) {
            $techniques[] = 'eval(unescape(...))';
        }

        // document.write + atob
        if (preg_match('/document\.write\s*\(\s*atob\s*\(/i', $html)) {
            $techniques[] = 'document.write(atob(...))';
        }

        // String.fromCharCode chains (panjang > 20 karakter)
        if (preg_match('/String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){15,}/i', $html)) {
            $techniques[] = 'String.fromCharCode (rantai panjang)';
        }

        // Hex-encoded strings (\x68\x74\x74\x70 dll) panjang
        if (preg_match('/(?:\\\\x[0-9a-f]{2}){20,}/i', $html)) {
            $techniques[] = 'Hex-encoded string (\xNN)';
        }

        if (!empty($techniques)) {
            $result['detected'] = true;
            $result['technique'] = implode(', ', $techniques);
        }

        return $result;
    }

    /**
     * Deteksi auto-download attempts
     */
    private static function detectAutoDownload(string $lower): bool
    {
        // <a download="file.exe" href="...">
        if (preg_match('/<a[^>]*\bdownload\b[^>]*href\s*=/i', $lower)) {
            return true;
        }

        // JavaScript auto-click download
        if (preg_match('/\.click\s*\(\s*\).*download/i', $lower) ||
            preg_match('/download.*\.click\s*\(\s*\)/i', $lower)) {
            return true;
        }

        // Blob URL auto-download
        if (str_contains($lower, 'createobjecturl') && str_contains($lower, 'download')) {
            return true;
        }

        // window.open with data: or blob:
        if (preg_match('/window\.open\s*\(\s*["\'](?:data:|blob:)/i', $lower)) {
            return true;
        }

        return false;
    }
}
