<?php
/**
 * Content Analyzer - LinkTester
 * 
 * Menginspeksi payload HTML halaman target untuk mendeteksi ancaman sisi klien:
 * formulir pencurian password, iframe tersembunyi, penambang kripto, kode ter-obfuskasi,
 * dan unduhan file otomatis.
 * 
 * Menghasilkan Evidence objects untuk diproses oleh RiskScorer.
 */

require_once __DIR__ . '/../Evidence.php';

class ContentAnalyzer
{
    /**
     * Analisis konten HTML halaman target.
     * 
     * @param string $htmlBody Body HTML (dibatasi oleh SafeUrlResolver)
     * @param string $url URL asal
     * @return array ['evidences' => Evidence[], 'details' => array]
     */
    public static function analyze(string $htmlBody, string $url = ''): array
    {
        $evidences = [];
        $source = 'content';

        $details = [
            'has_login_form'       => false,
            'has_password_field'   => false,
            'has_hidden_iframe'    => false,
            'has_crypto_miner'     => false,
            'has_obfuscated_js'    => false,
            'has_auto_download'    => false,
            'external_form_action' => null,
            'suspicious_scripts'   => [],
        ];

        if (empty(trim($htmlBody))) {
            return ['evidences' => $evidences, 'details' => $details];
        }

        $bodyLower = strtolower($htmlBody);

        // 1. Form Login / Password Field
        $form = self::detectLoginForm($htmlBody, $bodyLower, $url);
        if ($form['detected']) {
            $details['has_login_form'] = true;
            $details['has_password_field'] = $form['has_password'];
            $details['external_form_action'] = $form['external_action'];

            $evidences[] = Evidence::create(
                'phishing_login_form',
                true,
                $source,
                [
                    'has_password'    => $form['has_password'],
                    'external_action' => $form['external_action'],
                    'detail'          => 'Halaman memuat form input kredensial/password' . 
                        ($form['external_action'] ? ' yang dikirim ke domain eksternal (' . $form['external_action'] . ')' : '') . '.'
                ],
                $form['external_action'] ? 0.95 : 0.85
            );
        }

        // 2. Hidden Iframe
        if (self::detectHiddenIframe($bodyLower)) {
            $details['has_hidden_iframe'] = true;
            $evidences[] = Evidence::create(
                'hidden_iframe',
                true,
                $source,
                ['detail' => 'Ditemukan iframe tersembunyi (potensi drive-by download atau clickjacking).'],
                0.9
            );
        }

        // 3. Crypto Mining Scripts
        $miner = self::detectCryptoMiner($bodyLower);
        if ($miner['detected']) {
            $details['has_crypto_miner'] = true;
            $details['suspicious_scripts'] = array_merge($details['suspicious_scripts'], $miner['scripts']);
            $evidences[] = Evidence::create(
                'crypto_miner',
                true,
                $source,
                [
                    'scripts' => $miner['scripts'],
                    'detail'  => 'Skrip browser cryptocurrency mining terdeteksi: ' . implode(', ', $miner['scripts']) . '.'
                ],
                0.95
            );
        }

        // 4. Obfuscated JavaScript
        $obf = self::detectObfuscatedJs($htmlBody, $bodyLower);
        if ($obf['detected']) {
            $details['has_obfuscated_js'] = true;
            $evidences[] = Evidence::create(
                'obfuscated_javascript',
                true,
                $source,
                [
                    'technique' => $obf['technique'],
                    'detail'    => 'Ditemukan kode JavaScript ter-obfuskasi: ' . $obf['technique'] . '.'
                ],
                0.8
            );
        }

        // 5. Auto-Download Trigger
        if (self::detectAutoDownload($bodyLower)) {
            $details['has_auto_download'] = true;
            $evidences[] = Evidence::create(
                'auto_download_trigger',
                true,
                $source,
                ['detail' => 'Halaman secara otomatis memicu pengunduhan file tanpa interaksi pengguna.'],
                0.9
            );
        }

        return ['evidences' => $evidences, 'details' => $details];
    }

    private static function detectLoginForm(string $html, string $lower, string $currentUrl): array
    {
        $result = ['detected' => false, 'has_password' => false, 'external_action' => null];
        $hasPassword = (bool) preg_match('/<input[^>]*type\s*=\s*["\']password["\']/i', $html);

        if (!$hasPassword) {
            return $result;
        }

        $result['detected'] = true;
        $result['has_password'] = true;

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

        if (str_contains($lower, 'webassembly') && str_contains($lower, 'miner')) {
            $detected[] = 'WebAssembly Miner';
        }

        return [
            'detected' => !empty($detected),
            'scripts'  => array_unique($detected),
        ];
    }

    private static function detectObfuscatedJs(string $html, string $lower): array
    {
        $result = ['detected' => false, 'technique' => ''];
        $techniques = [];

        if (preg_match('/eval\s*\(\s*atob\s*\(/i', $html)) {
            $techniques[] = 'eval(atob(...))';
        }
        if (preg_match('/eval\s*\(\s*unescape\s*\(/i', $html)) {
            $techniques[] = 'eval(unescape(...))';
        }
        if (preg_match('/document\.write\s*\(\s*atob\s*\(/i', $html)) {
            $techniques[] = 'document.write(atob(...))';
        }
        if (preg_match('/String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){15,}/i', $html)) {
            $techniques[] = 'String.fromCharCode (chained)';
        }
        if (preg_match('/(?:\\\\x[0-9a-f]{2}){20,}/i', $html)) {
            $techniques[] = 'Hex-encoded string (\xNN)';
        }

        if (!empty($techniques)) {
            $result['detected'] = true;
            $result['technique'] = implode(', ', $techniques);
        }

        return $result;
    }

    private static function detectAutoDownload(string $lower): bool
    {
        if (preg_match('/<a[^>]*\bdownload\b[^>]*href\s*=/i', $lower)) {
            return true;
        }
        if (preg_match('/\.click\s*\(\s*\).*download/i', $lower) ||
            preg_match('/download.*\.click\s*\(\s*\)/i', $lower)) {
            return true;
        }
        if (str_contains($lower, 'createobjecturl') && str_contains($lower, 'download')) {
            return true;
        }
        if (preg_match('/window\.open\s*\(\s*["\'](?:data:|blob:)/i', $lower)) {
            return true;
        }

        return false;
    }
}
