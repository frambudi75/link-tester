<?php
/**
 * Heuristic Analyzer - LinkTester
 * 
 * Menganalisis karakteristik struktural dan leksikal URL untuk mendeteksi
 * anomali tanpa memanggil layanan eksternal.
 * 
 * Menghasilkan Evidence objects yang akan diproses oleh RiskScorer.
 */

require_once __DIR__ . '/../Evidence.php';

class HeuristicAnalyzer
{
    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * Jalankan analisis heuristik terhadap data URL yang telah di-parse.
     * 
     * @param array $parsedUrl Hasil dari SafeUrlResolver::parseUrl()
     * @return Evidence[] Daftar bukti yang terdeteksi
     */
    public function analyze(array $parsedUrl): array
    {
        $evidences = [];
        $source = 'heuristic';

        $host = strtolower($parsedUrl['host'] ?? '');
        $subdomain = strtolower($parsedUrl['subdomain'] ?? '');
        $domain = strtolower($parsedUrl['domain'] ?? '');
        $tld = strtolower($parsedUrl['tld'] ?? '');
        $path = strtolower($parsedUrl['path'] ?? '');
        $query = strtolower($parsedUrl['query'] ?? '');
        $normalizedUrl = $parsedUrl['normalized_url'] ?? '';

        // 1. IP as Host
        if (!empty($parsedUrl['is_ip'])) {
            $evidences[] = Evidence::create(
                'ip_as_host',
                true,
                $source,
                [
                    'host' => $host,
                    'detail' => 'URL menggunakan alamat IP langsung tanpa nama domain terdaftar.'
                ],
                1.0
            );
        }

        // 2. Punycode / IDN Homoglyph
        if (!empty($parsedUrl['is_punycode'])) {
            $evidences[] = Evidence::create(
                'punycode_detected',
                true,
                $source,
                [
                    'host' => $host,
                    'detail' => 'URL menggunakan encoding Punycode (potensi serangan homoglyph).'
                ],
                0.95
            );
        }

        // 3. Subdomain Deception / Brand Impersonation
        $popularBrands = [
            'paypal', 'google', 'apple', 'microsoft', 'netflix', 'facebook', 'instagram',
            'bca', 'klikbca', 'mandiri', 'livin', 'bri', 'brimo', 'bni', 'cimb', 'dana',
            'gopay', 'shopee', 'tokopedia', 'whatsapp', 'telegram'
        ];

        foreach ($popularBrands as $brand) {
            if (!empty($subdomain) && str_contains($subdomain, $brand) && !str_contains($domain, $brand)) {
                $evidences[] = Evidence::create(
                    'subdomain_deception',
                    true,
                    $source,
                    [
                        'target_brand' => $brand,
                        'subdomain'    => $subdomain,
                        'real_domain'  => $domain,
                        'detail'       => 'Brand "' . strtoupper($brand) . '" disisipkan pada subdomain, padahal domain asli adalah "' . $domain . '".'
                    ],
                    0.9
                );
                break;
            }
        }

        // 4. Suspicious TLD
        $suspiciousTlds = $this->config['suspicious_tlds'] ?? ['xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'club', 'work', 'date', 'racing', 'win', 'bid', 'stream', 'download', 'review', 'country', 'kim', 'cricket', 'science', 'party', 'faith', 'trade', 'accountant'];
        if (in_array($tld, $suspiciousTlds, true)) {
            $evidences[] = Evidence::create(
                'suspicious_tld',
                true,
                $source,
                [
                    'tld' => $tld,
                    'detail' => 'Domain menggunakan TLD .' . $tld . ' yang bereputasi rendah dan sering disalahgunakan untuk spam/phishing.'
                ],
                0.75
            );
        }

        // 5. Phishing Keywords
        $keywords = $this->config['phishing_keywords'] ?? [
            'login', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'account',
            'banking', 'update', 'confirm', 'security', 'wallet', 'recovery', 'support',
            'authenticate', 'password', 'credential', 'billing', 'invoice', 'undangan', 'paket'
        ];
        $detectedKeywords = [];
        $fullCheckString = $subdomain . ' ' . $path . ' ' . $query;

        foreach ($keywords as $kw) {
            if (preg_match('/\b' . preg_quote($kw, '/') . '\b/i', $fullCheckString)) {
                $detectedKeywords[] = $kw;
            }
        }

        if (count($detectedKeywords) >= 2) {
            $evidences[] = Evidence::create(
                'phishing_keywords',
                count($detectedKeywords),
                $source,
                [
                    'count' => count($detectedKeywords),
                    'keywords' => $detectedKeywords,
                    'detail' => 'Ditemukan kombinasi kata kunci sensitif phishing: ' . implode(', ', array_slice($detectedKeywords, 0, 5))
                ],
                0.85
            );
        }

        // 6. Excessive Dashes in Domain
        $dashCount = substr_count($host, '-');
        if ($dashCount >= 3) {
            $evidences[] = Evidence::create(
                'excessive_dashes',
                $dashCount,
                $source,
                [
                    'dash_count' => $dashCount,
                    'detail' => 'Domain mengandung ' . $dashCount . ' tanda hubung (-), sering dipakai untuk meniru nama brand/organisasi resmi.'
                ],
                0.7
            );
        }

        // 7. Karakter @ dalam URL
        if (str_contains($normalizedUrl, '@')) {
            $evidences[] = Evidence::create(
                'at_symbol_in_url',
                true,
                $source,
                [
                    'detail' => 'URL mengandung simbol "@" yang dapat mengecoh browser mengenai host tujuan sebenarnya.'
                ],
                0.8
            );
        }

        // 8. Port Non-Standar
        $port = $parsedUrl['port'] ?? null;
        if ($port && !in_array((int)$port, [80, 443, 8080, 8443], true)) {
            $evidences[] = Evidence::create(
                'non_standard_port',
                (int)$port,
                $source,
                [
                    'port' => (int)$port,
                    'detail' => 'URL berjalan pada port non-standar (:' . $port . ').'
                ],
                0.7
            );
        }

        // 9. HTTP Tanpa SSL
        if (($parsedUrl['scheme'] ?? '') === 'http') {
            $evidences[] = Evidence::create(
                'http_no_ssl',
                true,
                $source,
                [
                    'detail' => 'Koneksi tidak terenkripsi (HTTP biasa tanpa SSL/TLS).'
                ],
                0.6
            );
        }

        // 10. Direct Link to Dangerous Executables (.apk, .exe, etc)
        $dangerousExts = $this->config['dangerous_extensions'] ?? ['apk', 'exe', 'bat', 'cmd', 'ps1', 'vbs', 'msi', 'scr', 'iso', 'dmg'];
        $ext = strtolower(pathinfo(parse_url($normalizedUrl, PHP_URL_PATH) ?? '', PATHINFO_EXTENSION));
        if (in_array($ext, $dangerousExts, true)) {
            $evidences[] = Evidence::create(
                'dangerous_file_ext',
                $ext,
                $source,
                [
                    'extension' => $ext,
                    'detail' => 'Tautan langsung mengarah ke file executable/installer (.' . strtoupper($ext) . ').'
                ],
                0.95
            );
        }

        // 11. Subdomain Berlebih (> 3 tingkatan)
        $subdomainSegments = !empty($subdomain) ? explode('.', $subdomain) : [];
        if (count($subdomainSegments) >= 3) {
            $evidences[] = Evidence::create(
                'deep_subdomains',
                count($subdomainSegments),
                $source,
                [
                    'depth' => count($subdomainSegments),
                    'detail' => 'URL memiliki hierarki subdomain yang dalam (' . count($subdomainSegments) . ' level).'
                ],
                0.6
            );
        }

        return $evidences;
    }
}
