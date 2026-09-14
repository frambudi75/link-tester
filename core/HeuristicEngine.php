<?php
/**
 * Heuristic Risk Engine - LinkTester
 * Menganalisis pola anomali URL secara lokal tanpa memanggil API pihak ketiga.
 */

class HeuristicEngine
{
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Jalankan seluruh tes heuristik terhadap parsed URL dan rantai redirect
     */
    public function analyze(array $parsedUrl, array $redirectInfo = []): array
    {
        $findings = [];
        $totalPenalty = 0;

        $host = strtolower($parsedUrl['host'] ?? '');
        $subdomain = strtolower($parsedUrl['subdomain'] ?? '');
        $domain = strtolower($parsedUrl['domain'] ?? '');
        $tld = strtolower($parsedUrl['tld'] ?? '');
        $path = strtolower($parsedUrl['path'] ?? '');
        $query = strtolower($parsedUrl['query'] ?? '');
        $normalizedUrl = $parsedUrl['normalized_url'] ?? '';

        // 1. IP as Hostname
        if ($parsedUrl['is_ip']) {
            $findings[] = [
                'rule_name' => 'IP_AS_HOST',
                'category' => 'heuristic',
                'severity' => 'high',
                'score_impact' => 40,
                'description' => 'URL menggunakan alamat IP langsung (' . $host . ') tanpa nama domain terdaftar. Ini adalah pola klasik phishing dan server command-and-control.',
            ];
            $totalPenalty += 40;
        }

        // 2. IDN Homoglyph / Punycode
        if ($parsedUrl['is_punycode']) {
            $findings[] = [
                'rule_name' => 'IDN_HOMOGLYPH',
                'category' => 'heuristic',
                'severity' => 'high',
                'score_impact' => 35,
                'description' => 'URL menggunakan karakter Punycode (IDN Homoglyph Attack). Karakter ini sering dipakai untuk memalsukan huruf alfabet (misal mengganti huruf "o" dengan aksara cyrillic).',
            ];
            $totalPenalty += 35;
        }

        // 3. Subdomain Deception / Brand Impersonation
        $popularBrands = [
            'paypal', 'google', 'apple', 'microsoft', 'netflix', 'facebook', 'instagram',
            'bca', 'klikbca', 'mandiri', 'livin', 'bri', 'brimo', 'bni', 'cimb', 'dana',
            'gopay', 'shopee', 'tokopedia', 'whatsapp', 'telegram'
        ];

        foreach ($popularBrands as $brand) {
            // Jika nama brand ada di subdomain padahal domain utamanya BUKAN brand tsb
            if (!empty($subdomain) && str_contains($subdomain, $brand) && !str_contains($domain, $brand)) {
                $findings[] = [
                    'rule_name' => 'SUBDOMAIN_DECEPTION',
                    'category' => 'heuristic',
                    'severity' => 'high',
                    'score_impact' => 40,
                    'description' => 'Ditemukan teknik Subdomain Deception: Brand "' . strtoupper($brand) . '" disisipkan pada subdomain, padahal domain aslinya adalah "' . $domain . '".',
                ];
                $totalPenalty += 40;
                break;
            }
        }

        // 4. Suspicious TLD
        $suspiciousTlds = $this->config['suspicious_tlds'] ?? [];
        if (in_array($tld, $suspiciousTlds, true)) {
            $findings[] = [
                'rule_name' => 'SUSPICIOUS_TLD',
                'category' => 'heuristic',
                'severity' => 'medium',
                'score_impact' => 20,
                'description' => 'Menggunakan Top-Level Domain (.' . $tld . ') yang memiliki reputasi rendah dan sering disalahgunakan untuk kampanye spam/phishing massal.',
            ];
            $totalPenalty += 20;
        }

        // 5. Phishing Keywords
        $keywords = $this->config['phishing_keywords'] ?? [];
        $detectedKeywords = [];
        $fullCheckString = $subdomain . ' ' . $path . ' ' . $query;

        foreach ($keywords as $kw) {
            if (preg_match('/\b' . preg_quote($kw, '/') . '\b/i', $fullCheckString)) {
                $detectedKeywords[] = $kw;
            }
        }

        if (count($detectedKeywords) >= 2) {
            $findings[] = [
                'rule_name' => 'PHISH_KEYWORDS',
                'category' => 'heuristic',
                'severity' => 'medium',
                'score_impact' => 25,
                'description' => 'Ditemukan kombinasi kata kunci sensitif yang sering dipakai modus phishing: ' . implode(', ', array_slice($detectedKeywords, 0, 4)),
            ];
            $totalPenalty += 25;
        }

        // 6. Excessive Dashes in Domain
        if (substr_count($host, '-') >= 3) {
            $findings[] = [
                'rule_name' => 'EXCESSIVE_DASHES',
                'category' => 'heuristic',
                'severity' => 'low',
                'score_impact' => 15,
                'description' => 'Domain mengandung banyak tanda hubung (-) yang biasa dipakai untuk membuat nama domain palsu terlihat seperti domain resmi.',
            ];
            $totalPenalty += 15;
        }

        // 7. Karakter @ dalam URL
        if (str_contains($normalizedUrl, '@')) {
            $findings[] = [
                'rule_name' => 'AT_SYMBOL_URL',
                'category' => 'heuristic',
                'severity' => 'medium',
                'score_impact' => 30,
                'description' => 'URL mengandung simbol "@". Pada browser, karakter ini dapat mengalihkan fokus pengguna dari host sebenarnya.',
            ];
            $totalPenalty += 30;
        }

        // 8. Port Non-Standar
        $port = $parsedUrl['port'] ?? null;
        if ($port && !in_array($port, [80, 443, 8080, 8443], true)) {
            $findings[] = [
                'rule_name' => 'NON_STANDARD_PORT',
                'category' => 'heuristic',
                'severity' => 'low',
                'score_impact' => 20,
                'description' => 'URL menggunakan port non-standar (:' . $port . '). Layanan resmi publik umumnya hanya berjalan pada port 80 (HTTP) atau 443 (HTTPS).',
            ];
            $totalPenalty += 20;
        }

        // 9. HTTP Tanpa SSL
        if (($parsedUrl['scheme'] ?? '') === 'http') {
            $findings[] = [
                'rule_name' => 'HTTP_NO_SSL',
                'category' => 'heuristic',
                'severity' => 'low',
                'score_impact' => 10,
                'description' => 'Koneksi tidak terenkripsi (HTTP biasa tanpa SSL/TLS). Komunikasi data rawan disadap pihak ketiga (Man-in-the-Middle).',
            ];
            $totalPenalty += 10;
        }

        // 10. Direct Link to Dangerous Executables (.apk, .exe, etc)
        $dangerousExts = $this->config['dangerous_extensions'] ?? [];
        $ext = strtolower(pathinfo(parse_url($normalizedUrl, PHP_URL_PATH) ?? '', PATHINFO_EXTENSION));
        
        if (in_array($ext, $dangerousExts, true)) {
            $findings[] = [
                'rule_name' => 'SUSPICIOUS_FILE_EXT',
                'category' => 'heuristic',
                'severity' => 'critical',
                'score_impact' => 50,
                'description' => 'PERINGATAN BAHAYA: Tautan ini mengarah langsung ke file eksekusi/installer (.' . strtoupper($ext) . '). Ini adalah modus umum penyebaran malware APK (misal undangan pernikahan palsu, kurir paket, surat tilang).',
            ];
            $totalPenalty += 50;
        }

        // 11. Subdomain Berlebih (> 3 tingkatan)
        $subdomainSegments = !empty($subdomain) ? explode('.', $subdomain) : [];
        if (count($subdomainSegments) >= 3) {
            $findings[] = [
                'rule_name' => 'DEEP_SUBDOMAINS',
                'category' => 'heuristic',
                'severity' => 'low',
                'score_impact' => 15,
                'description' => 'URL memiliki hierarki subdomain yang terlalu dalam (' . count($subdomainSegments) . ' level), sering digunakan untuk menyamarkan domain asli.',
            ];
            $totalPenalty += 15;
        }

        // 12. Cross-Domain Redirect (Cloaking / Arbitrary Redirect)
        if (!empty($redirectInfo['is_cross_domain'])) {
            $orig = $redirectInfo['original_domain'] ?? '';
            $final = $redirectInfo['final_domain'] ?? '';
            $findings[] = [
                'rule_name' => 'CROSS_DOMAIN_REDIRECT',
                'category' => 'network',
                'severity' => 'high',
                'score_impact' => 35,
                'description' => 'PENGALIHAN LINTAS DOMAIN (Cloaking): Link awal menunjuk ke "' . $orig . '", namun dialihkan diam-diam ke domain berbeda ("' . $final . '"). Ini adalah teknik umum untuk menyembunyikan situs jebakan/iklan berbahaya.',
            ];
            $totalPenalty += 35;
        }

        // 13. Excessive Redirects (Rantai Lompatan Beruntun)
        $redirCount = $redirectInfo['redirect_count'] ?? 0;
        if ($redirCount >= 2) {
            $findings[] = [
                'rule_name' => 'EXCESSIVE_REDIRECTS',
                'category' => 'network',
                'severity' => 'medium',
                'score_impact' => 25,
                'description' => 'RANTAI PENGALIHAN BERUNTUN: Tautan dialihkan sebanyak ' . $redirCount . ' kali sebelum mencapai tujuan akhir. Rantai redirect yang beruntun sering dipakai jaringan malvertising dan scam bypass.',
            ];
            $totalPenalty += 25;
        }

        // 14. Traffic Distribution System (TDS) / Ad Cloaker
        if (!empty($redirectInfo['has_tds_router'])) {
            $findings[] = [
                'rule_name' => 'TRAFFIC_DISTRIBUTION_SYSTEM',
                'category' => 'network',
                'severity' => 'high',
                'score_impact' => 40,
                'description' => 'TRAFFIC DISTRIBUTION SYSTEM (TDS) TERDETEKSI: Halaman menggunakan skrip router tersembunyi (ParkLogic/Ad-Router) untuk merutekan pengunjung secara dinamis ke target iklan, landing page mencurigakan, atau parked domain.',
            ];
            $totalPenalty += 40;
        }

        return [
            'findings' => $findings,
            'penalty' => min(100, $totalPenalty),
        ];
    }
}
