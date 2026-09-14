<?php
/**
 * URL Parser, Normalizer, & Safe Redirect Follower - LinkTester
 */

class UrlParser
{
    /**
     * Normalisasi input URL dari user
     */
    public static function normalize(string $input): string
    {
        $input = trim($input);
        
        // Tambahkan https:// jika user menginput tanpa scheme
        if (!preg_match('#^https?://#i', $input)) {
            $input = 'http://' . $input;
        }

        return filter_var($input, FILTER_SANITIZE_URL) ?: $input;
    }

    /**
     * Validasi apakah URL valid
     */
    public static function isValidUrl(string $url): bool
    {
        return (bool) filter_var($url, FILTER_VALIDATE_URL);
    }

    /**
     * Parse komponen URL
     */
    public static function parse(string $url): array
    {
        $normalized = self::normalize($url);
        $parts = parse_url($normalized);

        $host = $parts['host'] ?? '';
        $port = $parts['port'] ?? null;
        $scheme = strtolower($parts['scheme'] ?? 'http');
        $path = $parts['path'] ?? '/';
        $query = $parts['query'] ?? '';

        // Ekstraksi domain dan subdomain
        $domainInfo = self::extractDomain($host);

        // Deteksi Punycode / IDN Homoglyph
        $isPunycode = str_contains(strtolower($host), 'xn--');
        $utf8Host = $host;
        if (function_exists('idn_to_utf8')) {
            $decoded = @idn_to_utf8($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($decoded && $decoded !== $host) {
                $utf8Host = $decoded;
                $isPunycode = true;
            }
        }

        return [
            'original_url' => $url,
            'normalized_url' => $normalized,
            'scheme' => $scheme,
            'host' => $host,
            'port' => $port,
            'path' => $path,
            'query' => $query,
            'subdomain' => $domainInfo['subdomain'],
            'domain' => $domainInfo['domain'],
            'tld' => $domainInfo['tld'],
            'is_punycode' => $isPunycode,
            'utf8_host' => $utf8Host,
            'is_ip' => (bool) filter_var($host, FILTER_VALIDATE_IP),
        ];
    }

    /**
     * Ekstrak domain utama, subdomain, dan TLD
     */
    public static function extractDomain(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [
                'domain' => $host,
                'subdomain' => '',
                'tld' => '',
            ];
        }

        $host = strtolower(trim($host));
        $parts = explode('.', $host);
        $count = count($parts);

        if ($count <= 1) {
            return ['domain' => $host, 'subdomain' => '', 'tld' => ''];
        }

        // Tangani TLD bertingkat (contoh: .co.id, .ac.id, .com.my, .co.uk)
        $knownMultiTlds = ['co.id', 'ac.id', 'go.id', 'mil.id', 'net.id', 'or.id', 'sch.id', 'web.id', 'co.uk', 'com.au', 'com.my', 'co.jp'];
        
        $lastTwo = '';
        if ($count >= 2) {
            $lastTwo = $parts[$count - 2] . '.' . $parts[$count - 1];
        }

        if (in_array($lastTwo, $knownMultiTlds, true) && $count >= 3) {
            $tld = $lastTwo;
            $mainName = $parts[$count - 3];
            $domain = $mainName . '.' . $tld;
            $subdomainParts = array_slice($parts, 0, $count - 3);
            $subdomain = implode('.', $subdomainParts);
        } else {
            $tld = $parts[$count - 1];
            $mainName = $parts[$count - 2];
            $domain = $mainName . '.' . $tld;
            $subdomainParts = array_slice($parts, 0, $count - 2);
            $subdomain = implode('.', $subdomainParts);
        }

        return [
            'domain' => $domain,
            'subdomain' => $subdomain,
            'tld' => $tld,
        ];
    }

    /**
     * Anti-SSRF: Periksa apakah IP merupakan private, loopback, atau link-local
     */
    public static function isPrivateIp(string $ip): bool
    {
        return !filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    /**
     * Melacak rantai pengalihan (URL Unshortener) dengan aman
     */
    public static function traceRedirects(string $url, int $maxRedirects = 5): array
    {
        $currentUrl = self::normalize($url);
        $chain = [];
        $finalIp = null;

        for ($i = 0; $i < $maxRedirects; $i++) {
            $chain[] = $currentUrl;
            
            $parts = parse_url($currentUrl);
            $host = $parts['host'] ?? '';
            
            if (empty($host)) {
                break;
            }

            // Cek DNS & Anti-SSRF
            $resolvedIps = @dns_get_record($host, DNS_A);
            $ip = null;
            if (!empty($resolvedIps) && isset($resolvedIps[0]['ip'])) {
                $ip = $resolvedIps[0]['ip'];
            } elseif (filter_var($host, FILTER_VALIDATE_IP)) {
                $ip = $host;
            }

            if ($ip) {
                $finalIp = $ip;
                if (self::isPrivateIp($ip)) {
                    // Blokir SSRF attempt!
                    return [
                        'original_url' => $url,
                        'final_url' => $currentUrl,
                        'redirect_count' => count($chain) - 1,
                        'is_redirected' => count($chain) > 1,
                        'chain' => $chain,
                        'ip_address' => $ip,
                        'error' => 'Blokir SSRF: Host mengarah ke IP internal/privat.',
                    ];
                }
            }

            // Lakukan HEAD request aman
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $currentUrl,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => true,
                CURLOPT_NOBODY         => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT        => 4,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $redirectUrl = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
            curl_close($ch);

            // Jika ada pengalihan HTTP (301, 302, 303, 307, 308)
            if (in_array($httpCode, [301, 302, 303, 307, 308]) && !empty($redirectUrl)) {
                // Tangani relative redirect
                if (!preg_match('#^https?://#i', $redirectUrl)) {
                    $base = $parts['scheme'] . '://' . $parts['host'];
                    $redirectUrl = rtrim($base, '/') . '/' . ltrim($redirectUrl, '/');
                }
                $currentUrl = $redirectUrl;
            } else {
                break;
            }
        }

        return [
            'original_url' => $url,
            'final_url' => $currentUrl,
            'redirect_count' => count($chain) - 1,
            'is_redirected' => count($chain) > 1,
            'chain' => $chain,
            'ip_address' => $finalIp,
            'error' => null,
        ];
    }
}
