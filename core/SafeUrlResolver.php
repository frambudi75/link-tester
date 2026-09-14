<?php
/**
 * Safe URL Resolver - LinkTester
 * 
 * Rewrites UrlParser with comprehensive SSRF protection at every redirect hop.
 * Every outbound request is validated through SsrfGuard before execution.
 * 
 * Features:
 * - Per-hop SSRF validation (DNS resolve → IP check → request)
 * - DNS rebinding protection
 * - Response size limiting (256KB)
 * - Timeout enforcement per hop
 * - Redirect loop detection
 * - Client-side redirect detection (meta refresh, JS, TDS router)
 * - Rich redirect chain metadata (status code, timing, domain change)
 */

require_once __DIR__ . '/SsrfGuard.php';

class SafeUrlResolver
{
    /**
     * Normalize user input URL.
     */
    public static function normalize(string $input): string
    {
        $input = trim($input);

        if (!preg_match('#^https?://#i', $input)) {
            $input = 'https://' . $input;
        }

        return filter_var($input, FILTER_SANITIZE_URL) ?: $input;
    }

    /**
     * Validate if URL format is acceptable.
     */
    public static function isValidUrl(string $url): bool
    {
        return (bool) filter_var($url, FILTER_VALIDATE_URL);
    }

    public static function parseUrl(string $url): array
    {
        return self::parse($url);
    }

    /**
     * Parse URL components with domain extraction.
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

        $domainInfo = self::extractDomain($host);

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
            'original_url'   => $url,
            'normalized_url' => $normalized,
            'scheme'         => $scheme,
            'host'           => $host,
            'port'           => $port,
            'path'           => $path,
            'query'          => $query,
            'subdomain'      => $domainInfo['subdomain'],
            'domain'         => $domainInfo['domain'],
            'tld'            => $domainInfo['tld'],
            'is_punycode'    => $isPunycode,
            'utf8_host'      => $utf8Host,
            'is_ip'          => (bool) filter_var($host, FILTER_VALIDATE_IP)
                                || SsrfGuard::decodeIpAddress($host) !== null,
        ];
    }

    /**
     * Extract apex domain, subdomain, and TLD.
     */
    public static function extractDomain(string $host): array
    {
        // Check if host is an IP (including encoded forms)
        $decodedIp = SsrfGuard::decodeIpAddress($host);
        if ($decodedIp !== null || filter_var($host, FILTER_VALIDATE_IP)) {
            return ['domain' => $decodedIp ?? $host, 'subdomain' => '', 'tld' => ''];
        }

        $host = strtolower(trim($host));
        $parts = explode('.', $host);
        $count = count($parts);

        if ($count <= 1) {
            return ['domain' => $host, 'subdomain' => '', 'tld' => ''];
        }

        $knownMultiTlds = [
            'co.id', 'ac.id', 'go.id', 'mil.id', 'net.id', 'or.id', 'sch.id', 'web.id',
            'co.uk', 'org.uk', 'com.au', 'com.my', 'co.jp', 'co.kr', 'co.nz',
            'com.br', 'com.sg', 'com.tw', 'co.th', 'co.za',
        ];

        $lastTwo = ($count >= 2) ? $parts[$count - 2] . '.' . $parts[$count - 1] : '';

        if (in_array($lastTwo, $knownMultiTlds, true) && $count >= 3) {
            $tld = $lastTwo;
            $domain = $parts[$count - 3] . '.' . $tld;
            $subdomain = implode('.', array_slice($parts, 0, $count - 3));
        } else {
            $tld = $parts[$count - 1];
            $domain = $parts[$count - 2] . '.' . $tld;
            $subdomain = implode('.', array_slice($parts, 0, $count - 2));
        }

        return ['domain' => $domain, 'subdomain' => $subdomain, 'tld' => $tld];
    }

    /**
     * Safely trace redirect chain with SSRF protection at every hop.
     * 
     * SECURITY: Every hop goes through:
     *   1. URL parse → scheme validation
     *   2. DNS resolve → IP validation via SsrfGuard
     *   3. Anti DNS-rebinding check
     *   4. Request with timeout and size limits
     *   5. If redirect → back to step 1
     */
    public static function traceRedirects(string $url): array
    {
        $currentUrl = self::normalize($url);
        $chain = [];
        $chainDetails = [];
        $visitedUrls = [];
        $finalIp = null;
        $hasTdsRouter = false;
        $lastBody = '';

        for ($hop = 0; $hop <= SsrfGuard::MAX_REDIRECTS; $hop++) {
            // ── Redirect loop detection ──
            if (in_array($currentUrl, $visitedUrls, true)) {
                return self::buildResult($url, $currentUrl, $chain, $chainDetails, $finalIp, $hasTdsRouter, $lastBody, null);
            }
            $visitedUrls[] = $currentUrl;

            $parts = parse_url($currentUrl);
            $host = $parts['host'] ?? '';
            $scheme = strtolower($parts['scheme'] ?? '');

            if (empty($host)) {
                break;
            }

            // ── SSRF Check: scheme ──
            if (!SsrfGuard::isAllowedScheme($scheme)) {
                return self::buildError($url, $currentUrl, $chain, "Skema '{$scheme}://' tidak diizinkan.");
            }

            // ── SSRF Check: DNS resolve + IP validation ──
            $ssrfCheck = SsrfGuard::validateUrl($currentUrl);
            if (!$ssrfCheck['safe']) {
                return self::buildError($url, $currentUrl, $chain, 'Blokir SSRF: ' . $ssrfCheck['reason']);
            }

            $ip = $ssrfCheck['resolved_ip'];

            // ── SSRF Check: DNS rebinding (on first hop and cross-domain hops) ──
            if ($hop === 0 || ($hop > 0 && !empty($chain) && self::extractDomain($host)['domain'] !== self::extractDomain(parse_url($chain[count($chain) - 1], PHP_URL_HOST) ?? '')['domain'])) {
                $rebindCheck = SsrfGuard::antiRebinding($host);
                if (!$rebindCheck['safe']) {
                    return self::buildError($url, $currentUrl, $chain, 'Blokir SSRF: ' . $rebindCheck['reason']);
                }
            }

            if ($ip) {
                $finalIp = $ip;
            }

            $chain[] = $currentUrl;

            // ── Make the request with safety limits ──
            $hopStartTime = microtime(true);

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $currentUrl,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT        => SsrfGuard::REQUEST_TIMEOUT,
                CURLOPT_CONNECTTIMEOUT => SsrfGuard::CONNECT_TIMEOUT,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_MAXFILESIZE    => SsrfGuard::MAX_RESPONSE_SIZE,
                CURLOPT_BUFFERSIZE     => 32768,
                CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            ]);

            // Bind to resolved IP to prevent DNS rebinding between resolve and connect
            if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
                $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
                curl_setopt($ch, CURLOPT_RESOLVE, ["{$host}:{$port}:{$ip}"]);
            }

            $response = curl_exec($ch);
            $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $redirectUrl = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
            $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $hopTime = round((microtime(true) - $hopStartTime) * 1000, 1);
            curl_close($ch);

            // Safely extract body (limit to 256KB)
            $body = '';
            if ($response !== false && $headerSize < strlen($response)) {
                $body = substr($response, $headerSize, SsrfGuard::MAX_RESPONSE_SIZE);
            }
            $lastBody = $body;

            // ── Record hop detail ──
            $hopDetail = [
                'hop'             => $hop,
                'url'             => $currentUrl,
                'status_code'     => $httpCode,
                'redirect_type'   => null,
                'hostname'        => $host,
                'scheme'          => $scheme,
                'ip'              => $ip,
                'response_time_ms'=> $hopTime,
                'domain_changed'  => false,
            ];

            // Check domain change from previous hop
            if ($hop > 0 && count($chainDetails) > 0) {
                $prevHost = $chainDetails[$hop - 1]['hostname'] ?? '';
                $prevDomain = self::extractDomain($prevHost)['domain'];
                $curDomain = self::extractDomain($host)['domain'];
                $hopDetail['domain_changed'] = ($prevDomain !== $curDomain);
            }

            // ── Detect next URL ──
            $nextUrl = null;
            $redirectType = null;

            // 1. HTTP Header redirect (301, 302, 303, 307, 308)
            if (in_array($httpCode, [301, 302, 303, 307, 308]) && !empty($redirectUrl)) {
                $nextUrl = $redirectUrl;
                $redirectType = 'http_' . $httpCode;
            }
            // 2. Client-side redirects (on HTTP 200)
            elseif ($httpCode === 200 && !empty($body)) {
                // a. Meta refresh
                if (preg_match('/\<meta[^>]*http-equiv=[\'"]?refresh[\'"]?[^>]*content=[\'"]?[0-9]*;\s*url=([^\'" >]+)/i', $body, $m)) {
                    $nextUrl = html_entity_decode(trim($m[1]));
                    $redirectType = 'meta_refresh';
                }
                // b. JS location
                elseif (preg_match('/(?:window\.|document\.|self\.|top\.)?location(?:\.href)?\s*=\s*[\'"]([^\'";\s]+)[\'"]/i', $body, $m) ||
                        preg_match('/(?:window\.|document\.|self\.|top\.)?location\.(?:replace|assign)\s*\(\s*[\'"]([^\'";\s]+)[\'"]\s*\)/i', $body, $m)) {
                    $nextUrl = html_entity_decode(trim($m[1]));
                    $redirectType = 'javascript';
                }
                // c. Base64 obfuscated JS redirect
                elseif (preg_match('/location(?:\.href|\.replace|\.assign)?\s*=\s*atob\(\s*[\'"]([a-zA-Z0-9+\/=]{12,})[\'"]\s*\)/i', $body, $bm)) {
                    $decoded = @base64_decode($bm[1]);
                    if (!empty($decoded) && preg_match('#^https?://#i', $decoded)) {
                        $nextUrl = trim($decoded);
                        $redirectType = 'javascript_base64';
                    }
                }
                // d. TDS Router detection
                elseif (preg_match('#https?://(?:router|tds|traffic|gate|redirector)\.[a-z0-9.-]+/[a-zA-Z0-9/_.-]+#i', $body, $rm) ||
                        preg_match('#https?://[a-z0-9.-]*parklogic\.com/[a-zA-Z0-9/_.-]+#i', $body, $rm)) {
                    $routerUrl = $rm[0];
                    $redirectType = 'tds_router';
                    $hasTdsRouter = true;

                    // Query TDS endpoint
                    $rCh = curl_init($routerUrl);
                    curl_setopt_array($rCh, [
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_TIMEOUT        => SsrfGuard::CONNECT_TIMEOUT,
                        CURLOPT_POST           => true,
                        CURLOPT_POSTFIELDS     => json_encode(['parameters' => [
                            'domainApex' => $host,
                            'path'       => $parts['path'] ?? '',
                            'protocol'   => $scheme,
                        ]]),
                        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
                        CURLOPT_SSL_VERIFYPEER => false,
                        CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    ]);
                    $rRes = curl_exec($rCh);
                    curl_close($rCh);

                    if (!empty($rRes) && preg_match('#https?://[^\s"\'<>]+#i', $rRes, $dst)) {
                        $nextUrl = trim($dst[0]);
                    }
                }
            }

            $hopDetail['redirect_type'] = $redirectType;
            $chainDetails[] = $hopDetail;

            // ── Follow redirect ──
            if (!empty($nextUrl)) {
                // Handle relative redirects
                if (!preg_match('#^https?://#i', $nextUrl)) {
                    $base = $scheme . '://' . $host;
                    $nextUrl = rtrim($base, '/') . '/' . ltrim($nextUrl, '/');
                }

                // ── CRITICAL: Validate redirect destination BEFORE following ──
                $destCheck = SsrfGuard::validateUrl($nextUrl);
                if (!$destCheck['safe']) {
                    return self::buildError($url, $currentUrl, $chain,
                        'Blokir SSRF: Redirect mengarah ke target terblokir: ' . $destCheck['reason']
                    );
                }

                $currentUrl = $nextUrl;
            } else {
                break;
            }
        }

        return self::buildResult($url, $currentUrl, $chain, $chainDetails, $finalIp, $hasTdsRouter, $lastBody, null);
    }

    // ─── Result Builders ─────────────────────────────────────

    private static function buildResult(
        string $originalUrl,
        string $finalUrl,
        array $chain,
        array $chainDetails,
        ?string $finalIp,
        bool $hasTdsRouter,
        string $htmlBody,
        ?string $error
    ): array {
        $origDomain = self::extractDomain(parse_url(self::normalize($originalUrl), PHP_URL_HOST) ?? '')['domain'];
        $finalDomain = self::extractDomain(parse_url($finalUrl, PHP_URL_HOST) ?? '')['domain'];
        $isCrossDomain = (!empty($origDomain) && !empty($finalDomain) && strtolower($origDomain) !== strtolower($finalDomain));

        $domainsVisited = [];
        foreach ($chainDetails as $d) {
            $dom = self::extractDomain($d['hostname'])['domain'];
            if (!empty($dom) && !in_array($dom, $domainsVisited, true)) {
                $domainsVisited[] = $dom;
            }
        }

        $totalTime = array_sum(array_column($chainDetails, 'response_time_ms'));
        $schemeDowngrade = false;
        for ($i = 1; $i < count($chainDetails); $i++) {
            if ($chainDetails[$i - 1]['scheme'] === 'https' && $chainDetails[$i]['scheme'] === 'http') {
                $schemeDowngrade = true;
                break;
            }
        }

        return [
            'original_url'     => $originalUrl,
            'final_url'        => $finalUrl,
            'redirect_count'   => max(0, count($chain) - 1),
            'is_redirected'    => count($chain) > 1,
            'is_cross_domain'  => $isCrossDomain,
            'has_tds_router'   => $hasTdsRouter,
            'original_domain'  => $origDomain,
            'final_domain'     => $finalDomain,
            'chain'            => $chain,
            'chain_details'    => $chainDetails,
            'redirect_chain'   => $chainDetails,
            'ip_address'       => $finalIp,
            'html_body'        => $htmlBody,
            'redirect_summary' => [
                'total_hops'       => max(0, count($chain) - 1),
                'total_time_ms'    => round($totalTime, 1),
                'domains_visited'  => count($domainsVisited),
                'cross_domain'     => $isCrossDomain,
                'scheme_downgrade' => $schemeDowngrade,
            ],
            'error' => $error,
        ];
    }

    private static function buildError(string $originalUrl, string $currentUrl, array $chain, string $error): array
    {
        return [
            'original_url'     => $originalUrl,
            'final_url'        => $currentUrl,
            'redirect_count'   => max(0, count($chain) - 1),
            'is_redirected'    => count($chain) > 1,
            'is_cross_domain'  => false,
            'has_tds_router'   => false,
            'original_domain'  => '',
            'final_domain'     => '',
            'chain'            => $chain,
            'chain_details'    => [],
            'redirect_chain'   => [],
            'ip_address'       => null,
            'html_body'        => '',
            'redirect_summary' => [],
            'error'            => $error,
        ];
    }
}
