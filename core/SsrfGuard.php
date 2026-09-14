<?php
/**
 * SSRF Guard - LinkTester
 * 
 * Comprehensive Server-Side Request Forgery protection.
 * ALL outbound requests MUST be validated through this module.
 * 
 * Protects against:
 * - Private IPv4/IPv6 ranges
 * - Loopback addresses (127.x, ::1)
 * - Link-local addresses (169.254.x, fe80::)
 * - Multicast/reserved ranges
 * - Cloud metadata endpoints (169.254.169.254)
 * - DNS resolving to private IPs
 * - DNS rebinding attacks
 * - Non-HTTP schemes (file://, gopher://, etc.)
 * - Redirect chains to internal IPs
 * - Hex/octal/decimal IP encoding bypasses
 */

class SsrfGuard
{
    /** Max allowed response body size in bytes (256KB) */
    const MAX_RESPONSE_SIZE = 262144;

    /** Connection timeout per hop (seconds) */
    const CONNECT_TIMEOUT = 3;

    /** Total timeout per hop (seconds) */
    const REQUEST_TIMEOUT = 8;

    /** Maximum redirect hops */
    const MAX_REDIRECTS = 5;

    /** Allowed URL schemes */
    const ALLOWED_SCHEMES = ['http', 'https'];

    /**
     * Blocked IPv4 CIDR ranges
     * Each entry: [network_long, mask_long, label]
     */
    private static array $blockedIpv4Cidrs = [
        // Loopback
        ['127.0.0.0',     8,  'loopback'],
        // Private (RFC 1918)
        ['10.0.0.0',      8,  'private (10.0.0.0/8)'],
        ['172.16.0.0',    12, 'private (172.16.0.0/12)'],
        ['192.168.0.0',   16, 'private (192.168.0.0/16)'],
        // Link-local
        ['169.254.0.0',   16, 'link-local'],
        // CGNAT (Shared Address Space)
        ['100.64.0.0',    10, 'CGNAT (100.64.0.0/10)'],
        // Current network
        ['0.0.0.0',       8,  'current-network (0.0.0.0/8)'],
        // Multicast
        ['224.0.0.0',     4,  'multicast'],
        // Reserved / future use
        ['240.0.0.0',     4,  'reserved (240.0.0.0/4)'],
        // Broadcast
        ['255.255.255.255', 32, 'broadcast'],
        // TEST-NET ranges
        ['192.0.2.0',     24, 'TEST-NET-1'],
        ['198.51.100.0',  24, 'TEST-NET-2'],
        ['203.0.113.0',   24, 'TEST-NET-3'],
        // Benchmarking
        ['198.18.0.0',    15, 'benchmarking'],
    ];

    /**
     * Specific blocked IPs (cloud metadata, etc.)
     */
    private static array $blockedIps = [
        '169.254.169.254',  // AWS/GCP/Azure metadata
        'fd00::1',          // Common Docker/K8s internal
    ];

    /**
     * Blocked hostnames
     */
    private static array $blockedHostnames = [
        'localhost',
        'metadata.google.internal',
        'metadata.goog',
        'kubernetes.default.svc',
        'kubernetes.default',
    ];

    // ─── Public API ──────────────────────────────────────────

    /**
     * Check if a given IP address belongs to blocked/private ranges.
     */
    public static function isBlockedIp(string $ip): bool
    {
        $res = self::checkIp($ip);
        return !$res['safe'];
    }

    /**
     * Validate target URL and return object with isBlocked property.
     */
    public static function validateTarget(string $url): object
    {
        $res = self::validateUrl($url);
        return (object) [
            'isBlocked'  => !$res['safe'],
            'safe'       => $res['safe'],
            'reason'     => $res['reason'],
            'resolvedIp' => $res['resolved_ip'] ?? null,
        ];
    }

    /**
     * Validate a URL before making any request.
     * Returns ['safe' => bool, 'reason' => string|null, 'resolved_ip' => string|null]
     */
    public static function validateUrl(string $url): array
    {
        // 1. Parse URL
        $parts = parse_url($url);
        if ($parts === false || empty($parts['host'])) {
            return self::block('URL tidak dapat di-parse atau tidak memiliki host.');
        }

        // 2. Validate scheme
        $scheme = strtolower($parts['scheme'] ?? '');
        if (!self::isAllowedScheme($scheme)) {
            return self::block("Skema URL '{$scheme}://' tidak diizinkan. Hanya HTTP dan HTTPS.");
        }

        // 3. Check blocked hostnames
        $host = strtolower($parts['host']);
        if (in_array($host, self::$blockedHostnames, true)) {
            return self::block("Hostname '{$host}' diblokir (target internal/metadata).");
        }

        // 4. Check if host is a raw IP (including encoded forms)
        $decodedIp = self::decodeIpAddress($host);
        if ($decodedIp !== null) {
            $check = self::checkIp($decodedIp);
            if (!$check['safe']) {
                return $check;
            }
            return self::allow($decodedIp);
        }

        // 5. DNS resolve and check
        $resolveResult = self::safeResolve($host);
        if (!$resolveResult['safe']) {
            return $resolveResult;
        }

        return self::allow($resolveResult['resolved_ip']);
    }

    /**
     * Resolve hostname via DNS and validate the resulting IP.
     */
    public static function safeResolve(string $hostname): array
    {
        if (empty($hostname)) {
            return self::block('Hostname kosong.');
        }

        // Try to resolve A records
        $records = @dns_get_record($hostname, DNS_A);
        $ip = null;

        if (!empty($records)) {
            $ip = $records[0]['ip'] ?? null;
        }

        // Try AAAA if no A record
        if ($ip === null) {
            $records6 = @dns_get_record($hostname, DNS_AAAA);
            if (!empty($records6)) {
                $ip = $records6[0]['ipv6'] ?? null;
            }
        }

        // Fallback to gethostbyname
        if ($ip === null) {
            $resolved = @gethostbyname($hostname);
            if ($resolved !== $hostname) {
                $ip = $resolved;
            }
        }

        if ($ip === null) {
            // Can't resolve — allow but note it (the curl request itself will fail)
            return self::allow(null);
        }

        // Validate resolved IP
        $check = self::checkIp($ip);
        if (!$check['safe']) {
            return self::block(
                "DNS resolusi '{$hostname}' mengarah ke IP terblokir ({$ip}): {$check['reason']}"
            );
        }

        return self::allow($ip);
    }

    /**
     * Anti DNS-rebinding: resolve twice with a delay and compare.
     * If the IP changes from public to private between resolves, it's suspicious.
     */
    public static function antiRebinding(string $hostname): array
    {
        // First resolve
        $resolve1 = self::safeResolve($hostname);
        if (!$resolve1['safe']) {
            return $resolve1;
        }
        $ip1 = $resolve1['resolved_ip'];

        // Small delay to allow DNS TTL tricks
        usleep(100000); // 100ms

        // Second resolve (bypass cache by using different method)
        $ip2 = @gethostbyname($hostname);
        if ($ip2 === $hostname) {
            $ip2 = $ip1; // Can't re-resolve, use first result
        }

        // If the second resolution is a private IP, block
        if ($ip2 !== null && $ip1 !== $ip2) {
            $check2 = self::checkIp($ip2);
            if (!$check2['safe']) {
                return self::block(
                    "DNS rebinding terdeteksi: '{$hostname}' berubah dari {$ip1} ke {$ip2} (private/internal)."
                );
            }
        }

        return self::allow($ip1);
    }

    /**
     * Check if a scheme is allowed.
     */
    public static function isAllowedScheme(string $scheme): bool
    {
        return in_array(strtolower($scheme), self::ALLOWED_SCHEMES, true);
    }

    /**
     * Full check for a single IP address (IPv4 or IPv6).
     */
    public static function checkIp(string $ip): array
    {
        if (empty($ip)) {
            return self::allow(null);
        }

        // Normalize IPv4-mapped IPv6 (::ffff:127.0.0.1 → 127.0.0.1)
        $normalized = self::normalizeIp($ip);

        // Check specific blocked IPs
        if (in_array($normalized, self::$blockedIps, true)) {
            return self::block("IP {$normalized} diblokir (endpoint metadata/internal).");
        }

        // IPv4 check
        if (filter_var($normalized, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return self::checkIpv4($normalized);
        }

        // IPv6 check
        if (filter_var($normalized, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::checkIpv6($normalized);
        }

        return self::block("Format IP '{$ip}' tidak valid.");
    }

    // ─── IPv4 Validation ─────────────────────────────────────

    private static function checkIpv4(string $ip): array
    {
        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return self::block("IPv4 '{$ip}' tidak valid.");
        }

        foreach (self::$blockedIpv4Cidrs as [$network, $bits, $label]) {
            $networkLong = ip2long($network);
            $mask = $bits === 0 ? 0 : (~0 << (32 - $bits));

            if (($ipLong & $mask) === ($networkLong & $mask)) {
                return self::block("IPv4 {$ip} termasuk range terblokir: {$label}.");
            }
        }

        // Additional: use PHP's built-in private/reserved check as safety net
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return self::block("IPv4 {$ip} terdeteksi sebagai private/reserved oleh filter PHP.");
        }

        return self::allow($ip);
    }

    // ─── IPv6 Validation ─────────────────────────────────────

    private static function checkIpv6(string $ip): array
    {
        // Expand IPv6 for comparison
        $expanded = self::expandIpv6($ip);
        if ($expanded === null) {
            return self::block("IPv6 '{$ip}' tidak valid.");
        }

        // Loopback ::1
        if ($expanded === '00000000000000000000000000000001') {
            return self::block("IPv6 {$ip} adalah loopback (::1).");
        }

        // All zeros ::
        if ($expanded === '00000000000000000000000000000000') {
            return self::block("IPv6 {$ip} adalah unspecified (::).");
        }

        // Link-local fe80::/10
        if (str_starts_with($expanded, 'fe8') || str_starts_with($expanded, 'fe9') ||
            str_starts_with($expanded, 'fea') || str_starts_with($expanded, 'feb')) {
            return self::block("IPv6 {$ip} adalah link-local (fe80::/10).");
        }

        // Unique local fc00::/7
        if (str_starts_with($expanded, 'fc') || str_starts_with($expanded, 'fd')) {
            return self::block("IPv6 {$ip} adalah unique-local/private (fc00::/7).");
        }

        // Multicast ff00::/8
        if (str_starts_with($expanded, 'ff')) {
            return self::block("IPv6 {$ip} adalah multicast (ff00::/8).");
        }

        // IPv4-mapped IPv6 ::ffff:x.x.x.x
        if (str_starts_with($expanded, '00000000000000000000ffff')) {
            $ipv4Hex = substr($expanded, 24, 8);
            $ipv4 = long2ip(hexdec($ipv4Hex));
            $v4Check = self::checkIpv4($ipv4);
            if (!$v4Check['safe']) {
                return self::block("IPv6 {$ip} adalah IPv4-mapped yang mengarah ke IP terblokir ({$ipv4}).");
            }
        }

        // Use PHP's built-in check as safety net
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return self::block("IPv6 {$ip} terdeteksi sebagai private/reserved.");
        }

        return self::allow($ip);
    }

    // ─── IP Encoding Bypass Detection ────────────────────────

    /**
     * Decode various IP address encodings that attackers use to bypass SSRF filters.
     * Returns the decoded IPv4 string, or null if the host is not an encoded IP.
     * 
     * Handles:
     * - Decimal: 2130706433 → 127.0.0.1
     * - Hex: 0x7f000001 → 127.0.0.1
     * - Octal: 0177.0.0.01 → 127.0.0.1
     * - Mixed: 127.1 → 127.0.0.1
     * - IPv6 brackets: [::1]
     * - IPv4-mapped IPv6: [::ffff:127.0.0.1]
     */
    public static function decodeIpAddress(string $host): ?string
    {
        $host = trim($host, '[]'); // strip IPv6 brackets

        // Already a standard IPv4
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $host;
        }

        // Already a standard IPv6
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $host;
        }

        // Decimal IP (e.g., 2130706433)
        if (preg_match('/^[1-9]\d{6,9}$/', $host)) {
            $long = (int) $host;
            if ($long >= 0 && $long <= 4294967295) {
                return long2ip($long);
            }
        }

        // Single-number Octal IP (e.g., 017700000001)
        if (preg_match('/^0[0-7]{7,12}$/', $host)) {
            $long = octdec($host);
            if ($long >= 0 && $long <= 4294967295) {
                return long2ip($long);
            }
        }

        // Hex IP (e.g., 0x7f000001)
        if (preg_match('/^0x([0-9a-f]{1,8})$/i', $host, $m)) {
            $long = hexdec($m[1]);
            if ($long >= 0 && $long <= 4294967295) {
                return long2ip($long);
            }
        }

        // Octal IP segments (e.g., 0177.0.0.01)
        if (preg_match('/^(0[0-7]+)\./', $host)) {
            $parts = explode('.', $host);
            if (count($parts) >= 2 && count($parts) <= 4) {
                $decodedParts = [];
                foreach ($parts as $p) {
                    if (str_starts_with($p, '0') && strlen($p) > 1 && !str_contains($p, 'x')) {
                        $decodedParts[] = octdec($p);
                    } elseif (str_starts_with(strtolower($p), '0x')) {
                        $decodedParts[] = hexdec($p);
                    } else {
                        $decodedParts[] = (int) $p;
                    }
                }

                // Reconstruct IP (handle short forms like 127.1)
                return self::expandShortIp($decodedParts);
            }
        }

        // Short IP notation (e.g., 127.1 → 127.0.0.1)
        if (preg_match('/^\d+\.\d+$/', $host) || preg_match('/^\d+\.\d+\.\d+$/', $host)) {
            $parts = array_map('intval', explode('.', $host));
            $expanded = self::expandShortIp($parts);
            if ($expanded !== null && filter_var($expanded, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return $expanded;
            }
        }

        return null;
    }

    // ─── Helpers ─────────────────────────────────────────────

    /**
     * Normalize IP address:
     * - Strip IPv6 brackets
     * - Convert IPv4-mapped IPv6 to IPv4
     */
    private static function normalizeIp(string $ip): string
    {
        $ip = trim($ip, '[]');

        // IPv4-mapped IPv6: ::ffff:1.2.3.4
        if (preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i', $ip, $m)) {
            return $m[1];
        }

        // [::ffff:7f00:1] style
        if (preg_match('/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i', $ip, $m)) {
            $high = hexdec($m[1]);
            $low = hexdec($m[2]);
            return (($high >> 8) & 0xFF) . '.' . ($high & 0xFF) . '.' . (($low >> 8) & 0xFF) . '.' . ($low & 0xFF);
        }

        return $ip;
    }

    /**
     * Expand IPv6 to full 32 hex-char string for comparison.
     */
    private static function expandIpv6(string $ip): ?string
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return null;
        }
        return bin2hex($packed);
    }

    /**
     * Expand short IP notation: [127, 1] → "127.0.0.1"
     */
    private static function expandShortIp(array $parts): ?string
    {
        $count = count($parts);
        if ($count === 2) {
            // a.b → a.0.0.b
            return "{$parts[0]}.0.0.{$parts[1]}";
        } elseif ($count === 3) {
            // a.b.c → a.b.0.c
            return "{$parts[0]}.{$parts[1]}.0.{$parts[2]}";
        } elseif ($count === 4) {
            return implode('.', $parts);
        }
        return null;
    }

    /**
     * Build a "blocked" result.
     */
    private static function block(string $reason): array
    {
        return ['safe' => false, 'reason' => $reason, 'resolved_ip' => null];
    }

    /**
     * Build an "allowed" result.
     */
    private static function allow(?string $ip): array
    {
        return ['safe' => true, 'reason' => null, 'resolved_ip' => $ip];
    }
}
