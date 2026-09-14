<?php
/**
 * URL Sanitizer - LinkTester
 * 
 * Membersihkan URL sebelum disimpan ke database / log untuk menjaga privasi pengguna.
 * Menghapus/menyamarkan parameter sensitif seperti API key, token otentikasi, password,
 * sesi, dan OTP (PII / credential protection).
 */

class UrlSanitizer
{
    /**
     * Daftar parameter query sensitif yang wajib di-redact.
     */
    private static array $sensitiveParams = [
        'token', 'key', 'api_key', 'apikey', 'secret',
        'password', 'pass', 'pwd', 'auth', 'access_token',
        'refresh_token', 'session', 'sessionid', 'sid',
        'otp', 'code', 'reset', 'verify', 'signature',
        'sig', 'state', 'client_secret', 'user_token'
    ];

    /**
     * Sensor parameter sensitif di dalam URL.
     * Contoh: https://example.com/login?token=xyz123&user=admin
     *      → https://example.com/login?token=[REDACTED]&user=admin
     * 
     * @param string $url URL asli
     * @return string URL setelah di-redact
     */
    public static function redact(string $url): string
    {
        $parsed = parse_url($url);
        if (!$parsed || empty($parsed['query'])) {
            return $url;
        }

        parse_str($parsed['query'], $queryParams);
        $modified = false;

        foreach ($queryParams as $key => $val) {
            $keyLower = strtolower($key);
            if (in_array($keyLower, self::$sensitiveParams, true)) {
                $queryParams[$key] = '[REDACTED]';
                $modified = true;
            }
        }

        if (!$modified) {
            return $url;
        }

        // Reconstruct URL
        $scheme   = isset($parsed['scheme']) ? $parsed['scheme'] . '://' : '';
        $host     = $parsed['host'] ?? '';
        $port     = isset($parsed['port']) ? ':' . $parsed['port'] : '';
        $user     = isset($parsed['user']) ? $parsed['user'] : '';
        $pass     = isset($parsed['pass']) ? ':[REDACTED]' : '';
        $pass     = ($user || $pass) ? "$pass@" : '';
        $path     = $parsed['path'] ?? '';
        $query    = '?' . http_build_query($queryParams);
        $fragment = isset($parsed['fragment']) ? '#' . $parsed['fragment'] : '';

        return "$scheme$user$pass$host$port$path$query$fragment";
    }

    /**
     * Hitung hash SHA-256 URL untuk deduplikasi tanpa menyimpan raw token.
     * 
     * @param string $url
     * @return string
     */
    public static function hash(string $url): string
    {
        return hash('sha256', strtolower(trim($url)));
    }
}
