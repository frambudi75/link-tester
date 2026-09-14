<?php
/**
 * SSRF Guard Security Test - LinkTester
 * Verifies core SSRF protection against private IP ranges, loopback, metadata endpoints, and non-HTTP schemes.
 */

require_once __DIR__ . '/../../core/SsrfGuard.php';

function testSsrfGuard() {
    // 1. Loopback IPv4
    assert(SsrfGuard::isBlockedIp('127.0.0.1') === true, '127.0.0.1 must be blocked');
    assert(SsrfGuard::isBlockedIp('127.12.34.56') === true, '127.x.x.x must be blocked');

    // 2. Private 10.0.0.0/8
    assert(SsrfGuard::isBlockedIp('10.0.0.1') === true, '10.0.0.1 must be blocked');
    assert(SsrfGuard::isBlockedIp('10.255.255.255') === true, '10.255.255.255 must be blocked');

    // 3. Private 172.16.0.0/12
    assert(SsrfGuard::isBlockedIp('172.16.0.1') === true, '172.16.0.1 must be blocked');
    assert(SsrfGuard::isBlockedIp('172.31.255.255') === true, '172.31.255.255 must be blocked');

    // 4. Private 192.168.0.0/16
    assert(SsrfGuard::isBlockedIp('192.168.1.1') === true, '192.168.1.1 must be blocked');
    assert(SsrfGuard::isBlockedIp('192.168.0.254') === true, '192.168.0.254 must be blocked');

    // 5. Cloud Metadata IP (169.254.169.254)
    assert(SsrfGuard::isBlockedIp('169.254.169.254') === true, 'AWS/GCP metadata IP must be blocked');

    // 6. IPv6 Loopback & Private
    assert(SsrfGuard::isBlockedIp('::1') === true, 'IPv6 loopback ::1 must be blocked');
    assert(SsrfGuard::isBlockedIp('fc00::1') === true, 'IPv6 ULA must be blocked');
    assert(SsrfGuard::isBlockedIp('fe80::1') === true, 'IPv6 link-local must be blocked');

    // 7. Public Safe IPs (Cloudflare DNS, Google DNS)
    assert(SsrfGuard::isBlockedIp('1.1.1.1') === false, '1.1.1.1 must NOT be blocked');
    assert(SsrfGuard::isBlockedIp('8.8.8.8') === false, '8.8.8.8 must NOT be blocked');

    // 8. Scheme validation
    assert(SsrfGuard::isAllowedScheme('http') === true, 'http must be allowed');
    assert(SsrfGuard::isAllowedScheme('https') === true, 'https must be allowed');
    assert(SsrfGuard::isAllowedScheme('file') === false, 'file:// scheme must be rejected');
    assert(SsrfGuard::isAllowedScheme('gopher') === false, 'gopher:// scheme must be rejected');
    assert(SsrfGuard::isAllowedScheme('dict') === false, 'dict:// scheme must be rejected');
    assert(SsrfGuard::isAllowedScheme('ftp') === false, 'ftp:// scheme must be rejected');

    echo "  [PASS] testSsrfGuard\n";
}

testSsrfGuard();
