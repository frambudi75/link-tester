<?php
/**
 * SSRF Bypass Techniques Test - LinkTester
 * Tests 15+ known SSRF bypass and obfuscation vectors against SsrfGuard::validateTarget().
 */

require_once __DIR__ . '/../../core/SsrfGuard.php';

function testSsrfBypassVectors() {
    $bypassVectors = [
        'http://127.0.0.1/admin',
        'http://127.1/admin',
        'http://127.0.1/',
        'http://0.0.0.0/',
        'http://0x7f000001/',             // Hex IP for 127.0.0.1
        'http://2130706433/',             // Decimal IP for 127.0.0.1
        'http://017700000001/',           // Octal IP for 127.0.0.1
        'http://[::1]/',                  // IPv6 loopback
        'http://[::ffff:127.0.0.1]/',     // IPv4-mapped IPv6
        'http://[0:0:0:0:0:ffff:127.0.0.1]/',
        'http://localhost/',
        'http://localhost:8080/',
        'http://169.254.169.254/latest/meta-data/', // AWS metadata
        'http://metadata.google.internal/computeMetadata/v1/', // GCP metadata
        'http://192.168.1.1/router',
        'http://10.0.0.1/',
        'http://172.16.0.1/',
        'file:///etc/passwd',
        'gopher://127.0.0.1:6379/_INFO',
        'dict://127.0.0.1:11211/stat',
    ];

    $passedCount = 0;

    foreach ($bypassVectors as $url) {
        $result = SsrfGuard::validateTarget($url);
        assert(
            $result->isBlocked === true,
            "SSRF Bypass vector was NOT blocked: {$url} (Reason: {$result->reason})"
        );
        $passedCount++;
    }

    echo "  [PASS] testSsrfBypassVectors ({$passedCount} bypass vectors blocked successfully)\n";
}

testSsrfBypassVectors();
