<?php
/**
 * URL Sanitizer Test - LinkTester
 */

require_once __DIR__ . '/../../core/UrlSanitizer.php';

function testUrlRedaction() {
    $rawUrl = 'https://example.com/reset-password?token=secret12345&user=john_doe&key=api999';
    $redacted = UrlSanitizer::redact($rawUrl);

    assert(!str_contains($redacted, 'secret12345'), 'Token value should be redacted');
    assert(!str_contains($redacted, 'api999'), 'API key value should be redacted');
    assert(str_contains($redacted, 'user=john_doe'), 'Non-sensitive user parameter should remain intact');
    assert(str_contains($redacted, 'token=%5BREDACTED%5D') || str_contains($redacted, 'token=[REDACTED]'), 'Token should show [REDACTED]');

    $hash1 = UrlSanitizer::hash('https://example.com/test');
    $hash2 = UrlSanitizer::hash('HTTPS://EXAMPLE.COM/TEST');
    assert($hash1 === $hash2, 'Hashes should be normalized and identical');

    echo "  [PASS] testUrlRedaction\n";
}

testUrlRedaction();
