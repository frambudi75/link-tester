<?php
/**
 * Scan Pipeline Integration Test - LinkTester
 * Verifies that the entire pipeline (SafeUrlResolver -> Analyzers -> RiskScorer -> Sanitizer) works seamlessly.
 */

require_once __DIR__ . '/../../core/Evidence.php';
require_once __DIR__ . '/../../core/SsrfGuard.php';
require_once __DIR__ . '/../../core/SafeUrlResolver.php';
require_once __DIR__ . '/../../core/analyzers/HeuristicAnalyzer.php';
require_once __DIR__ . '/../../core/analyzers/RedirectAnalyzer.php';
require_once __DIR__ . '/../../core/analyzers/ThreatIntelAnalyzer.php';
require_once __DIR__ . '/../../core/RiskScorer.php';
require_once __DIR__ . '/../../core/UrlSanitizer.php';

function testFullPipeline() {
    $config = require __DIR__ . '/../../config/config.php';

    $testUrl = 'https://xn--pple-43d.xyz/verify-account?token=SECRET_JWT_KEY_12345';

    // 1. Sanitize
    $sanitized = UrlSanitizer::redact($testUrl);
    assert(!str_contains($sanitized, 'SECRET_JWT_KEY_12345'), 'Token must be redacted');

    // 2. Parse
    $parsed = SafeUrlResolver::parseUrl($testUrl);
    assert($parsed['is_punycode'] === true, 'Punycode should be detected');

    // 3. Analyzers
    $heuristicAnalyzer = new HeuristicAnalyzer($config);
    $evidences = $heuristicAnalyzer->analyze($parsed);
    assert(count($evidences) > 0, 'Heuristic should produce evidence');

    // 4. Scorer
    $scorer = new RiskScorer($config);
    $result = $scorer->calculate($evidences);

    assert(isset($result['risk_score']), 'Result must have risk score');
    assert(isset($result['verdict']), 'Result must have verdict');
    assert(isset($result['verdict_label']), 'Result must have verdict label');
    assert(is_array($result['findings']), 'Findings must be an array');
    assert(count($result['findings']) > 0, 'Findings should not be empty');

    echo "  [PASS] testFullPipeline (Score: {$result['risk_score']}, Verdict: {$result['verdict_label']})\n";
}

testFullPipeline();
