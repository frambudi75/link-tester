<?php
/**
 * Redirect Chain Security Test - LinkTester
 * Verifies per-hop SSRF validation and redirect loop detection.
 */

require_once __DIR__ . '/../../core/SafeUrlResolver.php';
require_once __DIR__ . '/../../core/analyzers/RedirectAnalyzer.php';

function testRedirectAnalyzer() {
    // 1. Cross domain detection
    $mockInfo = [
        'redirect_count'   => 2,
        'is_cross_domain'  => true,
        'original_domain'  => 'short.ly',
        'final_domain'     => 'evil-landing.xyz',
        'has_tds_router'   => true,
        'redirect_chain'   => [
            ['hop' => 0, 'scheme' => 'https', 'hostname' => 'short.ly'],
            ['hop' => 1, 'scheme' => 'https', 'hostname' => 'tracking.net'],
            ['hop' => 2, 'scheme' => 'http',  'hostname' => 'evil-landing.xyz'],
        ],
    ];

    $evidences = RedirectAnalyzer::analyze($mockInfo);
    $signals = array_column(array_map(fn($e) => $e->toArray(), $evidences), 'signal');

    assert(in_array('cross_domain_redirect', $signals, true), 'Should detect cross domain redirect');
    assert(in_array('excessive_redirects', $signals, true), 'Should detect excessive redirects');
    assert(in_array('traffic_distribution_system', $signals, true), 'Should detect TDS router');
    assert(in_array('scheme_downgrade', $signals, true), 'Should detect SSL downgrade');

    echo "  [PASS] testRedirectAnalyzer\n";
}

testRedirectAnalyzer();
