<?php
/**
 * Risk Scorer Test - LinkTester
 */

require_once __DIR__ . '/../../core/Evidence.php';
require_once __DIR__ . '/../../core/RiskScorer.php';

function testRiskScorer() {
    $scorer = new RiskScorer();

    // 1. Clean Evidence test
    $cleanEvidences = [
        Evidence::create('domain_established', true, 'domain', ['years' => 5], 0.9),
        Evidence::create('dns_full_config', true, 'dns', [], 0.9),
    ];
    $cleanResult = $scorer->calculate($cleanEvidences);
    assert($cleanResult['risk_score'] === 0, 'Clean signals should produce 0 risk score');
    assert($cleanResult['verdict'] === 'clean', 'Verdict should be clean');

    // 2. High Risk Evidence test
    $highRiskEvidences = [
        Evidence::create('punycode_detected', true, 'heuristic', [], 0.95),
        Evidence::create('subdomain_deception', true, 'heuristic', [], 0.9),
    ];
    $highResult = $scorer->calculate($highRiskEvidences);
    assert($highResult['risk_score'] >= 66, 'Punycode + deception should produce high risk score');
    assert(in_array($highResult['verdict'], ['high_risk', 'critical'], true), 'Verdict should be high_risk or critical');

    // 3. Critical Signal (URLhaus hit)
    $critEvidences = [
        Evidence::create('urlhaus_hit', true, 'threat_intel', [], 1.0),
    ];
    $critResult = $scorer->calculate($critEvidences);
    assert($critResult['risk_score'] >= 86, 'Critical hit must produce >= 86 score');
    assert($critResult['verdict'] === 'critical', 'Critical signal must produce critical verdict');

    echo "  [PASS] testRiskScorer\n";
}

testRiskScorer();
