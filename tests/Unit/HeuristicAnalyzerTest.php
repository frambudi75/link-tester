<?php
/**
 * Heuristic Analyzer Test - LinkTester
 */

require_once __DIR__ . '/../../core/Evidence.php';
require_once __DIR__ . '/../../core/SafeUrlResolver.php';
require_once __DIR__ . '/../../core/analyzers/HeuristicAnalyzer.php';

function testHeuristicAnalyzer() {
    $analyzer = new HeuristicAnalyzer();

    // Test IP as host
    $parsedIp = SafeUrlResolver::parseUrl('http://192.0.2.1/login');
    $evidences = $analyzer->analyze($parsedIp);
    $signals = array_column(array_map(fn($e) => $e->toArray(), $evidences), 'signal');
    assert(in_array('ip_as_host', $signals, true), 'Should detect IP as host');

    // Test Subdomain deception
    $parsedSpoof = SafeUrlResolver::parseUrl('https://paypal.verification-portal.com/login');
    $evidencesSpoof = $analyzer->analyze($parsedSpoof);
    $signalsSpoof = array_column(array_map(fn($e) => $e->toArray(), $evidencesSpoof), 'signal');
    assert(in_array('subdomain_deception', $signalsSpoof, true), 'Should detect subdomain deception');

    // Test Executable file
    $parsedApk = SafeUrlResolver::parseUrl('https://example.com/undangan-nikah.apk');
    $evidencesApk = $analyzer->analyze($parsedApk);
    $signalsApk = array_column(array_map(fn($e) => $e->toArray(), $evidencesApk), 'signal');
    assert(in_array('dangerous_file_ext', $signalsApk, true), 'Should detect dangerous APK file extension');

    echo "  [PASS] testHeuristicAnalyzer\n";
}

testHeuristicAnalyzer();
