<?php
/**
 * LinkTester Test Suite Runner
 * Runs all Unit, Security, and Integration tests.
 * 
 * Usage: php tests/run_tests.php
 */

echo "====================================================\n";
echo "  LinkTester v2.0 - Automated Test Suite\n";
echo "====================================================\n\n";

$tests = [
    'Unit Tests' => [
        'Evidence'          => __DIR__ . '/Unit/EvidenceTest.php',
        'UrlSanitizer'      => __DIR__ . '/Unit/UrlSanitizerTest.php',
        'HeuristicAnalyzer' => __DIR__ . '/Unit/HeuristicAnalyzerTest.php',
        'RiskScorer'        => __DIR__ . '/Unit/RiskScorerTest.php',
    ],
    'Security Tests' => [
        'SsrfGuard'         => __DIR__ . '/Security/SsrfGuardTest.php',
        'SsrfBypassVectors' => __DIR__ . '/Security/SsrfBypassTest.php',
        'RedirectChain'     => __DIR__ . '/Security/RedirectChainTest.php',
    ],
    'Integration Tests' => [
        'ScanPipeline'      => __DIR__ . '/Integration/ScanPipelineTest.php',
    ],
];

$totalTests = 0;
$totalPassed = 0;
$totalFailed = 0;

foreach ($tests as $suiteName => $suiteFiles) {
    echo "▶ {$suiteName}\n";
    foreach ($suiteFiles as $name => $path) {
        $totalTests++;
        echo "  Testing {$name}...\n";
        try {
            require_once $path;
            $totalPassed++;
        } catch (Throwable $e) {
            $totalFailed++;
            echo "  [FAIL] {$name}: " . $e->getMessage() . " on line " . $e->getLine() . "\n";
        }
    }
    echo "\n";
}

echo "====================================================\n";
echo "  Results: {$totalPassed}/{$totalTests} passed";
if ($totalFailed > 0) {
    echo " ({$totalFailed} failed)\n";
    echo "====================================================\n";
    exit(1);
} else {
    echo " (All tests passed!)\n";
    echo "====================================================\n";
    exit(0);
}
