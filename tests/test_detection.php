<?php
require_once __DIR__ . '/../core/UrlParser.php';
require_once __DIR__ . '/../core/HeuristicEngine.php';
require_once __DIR__ . '/../core/WhoisLookup.php';
require_once __DIR__ . '/../core/ThreatIntel.php';
require_once __DIR__ . '/../core/ScoreEngine.php';

$config = require __DIR__ . '/../config/config.php';
$heuristic = new HeuristicEngine($config);
$scoreEngine = new ScoreEngine($config);

$testUrls = [
    'https://google.com' => 'safe',
    'http://bca.co.id.login-auth.xyz/update' => 'dangerous',
    'http://192.168.1.1/undangan.apk' => 'dangerous',
    'http://xn--gogle-pqa.com' => 'suspicious',
];

echo "=== LINKTESTER DETECTION ENGINE VERIFICATION ===" . PHP_EOL;

foreach ($testUrls as $url => $expectedMin) {
    $parsed = UrlParser::parse($url);
    $hRes = $heuristic->analyze($parsed);
    $eval = $scoreEngine->evaluate($hRes, ['findings' => [], 'penalty' => 0], ['findings' => [], 'penalty' => 0]);
    
    echo sprintf(
        "%-42s | Score: %3d | Verdict: %-10s | Findings: %d\n",
        $url,
        $eval['risk_score'],
        strtoupper($eval['verdict']),
        count($eval['findings'])
    );

    foreach ($eval['findings'] as $f) {
        echo "   -> [" . strtoupper($f['severity']) . "] " . $f['rule_name'] . ": " . $f['description'] . "\n";
    }
    echo PHP_EOL;
}
