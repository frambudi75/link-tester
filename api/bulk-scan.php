<?php
/**
 * Bulk Scan API Endpoint - LinkTester v2.0
 * 
 * Memindai beberapa URL sekaligus dengan Evidence-based detection & SSRF hardening.
 * POST: {"urls": ["url1", "url2", ...]}
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/../core/Database.php';
require_once __DIR__ . '/../core/SsrfGuard.php';
require_once __DIR__ . '/../core/SafeUrlResolver.php';
require_once __DIR__ . '/../core/Evidence.php';
require_once __DIR__ . '/../core/analyzers/HeuristicAnalyzer.php';
require_once __DIR__ . '/../core/analyzers/DomainAnalyzer.php';
require_once __DIR__ . '/../core/analyzers/RedirectAnalyzer.php';
require_once __DIR__ . '/../core/analyzers/ThreatIntelAnalyzer.php';
require_once __DIR__ . '/../core/analyzers/SslAnalyzer.php';
require_once __DIR__ . '/../core/analyzers/ContentAnalyzer.php';
require_once __DIR__ . '/../core/analyzers/DnsAnalyzer.php';
require_once __DIR__ . '/../core/RiskScorer.php';
require_once __DIR__ . '/../core/UrlSanitizer.php';
require_once __DIR__ . '/../core/RateLimiter.php';
require_once __DIR__ . '/../core/AuditLogger.php';

$config = require __DIR__ . '/../config/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Metode HTTP harus POST.']);
    exit;
}

$rawInput = file_get_contents('php://input');
$jsonData = json_decode($rawInput, true);
$urls = $jsonData['urls'] ?? [];

if (!is_array($urls) || empty($urls)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Parameter "urls" (array) diperlukan.']);
    exit;
}

$maxUrls = $config['bulk_scan']['max_urls'] ?? 10;
if (count($urls) > $maxUrls) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => "Maksimal {$maxUrls} URL per batch."]);
    exit;
}

// Rate Limiting
if (!empty($config['rate_limit']['enabled'])) {
    $limiter = new RateLimiter(
        $config['rate_limit']['max_requests'] ?? 20,
        $config['rate_limit']['window_sec'] ?? 60
    );
    $clientIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $rateCheck = $limiter->check(trim(explode(',', $clientIp)[0]));

    if (!$rateCheck['allowed']) {
        http_response_code(429);
        echo json_encode([
            'success' => false,
            'error'   => 'Batas scan tercapai. Coba lagi dalam ' . $rateCheck['retry_after'] . ' detik.',
        ]);
        exit;
    }
}

$scorer = new RiskScorer($config);
$heuristicAnalyzer = new HeuristicAnalyzer($config);
$threatAnalyzer = new ThreatIntelAnalyzer($config);

$results = [];

foreach ($urls as $idx => $rawUrl) {
    $rawUrl = trim($rawUrl);
    if (empty($rawUrl)) {
        $results[] = ['url' => $rawUrl, 'success' => false, 'error' => 'URL kosong.'];
        continue;
    }

    $targetUrl = SafeUrlResolver::normalize($rawUrl);

    if (!SafeUrlResolver::isValidUrl($targetUrl)) {
        $results[] = ['url' => $rawUrl, 'success' => false, 'error' => 'Format URL tidak valid.'];
        continue;
    }

    $startTime = microtime(true);

    try {
        // Trace Redirects with SSRF validation at every hop
        $redirectInfo = SafeUrlResolver::traceRedirects($targetUrl);
        if (!empty($redirectInfo['error'])) {
            $results[] = [
                'url'          => $rawUrl,
                'success'      => false,
                'error'        => $redirectInfo['error'],
                'ssrf_blocked' => true,
            ];
            continue;
        }

        $finalUrl = $redirectInfo['final_url'];
        $parsedFinal = SafeUrlResolver::parseUrl($finalUrl);
        $htmlBody = $redirectInfo['html_body'] ?? '';

        // Collect Evidences
        $evidences = [];
        $evidences = array_merge($evidences, $heuristicAnalyzer->analyze($parsedFinal));
        $evidences = array_merge($evidences, DomainAnalyzer::analyze($parsedFinal['domain']));
        $evidences = array_merge($evidences, RedirectAnalyzer::analyze($redirectInfo));
        $evidences = array_merge($evidences, $threatAnalyzer->analyze($finalUrl));

        if (!empty($config['ssl_check']['enabled'])) {
            $sslRes = SslAnalyzer::analyze($finalUrl);
            $evidences = array_merge($evidences, $sslRes['evidences']);
        }

        if (!empty($config['content_analysis']['enabled']) && !empty($htmlBody)) {
            $contentRes = ContentAnalyzer::analyze($htmlBody, $finalUrl);
            $evidences = array_merge($evidences, $contentRes['evidences']);
        }

        if (!empty($config['dns_analysis']['enabled'])) {
            $dnsRes = DnsAnalyzer::analyze($parsedFinal['domain']);
            $evidences = array_merge($evidences, $dnsRes['evidences']);
        }

        // Risk Scoring
        $scoring = $scorer->calculate($evidences);
        $execTime = round((microtime(true) - $startTime) * 1000, 2);

        $results[] = [
            'url'               => $rawUrl,
            'success'           => true,
            'original_url'      => $targetUrl,
            'final_url'         => $finalUrl,
            'domain'            => $parsedFinal['domain'],
            'risk_score'        => $scoring['risk_score'],
            'verdict'           => $scoring['verdict'],
            'verdict_label'     => $scoring['verdict_label'],
            'verdict_color'     => $scoring['verdict_color'],
            'is_redirected'     => $redirectInfo['is_redirected'],
            'redirect_count'    => $redirectInfo['redirect_count'],
            'findings_count'    => count($scoring['findings']),
            'execution_time_ms' => $execTime,
        ];

        // Audit log
        if (!empty($config['audit_log']['enabled'])) {
            AuditLogger::logScan([
                'url'       => UrlSanitizer::redact($targetUrl),
                'final_url' => UrlSanitizer::redact($finalUrl),
                'verdict'   => $scoring['verdict'],
                'score'     => $scoring['risk_score'],
                'exec_time' => $execTime,
                'cached'    => false,
            ]);
        }
    } catch (Exception $e) {
        $results[] = ['url' => $rawUrl, 'success' => false, 'error' => $e->getMessage()];
    }
}

echo json_encode([
    'success' => true,
    'total'   => count($urls),
    'results' => $results,
]);
