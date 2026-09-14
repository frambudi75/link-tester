<?php
/**
 * Scan API Endpoint - LinkTester v2.0
 * 
 * Pipeline Arsitektur Baru: Evidence-Based Threat Detection
 * SafeUrlResolver (SSRF Guarded) -> Analyzers -> Evidence Layer -> RiskScorer -> UrlSanitizer -> DB
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

// 1. Rate Limiting
if (!empty($config['rate_limit']['enabled'])) {
    $limiter = new RateLimiter(
        $config['rate_limit']['max_requests'] ?? 20,
        $config['rate_limit']['window_sec'] ?? 60
    );
    $clientIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $clientIp = explode(',', $clientIp)[0];
    $rateCheck = $limiter->check(trim($clientIp));

    if (!$rateCheck['allowed']) {
        http_response_code(429);
        header('Retry-After: ' . $rateCheck['retry_after']);
        echo json_encode([
            'success'     => false,
            'error'       => 'Batas scan tercapai. Coba lagi dalam ' . $rateCheck['retry_after'] . ' detik.',
            'retry_after' => $rateCheck['retry_after'],
        ]);
        exit;
    }
}

// 2. Parse Input URL
$rawInput = file_get_contents('php://input');
$jsonData = json_decode($rawInput, true);
$targetUrl = trim($_POST['url'] ?? ($jsonData['url'] ?? ''));

if (empty($targetUrl)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Parameter URL tidak boleh kosong.']);
    exit;
}

$targetUrl = SafeUrlResolver::normalize($targetUrl);

if (!SafeUrlResolver::isValidUrl($targetUrl)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Format URL tidak valid. Pastikan format diawali dengan http:// atau https://']);
    exit;
}

$startTime = microtime(true);
$urlHash = UrlSanitizer::hash($targetUrl);
$db = Database::getConnection();
$forceFresh = !empty($_POST['fresh']) || !empty($jsonData['fresh']);

// 3. Periksa Cache Database
if ($db && !$forceFresh) {
    try {
        $cacheHours = $config['app']['cache_hours'] ?? 6;
        $stmt = $db->prepare('SELECT * FROM scans WHERE url_hash = :hash AND created_at >= NOW() - INTERVAL :hours HOUR ORDER BY id DESC LIMIT 1');
        $stmt->bindValue(':hash', $urlHash, PDO::PARAM_STR);
        $stmt->bindValue(':hours', $cacheHours, PDO::PARAM_INT);
        $stmt->execute();
        $cached = $stmt->fetch();

        if ($cached) {
            $detStmt = $db->prepare('SELECT category, rule_name as signal_name, severity, score_impact as weight, description FROM scan_details WHERE scan_id = :scan_id');
            $detStmt->execute([':scan_id' => $cached['id']]);
            $cachedFindings = $detStmt->fetchAll();

            $cachedParsed = SafeUrlResolver::parseUrl($cached['final_url']);
            $executionTime = round((microtime(true) - $startTime) * 1000, 2);

            echo json_encode([
                'success'           => true,
                'cached'            => true,
                'scan_id'           => (int) $cached['id'],
                'original_url'      => $cached['original_url'],
                'final_url'         => $cached['final_url'],
                'domain'            => $cached['domain'],
                'subdomain'         => $cachedParsed['subdomain'],
                'ip_address'        => $cached['ip_address'],
                'risk_score'        => (int) $cached['risk_score'],
                'verdict'           => $cached['verdict'],
                'is_redirected'     => (bool) $cached['is_redirected'],
                'redirect_count'    => (int) $cached['redirect_count'],
                'domain_age_days'   => $cached['domain_age_days'] !== null ? (int) $cached['domain_age_days'] : null,
                'ssl_info'          => [
                    'ssl_valid'  => $cached['ssl_valid'] !== null ? (bool) $cached['ssl_valid'] : null,
                    'ssl_issuer' => $cached['ssl_issuer'] ?? null,
                ],
                'content_info'      => [
                    'has_login_form'    => (bool) ($cached['has_login_form'] ?? false),
                    'has_hidden_iframe' => (bool) ($cached['has_hidden_iframe'] ?? false),
                ],
                'dns_info'          => [
                    'has_spf'   => $cached['has_spf'] !== null ? (bool) $cached['has_spf'] : null,
                    'has_dmarc' => $cached['has_dmarc'] !== null ? (bool) $cached['has_dmarc'] : null,
                ],
                'findings'          => $cachedFindings,
                'recommendations'   => [
                    'Hasil scan diambil dari cache (6 jam terakhir).',
                    'Kirim parameter fresh=1 jika ingin menjalankan pemindaian ulang secara langsung.'
                ],
                'execution_time_ms' => $executionTime,
                'created_at'        => $cached['created_at'],
            ]);
            exit;
        }
    } catch (PDOException $e) {
        error_log('Cache query error: ' . $e->getMessage());
    }
}

// 4. Safe URL Resolution & Redirect Tracing dengan SSRF Guard di setiap hop
$redirectInfo = SafeUrlResolver::traceRedirects($targetUrl);

if (!empty($redirectInfo['error'])) {
    http_response_code(403);
    echo json_encode([
        'success' => false,
        'error'   => $redirectInfo['error'],
        'ssrf_blocked' => true,
    ]);
    exit;
}

$finalUrl = $redirectInfo['final_url'];
$parsedFinal = SafeUrlResolver::parseUrl($finalUrl);
$htmlBody = $redirectInfo['html_body'] ?? '';

// 5. Evidence Collection Pipeline (All Analyzers emit Evidence[])
$evidences = [];

// A. Heuristic Analyzer
$heuristicAnalyzer = new HeuristicAnalyzer($config);
$evidences = array_merge($evidences, $heuristicAnalyzer->analyze($parsedFinal));

// B. Domain Analyzer (WHOIS / RDAP)
$evidences = array_merge($evidences, DomainAnalyzer::analyze($parsedFinal['domain']));

// C. Redirect Analyzer
$evidences = array_merge($evidences, RedirectAnalyzer::analyze($redirectInfo));

// D. Threat Intelligence Analyzer (URLhaus, GSB, VT, PhishTank)
$threatAnalyzer = new ThreatIntelAnalyzer($config);
$evidences = array_merge($evidences, $threatAnalyzer->analyze($finalUrl));

// E. SSL Analyzer
$sslResult = ['evidences' => [], 'info' => []];
if (!empty($config['ssl_check']['enabled'])) {
    $sslResult = SslAnalyzer::analyze($finalUrl);
    $evidences = array_merge($evidences, $sslResult['evidences']);
}

// F. Content Analyzer (HTML inspect)
$contentResult = ['evidences' => [], 'details' => []];
if (!empty($config['content_analysis']['enabled']) && !empty($htmlBody)) {
    $contentResult = ContentAnalyzer::analyze($htmlBody, $finalUrl);
    $evidences = array_merge($evidences, $contentResult['evidences']);
}

// G. DNS Analyzer
$dnsResult = ['evidences' => [], 'details' => []];
if (!empty($config['dns_analysis']['enabled'])) {
    $dnsResult = DnsAnalyzer::analyze($parsedFinal['domain']);
    $evidences = array_merge($evidences, $dnsResult['evidences']);
}

// 6. Cek Reputasi Domain Lokal (Whitelist / Blacklist)
$reputationDb = null;
if ($db) {
    try {
        $repStmt = $db->prepare('SELECT * FROM domain_reputation WHERE domain = :domain LIMIT 1');
        $repStmt->execute([':domain' => $parsedFinal['domain']]);
        $reputationDb = $repStmt->fetch() ?: null;
    } catch (PDOException $e) {
        error_log('Reputation lookup error: ' . $e->getMessage());
    }
}

// 7. Risk Scoring (Sentralisasi penilaian pada RiskScorer)
$scorer = new RiskScorer($config);
$scoring = $scorer->calculate($evidences, $reputationDb);

$riskScore       = $scoring['risk_score'];
$verdict         = $scoring['verdict'];
$verdictLabel    = $scoring['verdict_label'];
$verdictColor    = $scoring['verdict_color'];
$findings        = $scoring['findings'];
$recommendations = $scoring['recommendations'];

// 8. Cari domain age dari evidences
$domainAgeDays = null;
foreach ($evidences as $ev) {
    if ($ev->signal === 'domain_age_days') {
        $domainAgeDays = (int) $ev->value;
        break;
    }
}

// 9. Sanitasi URL sebelum persistensi DB
$sanitizedOriginalUrl = UrlSanitizer::redact($targetUrl);
$sanitizedFinalUrl    = UrlSanitizer::redact($finalUrl);

// 10. Simpan ke Database
$scanId = null;
if ($db) {
    try {
        $insert = $db->prepare('
            INSERT INTO scans 
            (url_hash, original_url, final_url, domain, ip_address, risk_score, verdict, 
             is_redirected, redirect_count, domain_age_days,
             ssl_valid, ssl_issuer, has_login_form, has_hidden_iframe, has_spf, has_dmarc)
            VALUES 
            (:url_hash, :original_url, :final_url, :domain, :ip_address, :risk_score, :verdict, 
             :is_redirected, :redirect_count, :domain_age_days,
             :ssl_valid, :ssl_issuer, :has_login_form, :has_hidden_iframe, :has_spf, :has_dmarc)
        ');

        $sslInfo = $sslResult['info'] ?? [];
        $contentDetails = $contentResult['details'] ?? [];
        $dnsDetails = $dnsResult['details'] ?? [];

        $insert->execute([
            ':url_hash'        => $urlHash,
            ':original_url'    => $sanitizedOriginalUrl,
            ':final_url'       => $sanitizedFinalUrl,
            ':domain'          => $parsedFinal['domain'],
            ':ip_address'      => $redirectInfo['ip_address'],
            ':risk_score'      => $riskScore,
            ':verdict'         => $verdict,
            ':is_redirected'   => $redirectInfo['is_redirected'] ? 1 : 0,
            ':redirect_count'  => $redirectInfo['redirect_count'],
            ':domain_age_days' => $domainAgeDays,
            ':ssl_valid'       => isset($sslInfo['ssl_valid']) ? ($sslInfo['ssl_valid'] ? 1 : 0) : null,
            ':ssl_issuer'      => $sslInfo['ssl_issuer'] ?? null,
            ':has_login_form'  => !empty($contentDetails['has_login_form']) ? 1 : 0,
            ':has_hidden_iframe' => !empty($contentDetails['has_hidden_iframe']) ? 1 : 0,
            ':has_spf'         => isset($dnsDetails['has_spf']) ? ($dnsDetails['has_spf'] ? 1 : 0) : null,
            ':has_dmarc'       => isset($dnsDetails['has_dmarc']) ? ($dnsDetails['has_dmarc'] ? 1 : 0) : null,
        ]);

        $scanId = (int) $db->lastInsertId();

        if (!empty($findings)) {
            $detailInsert = $db->prepare('
                INSERT INTO scan_details (scan_id, category, rule_name, severity, score_impact, description)
                VALUES (:scan_id, :category, :rule_name, :severity, :score_impact, :description)
            ');

            foreach ($findings as $f) {
                $detailInsert->execute([
                    ':scan_id'      => $scanId,
                    ':category'     => $f['category'] ?? 'heuristic',
                    ':rule_name'    => $f['signal'] ?? 'UNKNOWN',
                    ':severity'     => $f['severity'] ?? 'low',
                    ':score_impact' => (int) ($f['weight'] ?? 0),
                    ':description'  => $f['explanation']['detail'] ?? '',
                ]);
            }
        }
    } catch (PDOException $e) {
        error_log('Database insert error: ' . $e->getMessage());
        // Fallback insert jika kolom v2.0 belum dimigrasi di database server
        try {
            $fallback = $db->prepare('
                INSERT INTO scans 
                (url_hash, original_url, final_url, domain, ip_address, risk_score, verdict, 
                 is_redirected, redirect_count, domain_age_days)
                VALUES 
                (:url_hash, :original_url, :final_url, :domain, :ip_address, :risk_score, :verdict, 
                 :is_redirected, :redirect_count, :domain_age_days)
            ');
            $fallback->execute([
                ':url_hash'        => $urlHash,
                ':original_url'    => $sanitizedOriginalUrl,
                ':final_url'       => $sanitizedFinalUrl,
                ':domain'          => $parsedFinal['domain'],
                ':ip_address'      => $redirectInfo['ip_address'],
                ':risk_score'      => $riskScore,
                ':verdict'         => $verdict,
                ':is_redirected'   => $redirectInfo['is_redirected'] ? 1 : 0,
                ':redirect_count'  => $redirectInfo['redirect_count'],
                ':domain_age_days' => $domainAgeDays,
            ]);
            $scanId = (int) $db->lastInsertId();
        } catch (PDOException $e2) {
            error_log('Fallback database insert error: ' . $e2->getMessage());
        }
    }
}

$executionTime = round((microtime(true) - $startTime) * 1000, 2);

// 10. Audit Logging
if (!empty($config['audit_log']['enabled'])) {
    AuditLogger::logScan([
        'url'       => $sanitizedOriginalUrl,
        'final_url' => $sanitizedFinalUrl,
        'verdict'   => $verdict,
        'score'     => $riskScore,
        'exec_time' => $executionTime,
        'cached'    => false,
    ]);
}

// 11. Structured Signals Summary (Investigation View)
$signalsSummary = [
    'domain' => [
        'name'        => $parsedFinal['domain'],
        'age_days'    => $domainAgeDays,
        'tld'         => $parsedFinal['tld'],
        'is_ip'       => $parsedFinal['is_ip'],
        'is_punycode' => $parsedFinal['is_punycode'],
    ],
    'redirect' => [
        'count'          => $redirectInfo['redirect_count'],
        'is_cross_domain'=> $redirectInfo['is_cross_domain'],
        'has_tds'        => $redirectInfo['has_tds_router'],
        'hops'           => count($redirectInfo['redirect_chain']),
    ],
    'ssl' => $sslResult['info'] ?? [],
    'content' => $contentResult['details'] ?? [],
    'dns' => $dnsResult['details'] ?? [],
];

// Screenshot URL
$screenshotUrl = null;
if (!empty($config['screenshot']['enabled'])) {
    $screenshotUrl = ($config['screenshot']['base_url'] ?? 'https://image.thum.io/get/') . urlencode($finalUrl);
}

// 12. Output Rich Response
echo json_encode([
    'success'           => true,
    'cached'            => false,
    'scan_id'           => $scanId,
    'original_url'      => $targetUrl,
    'final_url'         => $finalUrl,
    'domain'            => $parsedFinal['domain'],
    'subdomain'         => $parsedFinal['subdomain'],
    'ip_address'        => $redirectInfo['ip_address'],
    'risk_score'        => $riskScore,
    'verdict'           => $verdict,
    'verdict_label'     => $verdictLabel,
    'verdict_color'     => $verdictColor,
    'is_redirected'     => $redirectInfo['is_redirected'],
    'redirect_count'    => $redirectInfo['redirect_count'],
    'redirect_chain'    => $redirectInfo['redirect_chain'],
    'signals'           => $signalsSummary,
    'ssl_info'          => $sslResult['info'] ?? [],
    'content_info'      => $contentResult['details'] ?? [],
    'dns_info'          => $dnsResult['details'] ?? [],
    'screenshot_url'    => $screenshotUrl,
    'findings'          => $findings,
    'recommendations'   => $recommendations,
    'execution_time_ms' => $executionTime,
    'created_at'        => date('Y-m-d H:i:s'),
]);
