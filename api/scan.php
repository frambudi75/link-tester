<?php
/**
 * Scan API Endpoint - LinkTester
 * Menerima URL, memproses pipeline deteksi, menyimpan ke database, dan mengembalikan hasil JSON.
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/../core/Database.php';
require_once __DIR__ . '/../core/UrlParser.php';
require_once __DIR__ . '/../core/HeuristicEngine.php';
require_once __DIR__ . '/../core/WhoisLookup.php';
require_once __DIR__ . '/../core/ThreatIntel.php';
require_once __DIR__ . '/../core/ScoreEngine.php';

$config = require __DIR__ . '/../config/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Metode HTTP harus POST.']);
    exit;
}

// Ambil input baik dari form-data maupun JSON body
$rawInput = file_get_contents('php://input');
$jsonData = json_decode($rawInput, true);
$targetUrl = trim($_POST['url'] ?? ($jsonData['url'] ?? ''));

if (empty($targetUrl)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Parameter URL tidak boleh kosong.']);
    exit;
}

$targetUrl = UrlParser::normalize($targetUrl);

if (!UrlParser::isValidUrl($targetUrl)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Format URL tidak valid. Pastikan format diawali dengan http:// atau https://']);
    exit;
}

$startTime = microtime(true);
$urlHash = hash('sha256', $targetUrl);
$db = Database::getConnection();

// 1. Periksa Cache Database (jika DB aktif)
if ($db) {
    try {
        $cacheHours = $config['app']['cache_hours'] ?? 6;
        $stmt = $db->prepare('SELECT * FROM scans WHERE url_hash = :hash AND created_at >= NOW() - INTERVAL :hours HOUR ORDER BY id DESC LIMIT 1');
        $stmt->bindValue(':hash', $urlHash, PDO::PARAM_STR);
        $stmt->bindValue(':hours', $cacheHours, PDO::PARAM_INT);
        $stmt->execute();
        $cached = $stmt->fetch();

        if ($cached) {
            // Ambil rincian temuan dari scan_details
            $detStmt = $db->prepare('SELECT category, rule_name, severity, score_impact, description FROM scan_details WHERE scan_id = :scan_id');
            $detStmt->execute([':scan_id' => $cached['id']]);
            $cachedFindings = $detStmt->fetchAll();

            $scoreEngine = new ScoreEngine($config);
            $evaluation = $scoreEngine->evaluate(
                ['findings' => $cachedFindings, 'penalty' => $cached['risk_score']],
                ['findings' => [], 'penalty' => 0],
                ['findings' => [], 'penalty' => 0]
            );

            $cachedParsed = UrlParser::parse($cached['final_url']);

            echo json_encode([
                'success' => true,
                'cached' => true,
                'scan_id' => (int) $cached['id'],
                'original_url' => $cached['original_url'],
                'final_url' => $cached['final_url'],
                'domain' => $cached['domain'],
                'subdomain' => $cachedParsed['subdomain'],
                'ip_address' => $cached['ip_address'],
                'risk_score' => (int) $cached['risk_score'],
                'verdict' => $cached['verdict'],
                'is_redirected' => (bool) $cached['is_redirected'],
                'redirect_count' => (int) $cached['redirect_count'],
                'domain_age_days' => $cached['domain_age_days'] !== null ? (int) $cached['domain_age_days'] : null,
                'findings' => $cachedFindings,
                'recommendations' => $evaluation['recommendations'],
                'execution_time_ms' => round((microtime(true) - $startTime) * 1000, 2),
                'created_at' => $cached['created_at'],
            ]);
            exit;
        }
    } catch (PDOException $e) {
        error_log('Cache query error: ' . $e->getMessage());
    }
}

// 2. Trace Redirects & Unshortener (Aman dari SSRF)
$redirectInfo = UrlParser::traceRedirects($targetUrl);
if (!empty($redirectInfo['error'])) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => $redirectInfo['error']]);
    exit;
}

$finalUrl = $redirectInfo['final_url'];
$parsedFinal = UrlParser::parse($finalUrl);

// 3. Heuristic Engine Scan
$heuristicEngine = new HeuristicEngine($config);
$heuristicResult = $heuristicEngine->analyze($parsedFinal);

// 4. Domain Age / WHOIS
$whoisResult = WhoisLookup::check($parsedFinal['domain']);

// 5. Threat Intelligence (URLhaus + GSB / VT jika API key ada)
$threatIntel = new ThreatIntel($config);
$threatIntelResult = $threatIntel->check($finalUrl);

// 6. Cek Reputasi Domain di Database
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

// 7. Hitung Skor & Verdict
$scoreEngine = new ScoreEngine($config);
$evaluation = $scoreEngine->evaluate(
    $heuristicResult,
    $whoisResult,
    $threatIntelResult,
    $reputationDb
);

$riskScore = $evaluation['risk_score'];
$verdict = $evaluation['verdict'];
$findings = $evaluation['findings'];
$recommendations = $evaluation['recommendations'];

// 8. Simpan ke Database
$scanId = null;
if ($db) {
    try {
        $insert = $db->prepare('
            INSERT INTO scans 
            (url_hash, original_url, final_url, domain, ip_address, risk_score, verdict, is_redirected, redirect_count, domain_age_days)
            VALUES 
            (:url_hash, :original_url, :final_url, :domain, :ip_address, :risk_score, :verdict, :is_redirected, :redirect_count, :domain_age_days)
        ');

        $insert->execute([
            ':url_hash'        => $urlHash,
            ':original_url'    => $targetUrl,
            ':final_url'       => $finalUrl,
            ':domain'          => $parsedFinal['domain'],
            ':ip_address'      => $redirectInfo['ip_address'],
            ':risk_score'      => $riskScore,
            ':verdict'         => $verdict,
            ':is_redirected'   => $redirectInfo['is_redirected'] ? 1 : 0,
            ':redirect_count'  => $redirectInfo['redirect_count'],
            ':domain_age_days' => $whoisResult['domain_age_days'],
        ]);

        $scanId = (int) $db->lastInsertId();

        // Simpan setiap temuan ke scan_details
        if (!empty($findings)) {
            $detailInsert = $db->prepare('
                INSERT INTO scan_details (scan_id, category, rule_name, severity, score_impact, description)
                VALUES (:scan_id, :category, :rule_name, :severity, :score_impact, :description)
            ');

            foreach ($findings as $f) {
                $detailInsert->execute([
                    ':scan_id'      => $scanId,
                    ':category'     => $f['category'] ?? 'heuristic',
                    ':rule_name'    => $f['rule_name'] ?? 'UNKNOWN',
                    ':severity'     => $f['severity'] ?? 'low',
                    ':score_impact' => (int) ($f['score_impact'] ?? 0),
                    ':description'  => $f['description'] ?? '',
                ]);
            }
        }
    } catch (PDOException $e) {
        error_log('Database insert error: ' . $e->getMessage());
    }
}

$executionTime = round((microtime(true) - $startTime) * 1000, 2);

echo json_encode([
    'success' => true,
    'cached' => false,
    'scan_id' => $scanId,
    'original_url' => $targetUrl,
    'final_url' => $finalUrl,
    'domain' => $parsedFinal['domain'],
    'subdomain' => $parsedFinal['subdomain'],
    'ip_address' => $redirectInfo['ip_address'],
    'risk_score' => $riskScore,
    'verdict' => $verdict,
    'is_redirected' => $redirectInfo['is_redirected'],
    'redirect_count' => $redirectInfo['redirect_count'],
    'redirect_chain' => $redirectInfo['chain'],
    'domain_age_days' => $whoisResult['domain_age_days'],
    'domain_registrar' => $whoisResult['registrar'],
    'findings' => $findings,
    'recommendations' => $recommendations,
    'execution_time_ms' => $executionTime,
    'created_at' => date('Y-m-d H:i:s'),
]);
