<?php
/**
 * Statistics API Endpoint - LinkTester v2.0
 * Menyediakan data agregat untuk dashboard: distribusi verdict, trend, top domain.
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/../core/Database.php';

$db = Database::getConnection();

if (!$db) {
    echo json_encode([
        'success' => false,
        'error' => 'Database tidak tersedia. Dashboard memerlukan koneksi database aktif.',
    ]);
    exit;
}

try {
    // 1. Total scan keseluruhan
    $totalStmt = $db->query('SELECT COUNT(*) as total FROM scans');
    $totalScans = (int) $totalStmt->fetch()['total'];

    // 2. Distribusi verdict (untuk pie chart)
    $verdictStmt = $db->query('SELECT verdict, COUNT(*) as count FROM scans GROUP BY verdict ORDER BY count DESC');
    $verdictDist = [];
    while ($row = $verdictStmt->fetch()) {
        $verdictDist[] = ['verdict' => $row['verdict'], 'count' => (int) $row['count']];
    }

    // 3. Trend scan per hari (7 hari terakhir) - untuk line chart
    $trendStmt = $db->query("
        SELECT DATE(created_at) as scan_date, COUNT(*) as count 
        FROM scans 
        WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) 
        GROUP BY DATE(created_at) 
        ORDER BY scan_date ASC
    ");
    $dailyTrend = [];
    while ($row = $trendStmt->fetch()) {
        $dailyTrend[] = ['date' => $row['scan_date'], 'count' => (int) $row['count']];
    }

    // 4. Top 10 domain paling sering di-scan
    $topStmt = $db->query('SELECT domain, COUNT(*) as count, MAX(verdict) as last_verdict FROM scans GROUP BY domain ORDER BY count DESC LIMIT 10');
    $topDomains = [];
    while ($row = $topStmt->fetch()) {
        $topDomains[] = [
            'domain' => $row['domain'],
            'count' => (int) $row['count'],
            'last_verdict' => $row['last_verdict'],
        ];
    }

    // 5. Rata-rata risk score
    $avgStmt = $db->query('SELECT ROUND(AVG(risk_score), 1) as avg_score FROM scans');
    $avgScore = (float) ($avgStmt->fetch()['avg_score'] ?? 0);

    // 6. Scan hari ini
    $todayStmt = $db->query("SELECT COUNT(*) as count FROM scans WHERE DATE(created_at) = CURDATE()");
    $todayCount = (int) $todayStmt->fetch()['count'];

    // 7. Distribusi severity dari findings
    $sevStmt = $db->query('SELECT severity, COUNT(*) as count FROM scan_details GROUP BY severity ORDER BY FIELD(severity, "critical", "high", "medium", "low", "info")');
    $severityDist = [];
    while ($row = $sevStmt->fetch()) {
        $severityDist[] = ['severity' => $row['severity'], 'count' => (int) $row['count']];
    }

    // 8. Detection rate (% URL terdeteksi berbahaya/mencurigakan)
    $detectedStmt = $db->query("SELECT COUNT(*) as count FROM scans WHERE verdict != 'safe'");
    $detectedCount = (int) $detectedStmt->fetch()['count'];
    $detectionRate = $totalScans > 0 ? round(($detectedCount / $totalScans) * 100, 1) : 0;

    echo json_encode([
        'success' => true,
        'stats' => [
            'total_scans'    => $totalScans,
            'today_scans'    => $todayCount,
            'avg_risk_score' => $avgScore,
            'detection_rate' => $detectionRate,
            'verdict_distribution' => $verdictDist,
            'daily_trend'    => $dailyTrend,
            'top_domains'    => $topDomains,
            'severity_distribution' => $severityDist,
        ],
    ]);
} catch (PDOException $e) {
    echo json_encode([
        'success' => false,
        'error' => 'Database query error: ' . $e->getMessage(),
    ]);
}
