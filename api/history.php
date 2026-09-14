<?php
/**
 * Recent Scans History API Endpoint - LinkTester
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/../core/Database.php';

$db = Database::getConnection();
if (!$db) {
    echo json_encode([
        'success' => true,
        'db_connected' => false,
        'history' => [],
    ]);
    exit;
}

try {
    $limit = isset($_GET['limit']) ? max(1, min(50, (int) $_GET['limit'])) : 10;
    $stmt = $db->prepare('
        SELECT id, original_url, final_url, domain, risk_score, verdict, is_redirected, created_at 
        FROM scans 
        ORDER BY id DESC 
        LIMIT :limit
    ');
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->execute();
    $history = $stmt->fetchAll();

    echo json_encode([
        'success' => true,
        'db_connected' => true,
        'history' => $history,
    ]);
} catch (PDOException $e) {
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
    ]);
}
