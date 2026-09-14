<?php
require_once __DIR__ . '/../core/Database.php';

$db = Database::getConnection();
if (!$db) {
    echo "No database connection\n";
    exit;
}

echo "Running migrations...\n";

// 1. Modify verdict column to VARCHAR(30) so all 5 tiers fit
try {
    $db->exec("ALTER TABLE `scans` MODIFY `verdict` VARCHAR(30) NOT NULL DEFAULT 'clean'");
    echo "[OK] scans.verdict converted to VARCHAR(30)\n";
} catch (PDOException $e) {
    echo "Note verdict modify: " . $e->getMessage() . "\n";
}

// 2. Add missing columns if they don't exist
$columns = [
    'ssl_valid'          => 'TINYINT(1) DEFAULT NULL',
    'ssl_issuer'         => 'VARCHAR(255) DEFAULT NULL',
    'has_login_form'     => 'TINYINT(1) NOT NULL DEFAULT 0',
    'has_hidden_iframe'  => 'TINYINT(1) NOT NULL DEFAULT 0',
    'has_spf'            => 'TINYINT(1) DEFAULT NULL',
    'has_dmarc'          => 'TINYINT(1) DEFAULT NULL',
];

// Check existing columns in scans
$existingCols = [];
$stmt = $db->query("SHOW COLUMNS FROM `scans`");
while ($row = $stmt->fetch()) {
    $existingCols[] = strtolower($row['Field']);
}

foreach ($columns as $col => $type) {
    if (!in_array(strtolower($col), $existingCols, true)) {
        try {
            $db->exec("ALTER TABLE `scans` ADD COLUMN `{$col}` {$type}");
            echo "[OK] Added column scans.{$col}\n";
        } catch (PDOException $e) {
            echo "[ERR] Adding {$col}: " . $e->getMessage() . "\n";
        }
    } else {
        echo "[EXISTS] scans.{$col}\n";
    }
}

// 3. Make sure scan_details severity allows 'info', 'low', 'medium', 'high', 'critical'
try {
    $db->exec("ALTER TABLE `scan_details` MODIFY `severity` VARCHAR(20) NOT NULL DEFAULT 'low'");
    echo "[OK] scan_details.severity converted to VARCHAR(20)\n";
} catch (PDOException $e) {
    echo "Note severity modify: " . $e->getMessage() . "\n";
}

echo "Migration complete.\n";
