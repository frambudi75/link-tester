<?php
/**
 * Export API Endpoint - LinkTester v2.0
 * Export hasil scan dalam format JSON atau HTML (printable PDF).
 * Usage: GET /api/export.php?scan_id=123&format=json|pdf
 */

require_once __DIR__ . '/../core/Database.php';

$scanId = (int) ($_GET['scan_id'] ?? 0);
$format = strtolower(trim($_GET['format'] ?? 'json'));

if ($scanId <= 0) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Parameter scan_id diperlukan.']);
    exit;
}

$db = Database::getConnection();
if (!$db) {
    http_response_code(503);
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Database tidak tersedia.']);
    exit;
}

// Ambil data scan
try {
    $stmt = $db->prepare('SELECT * FROM scans WHERE id = :id LIMIT 1');
    $stmt->execute([':id' => $scanId]);
    $scan = $stmt->fetch();

    if (!$scan) {
        http_response_code(404);
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => 'Scan ID tidak ditemukan.']);
        exit;
    }

    $detStmt = $db->prepare('SELECT category, rule_name, severity, score_impact, description FROM scan_details WHERE scan_id = :scan_id');
    $detStmt->execute([':scan_id' => $scanId]);
    $findings = $detStmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Database error: ' . $e->getMessage()]);
    exit;
}

// Format JSON
if ($format === 'json') {
    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="linktester_scan_' . $scanId . '.json"');
    echo json_encode([
        'export_info' => [
            'tool' => 'LinkTester v2.0',
            'exported_at' => date('Y-m-d H:i:s'),
            'scan_id' => (int) $scan['id'],
        ],
        'scan_result' => [
            'original_url'    => $scan['original_url'],
            'final_url'       => $scan['final_url'],
            'domain'          => $scan['domain'],
            'ip_address'      => $scan['ip_address'],
            'risk_score'      => (int) $scan['risk_score'],
            'verdict'         => $scan['verdict'],
            'is_redirected'   => (bool) $scan['is_redirected'],
            'redirect_count'  => (int) $scan['redirect_count'],
            'domain_age_days' => $scan['domain_age_days'] !== null ? (int) $scan['domain_age_days'] : null,
            'ssl_valid'       => $scan['ssl_valid'] !== null ? (bool) $scan['ssl_valid'] : null,
            'ssl_issuer'      => $scan['ssl_issuer'] ?? null,
            'has_login_form'  => (bool) ($scan['has_login_form'] ?? false),
            'has_hidden_iframe' => (bool) ($scan['has_hidden_iframe'] ?? false),
            'has_spf'         => $scan['has_spf'] !== null ? (bool) $scan['has_spf'] : null,
            'has_dmarc'       => $scan['has_dmarc'] !== null ? (bool) $scan['has_dmarc'] : null,
            'scanned_at'      => $scan['created_at'],
        ],
        'findings' => $findings,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

// Format PDF (HTML printable)
if ($format === 'pdf') {
    header('Content-Type: text/html; charset=utf-8');
    
    $verdictColors = [
        'clean'       => '#22c55e',
        'safe'        => '#22c55e',
        'low_risk'    => '#3b82f6',
        'medium_risk' => '#eab308',
        'suspicious'  => '#eab308',
        'high_risk'   => '#f97316',
        'critical'    => '#ef4444',
        'dangerous'   => '#ef4444',
    ];
    $verdictLabels = [
        'clean'       => 'CLEAN / AMAN',
        'safe'        => 'AMAN',
        'low_risk'    => 'LOW RISK / RISIKO RENDAH',
        'medium_risk' => 'MEDIUM RISK / RISIKO SEDANG',
        'suspicious'  => 'MENCURIGAKAN',
        'high_risk'   => 'HIGH RISK / RISIKO TINGGI',
        'critical'    => 'CRITICAL / KRITIS',
        'dangerous'   => 'BERBAHAYA',
    ];
    $vKey = strtolower($scan['verdict'] ?? 'clean');
    $verdictColor = $verdictColors[$vKey] ?? '#6b7280';
    $verdictLabel = $verdictLabels[$vKey] ?? strtoupper($vKey);
    ?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>LinkTester Report - Scan #<?= $scanId ?></title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: #fff; color: #111; padding: 40px; max-width: 800px; margin: 0 auto; font-size: 13px; }
        h1 { font-size: 20px; margin-bottom: 4px; }
        .subtitle { color: #6b7280; font-size: 12px; margin-bottom: 24px; }
        .verdict-box { padding: 16px 20px; border-radius: 8px; margin-bottom: 24px; display: flex; align-items: center; gap: 20px; }
        .score { font-family: 'JetBrains Mono', monospace; font-size: 36px; font-weight: 700; }
        .verdict-label { font-size: 14px; font-weight: 700; text-transform: uppercase; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; font-size: 12px; }
        th { background: #f9fafb; font-weight: 600; color: #374151; text-transform: uppercase; font-size: 10px; letter-spacing: 0.05em; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .sev { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; text-transform: uppercase; }
        .sev-critical { background: #fef2f2; color: #dc2626; }
        .sev-high { background: #fef2f2; color: #ef4444; }
        .sev-medium { background: #fffbeb; color: #d97706; }
        .sev-low { background: #eff6ff; color: #2563eb; }
        .sev-info { background: #ecfdf5; color: #059669; }
        .footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 11px; text-align: center; }
        @media print { body { padding: 20px; } .no-print { display: none; } }
    </style>
</head>
<body>
    <div class="no-print" style="margin-bottom:20px; text-align:right;">
        <button onclick="window.print()" style="padding:8px 20px; background:#2563eb; color:#fff; border:none; border-radius:4px; cursor:pointer; font-size:13px; font-weight:600;">
            🖨️ Cetak / Simpan PDF
        </button>
    </div>

    <h1>🛡️ LinkTester — Laporan Analisis Keamanan URL</h1>
    <p class="subtitle">Scan ID: #<?= $scanId ?> &bull; Waktu Scan: <?= htmlspecialchars($scan['created_at']) ?></p>

    <div class="verdict-box" style="background:<?= $verdictColor ?>15; border:1px solid <?= $verdictColor ?>40;">
        <div class="score" style="color:<?= $verdictColor ?>;"><?= (int)$scan['risk_score'] ?></div>
        <div>
            <div class="verdict-label" style="color:<?= $verdictColor ?>;"><?= $verdictLabel ?></div>
            <div style="color:#6b7280; font-size:11px;">Risk Score / 100</div>
        </div>
    </div>

    <h3 style="margin-bottom:8px;">Informasi URL</h3>
    <table>
        <tr><td style="width:30%; color:#6b7280;">URL Asli</td><td class="mono"><?= htmlspecialchars($scan['original_url']) ?></td></tr>
        <tr><td style="color:#6b7280;">URL Tujuan Akhir</td><td class="mono"><?= htmlspecialchars($scan['final_url']) ?></td></tr>
        <tr><td style="color:#6b7280;">Domain</td><td class="mono"><?= htmlspecialchars($scan['domain']) ?></td></tr>
        <tr><td style="color:#6b7280;">Alamat IP</td><td class="mono"><?= htmlspecialchars($scan['ip_address'] ?? '-') ?></td></tr>
        <tr><td style="color:#6b7280;">Redirect</td><td><?= $scan['is_redirected'] ? 'Ya (' . (int)$scan['redirect_count'] . ' hops)' : 'Tidak' ?></td></tr>
        <tr><td style="color:#6b7280;">Umur Domain</td><td><?= $scan['domain_age_days'] !== null ? (int)$scan['domain_age_days'] . ' hari' : 'Tidak diketahui' ?></td></tr>
        <tr><td style="color:#6b7280;">SSL Valid</td><td><?= $scan['ssl_valid'] !== null ? ($scan['ssl_valid'] ? '✅ Ya' : '❌ Tidak') : '-' ?></td></tr>
        <tr><td style="color:#6b7280;">SSL Issuer</td><td><?= htmlspecialchars($scan['ssl_issuer'] ?? '-') ?></td></tr>
    </table>

    <?php if (!empty($findings)): ?>
    <h3 style="margin-bottom:8px;">Temuan Keamanan (<?= count($findings) ?> item)</h3>
    <table>
        <thead>
            <tr><th>Severity</th><th>Rule</th><th>Kategori</th><th>Deskripsi</th></tr>
        </thead>
        <tbody>
        <?php foreach ($findings as $f): ?>
            <tr>
                <td><span class="sev sev-<?= htmlspecialchars($f['severity']) ?>"><?= htmlspecialchars($f['severity']) ?></span></td>
                <td class="mono" style="font-weight:600;"><?= htmlspecialchars($f['rule_name']) ?></td>
                <td><?= htmlspecialchars($f['category']) ?></td>
                <td><?= htmlspecialchars($f['description']) ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php else: ?>
    <p style="padding:12px; background:#ecfdf5; border-radius:6px; color:#059669;">✅ Tidak ditemukan ancaman keamanan.</p>
    <?php endif; ?>

    <div class="footer">
        LinkTester v2.0 — Laporan ini digenerate secara otomatis &bull; <?= date('Y-m-d H:i:s') ?>
    </div>
</body>
</html>
<?php
    exit;
}

// Format tidak dikenal
http_response_code(400);
header('Content-Type: application/json');
echo json_encode(['success' => false, 'error' => 'Format tidak valid. Gunakan: json atau pdf']);
