<?php
/**
 * Audit Logger - LinkTester v2.0
 * Mencatat setiap aktivitas scan ke file log harian untuk keperluan forensik.
 */

class AuditLogger
{
    private static ?string $logDir = null;

    /**
     * Inisialisasi direktori log
     */
    private static function init(): void
    {
        if (self::$logDir === null) {
            self::$logDir = __DIR__ . '/../logs';
            if (!is_dir(self::$logDir)) {
                @mkdir(self::$logDir, 0755, true);
            }
        }
    }

    /**
     * Catat aktivitas scan
     */
    public static function logScan(array $params): void
    {
        self::init();

        $entry = [
            'timestamp'  => date('Y-m-d H:i:s'),
            'ip'         => $params['ip'] ?? self::getClientIp(),
            'url'        => $params['url'] ?? '',
            'final_url'  => $params['final_url'] ?? '',
            'verdict'    => $params['verdict'] ?? '',
            'score'      => $params['score'] ?? 0,
            'exec_time'  => $params['exec_time'] ?? 0,
            'cached'     => $params['cached'] ?? false,
            'user_agent' => $params['user_agent'] ?? ($_SERVER['HTTP_USER_AGENT'] ?? ''),
        ];

        $line = '[' . $entry['timestamp'] . '] '
            . '[' . str_pad($entry['ip'], 15) . '] '
            . '[' . strtoupper(str_pad($entry['verdict'], 10)) . '] '
            . '[Score:' . str_pad($entry['score'], 3, ' ', STR_PAD_LEFT) . '] '
            . '[' . $entry['exec_time'] . 'ms] '
            . ($entry['cached'] ? '[CACHE] ' : '[FRESH] ')
            . $entry['url'];

        if ($entry['url'] !== $entry['final_url'] && !empty($entry['final_url'])) {
            $line .= ' → ' . $entry['final_url'];
        }

        $logFile = self::$logDir . '/audit_' . date('Y-m-d') . '.log';
        @file_put_contents($logFile, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    /**
     * Log error atau event khusus
     */
    public static function logEvent(string $type, string $message, array $context = []): void
    {
        self::init();

        $line = '[' . date('Y-m-d H:i:s') . '] '
            . '[' . strtoupper($type) . '] '
            . '[' . (self::getClientIp()) . '] '
            . $message;

        if (!empty($context)) {
            $line .= ' | ' . json_encode($context, JSON_UNESCAPED_SLASHES);
        }

        $logFile = self::$logDir . '/audit_' . date('Y-m-d') . '.log';
        @file_put_contents($logFile, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    /**
     * Ambil IP client (support proxy)
     */
    private static function getClientIp(): string
    {
        $headers = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = explode(',', $_SERVER[$header])[0];
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '127.0.0.1';
    }

    /**
     * Ambil log entries hari ini (untuk dashboard)
     */
    public static function getTodayStats(): array
    {
        self::init();

        $logFile = self::$logDir . '/audit_' . date('Y-m-d') . '.log';
        if (!file_exists($logFile)) {
            return ['total_scans' => 0, 'unique_ips' => 0];
        }

        $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $ips = [];
        $scanCount = 0;

        foreach ($lines as $line) {
            if (preg_match('/\[(\d+\.\d+\.\d+\.\d+)\s*\]/', $line, $m)) {
                $ips[$m[1]] = true;
            }
            if (str_contains($line, '[SAFE') || str_contains($line, '[SUSPICIOUS') || str_contains($line, '[DANGEROUS')) {
                $scanCount++;
            }
        }

        return [
            'total_scans' => $scanCount,
            'unique_ips'  => count($ips),
        ];
    }
}
