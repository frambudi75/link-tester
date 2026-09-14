<?php
/**
 * Rate Limiter - LinkTester v2.0
 * Membatasi jumlah request per IP per menit.
 * Menggunakan file-based storage (kompatibel semua environment).
 */

class RateLimiter
{
    private string $storageDir;
    private int $maxRequests;
    private int $windowSeconds;

    public function __construct(int $maxRequests = 20, int $windowSeconds = 60)
    {
        $this->storageDir = sys_get_temp_dir() . '/linktester_ratelimit';
        $this->maxRequests = $maxRequests;
        $this->windowSeconds = $windowSeconds;

        if (!is_dir($this->storageDir)) {
            @mkdir($this->storageDir, 0755, true);
        }
    }

    /**
     * Periksa apakah IP sudah melebihi batas
     * @return array ['allowed' => bool, 'remaining' => int, 'retry_after' => int]
     */
    public function check(string $ip): array
    {
        $file = $this->storageDir . '/' . md5($ip) . '.json';
        $now = time();

        $data = ['timestamps' => []];
        if (file_exists($file)) {
            $content = @file_get_contents($file);
            if ($content) {
                $data = json_decode($content, true) ?: ['timestamps' => []];
            }
        }

        // Buang timestamp yang sudah di luar window
        $data['timestamps'] = array_values(array_filter(
            $data['timestamps'],
            fn($ts) => ($now - $ts) < $this->windowSeconds
        ));

        $count = count($data['timestamps']);

        if ($count >= $this->maxRequests) {
            $oldestInWindow = min($data['timestamps']);
            $retryAfter = $this->windowSeconds - ($now - $oldestInWindow);
            return [
                'allowed'     => false,
                'remaining'   => 0,
                'retry_after' => max(1, $retryAfter),
                'count'       => $count,
            ];
        }

        // Catat request baru
        $data['timestamps'][] = $now;
        @file_put_contents($file, json_encode($data), LOCK_EX);

        return [
            'allowed'     => true,
            'remaining'   => $this->maxRequests - $count - 1,
            'retry_after' => 0,
            'count'       => $count + 1,
        ];
    }

    /**
     * Bersihkan file rate limit yang sudah expired
     */
    public function cleanup(): void
    {
        if (!is_dir($this->storageDir)) return;

        $files = glob($this->storageDir . '/*.json');
        $now = time();

        foreach ($files as $file) {
            if (($now - filemtime($file)) > $this->windowSeconds * 2) {
                @unlink($file);
            }
        }
    }
}
