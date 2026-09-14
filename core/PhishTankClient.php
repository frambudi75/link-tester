<?php
/**
 * PhishTank API Client - LinkTester v2.0
 * Memeriksa URL di database PhishTank (komunitas anti-phishing terbesar).
 * API key opsional — graceful degradation jika tidak tersedia.
 */

class PhishTankClient
{
    /**
     * Cek apakah URL terdaftar di PhishTank
     */
    public static function check(string $url, string $apiKey = ''): array
    {
        $findings = [];
        $penalty = 0;

        if (empty($url)) {
            return ['findings' => $findings, 'penalty' => 0, 'checked' => false];
        }

        $endpoint = 'https://checkurl.phishtank.com/checkurl/';

        $postFields = [
            'url'             => $url,
            'format'          => 'json',
        ];

        if (!empty($apiKey)) {
            $postFields['app_key'] = $apiKey;
        }

        $ch = curl_init($endpoint);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($postFields),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 4,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT      => 'LinkTester/2.0 (phishtank-client)',
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($httpCode !== 200 || empty($response)) {
            error_log('PhishTank API error: HTTP ' . $httpCode . ' - ' . $curlError);
            return ['findings' => $findings, 'penalty' => 0, 'checked' => false];
        }

        $data = json_decode($response, true);
        if (!is_array($data) || !isset($data['results'])) {
            return ['findings' => $findings, 'penalty' => 0, 'checked' => false];
        }

        $results = $data['results'];
        $isPhish = !empty($results['in_database']) && !empty($results['valid']);

        if ($isPhish) {
            $phishId = $results['phish_id'] ?? 'N/A';
            $findings[] = [
                'rule_name'    => 'PHISHTANK_CONFIRMED',
                'category'     => 'threat_intel',
                'severity'     => 'critical',
                'score_impact' => 80,
                'description'  => 'TERVERIFIKASI PHISHING oleh PhishTank (ID: ' . $phishId . '). URL ini telah dilaporkan dan dikonfirmasi oleh komunitas anti-phishing sebagai situs phishing aktif.',
            ];
            $penalty += 80;
        }

        return [
            'findings' => $findings,
            'penalty'  => min(100, $penalty),
            'checked'  => true,
        ];
    }
}
