<?php
/**
 * External Threat Intelligence Integration - LinkTester
 * Mengintegrasikan Google Safe Browsing, VirusTotal, dan URLhaus
 * Dilengkapi mekanisme graceful degradation (tetap aman jika API key kosong).
 */

class ThreatIntel
{
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config['threat_intel'] ?? [];
    }

    /**
     * Jalankan pemeriksaan threat intelligence
     */
    public function check(string $url): array
    {
        $findings = [];
        $totalPenalty = 0;
        $sourcesChecked = [];

        // 1. URLhaus API (Free & No API Key Required)
        if (!empty($this->config['urlhaus_enabled'])) {
            $sourcesChecked[] = 'URLhaus';
            $urlhausResult = $this->checkUrlhaus($url);
            if ($urlhausResult['is_malicious']) {
                $findings[] = [
                    'rule_name' => 'URLHAUS_MALICIOUS',
                    'category' => 'threat_intel',
                    'severity' => 'critical',
                    'score_impact' => 80,
                    'description' => 'TERDETEKSI OLEH URLHAUS: Link ini terdaftar aktif di database URLhaus sebagai penyebar malware (' . ($urlhausResult['threat'] ?? 'Malware URL') . ').',
                ];
                $totalPenalty += 80;
            }
        }

        // 2. Google Safe Browsing API (Jika API Key Disediakan)
        $gsbKey = $this->config['google_safe_browsing_api_key'] ?? '';
        if (!empty($gsbKey)) {
            $sourcesChecked[] = 'Google Safe Browsing';
            $gsbResult = $this->checkGoogleSafeBrowsing($url, $gsbKey);
            if ($gsbResult['is_malicious']) {
                $findings[] = [
                    'rule_name' => 'GOOGLE_SAFE_BROWSING_HIT',
                    'category' => 'threat_intel',
                    'severity' => 'critical',
                    'score_impact' => 80,
                    'description' => 'TERDETEKSI OLEH GOOGLE SAFE BROWSING: Situs ini dilaporkan sebagai ' . implode(', ', $gsbResult['threat_types']) . '.',
                ];
                $totalPenalty += 80;
            }
        }

        // 3. VirusTotal API (Jika API Key Disediakan)
        $vtKey = $this->config['virustotal_api_key'] ?? '';
        if (!empty($vtKey)) {
            $sourcesChecked[] = 'VirusTotal';
            $vtResult = $this->checkVirusTotal($url, $vtKey);
            if ($vtResult['positives'] >= 2) {
                $findings[] = [
                    'rule_name' => 'VIRUSTOTAL_MALICIOUS',
                    'category' => 'threat_intel',
                    'severity' => 'critical',
                    'score_impact' => 80,
                    'description' => 'TERDETEKSI OLEH VIRUSTOTAL: Sebanyak ' . $vtResult['positives'] . ' engine keamanan menandai link ini sebagai berbahaya/phishing.',
                ];
                $totalPenalty += 80;
            }
        }

        return [
            'findings' => $findings,
            'penalty' => min(100, $totalPenalty),
            'sources_checked' => $sourcesChecked,
        ];
    }

    /**
     * Cek ke URLhaus (abuse.ch)
     */
    private function checkUrlhaus(string $url): array
    {
        $ch = curl_init('https://urlhaus-api.abuse.ch/v1/url/');
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query(['url' => $url]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 3,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT      => 'LinkTester/1.0',
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 200 && !empty($response)) {
            $data = json_decode($response, true);
            if (isset($data['query_status']) && $data['query_status'] === 'ok') {
                return [
                    'is_malicious' => true,
                    'threat' => $data['threat'] ?? 'Malicious URL',
                    'url_status' => $data['url_status'] ?? 'online',
                ];
            }
        }

        return ['is_malicious' => false];
    }

    /**
     * Cek ke Google Safe Browsing API v4
     */
    private function checkGoogleSafeBrowsing(string $url, string $apiKey): array
    {
        $endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . urlencode($apiKey);

        $payload = [
            'client' => [
                'clientId'      => 'link-tester-app',
                'clientVersion' => '1.0.0',
            ],
            'threatInfo' => [
                'threatTypes'      => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes'    => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries'    => [['url' => $url]],
            ],
        ];

        $ch = curl_init($endpoint);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($payload),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 3,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 200 && !empty($response)) {
            $data = json_decode($response, true);
            if (!empty($data['matches'])) {
                $types = array_unique(array_column($data['matches'], 'threatType'));
                return [
                    'is_malicious' => true,
                    'threat_types' => $types,
                ];
            }
        }

        return ['is_malicious' => false];
    }

    /**
     * Cek ke VirusTotal API v3
     */
    private function checkVirusTotal(string $url, string $apiKey): array
    {
        // URL id adalah URL yang di-base64 tanpa padding '='
        $urlId = rtrim(strtr(base64_encode($url), '+/', '-_'), '=');
        $endpoint = 'https://www.virustotal.com/api/v3/urls/' . $urlId;

        $ch = curl_init($endpoint);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 3,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_HTTPHEADER     => [
                'x-apikey: ' . $apiKey,
                'Accept: application/json'
            ],
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 200 && !empty($response)) {
            $data = json_decode($response, true);
            $stats = $data['data']['attributes']['last_analysis_stats'] ?? [];
            $malicious = ($stats['malicious'] ?? 0) + ($stats['suspicious'] ?? 0);
            return [
                'is_malicious' => $malicious >= 2,
                'positives' => $malicious,
            ];
        }

        return ['is_malicious' => false, 'positives' => 0];
    }
}
