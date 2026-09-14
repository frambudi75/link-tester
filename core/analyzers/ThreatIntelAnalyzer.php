<?php
/**
 * Threat Intelligence Analyzer - LinkTester
 * 
 * Mengintegrasikan database ancaman eksternal (URLhaus, VirusTotal, Google Safe Browsing, PhishTank).
 * Dilengkapi graceful degradation jika API key belum diisi.
 * 
 * Menghasilkan Evidence objects untuk diproses oleh RiskScorer.
 */

require_once __DIR__ . '/../Evidence.php';
require_once __DIR__ . '/../PhishTankClient.php';

class ThreatIntelAnalyzer
{
    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config['threat_intel'] ?? [];
    }

    /**
     * Jalankan pemeriksaan threat intel pada URL.
     * 
     * @param string $url URL yang diperiksa
     * @return Evidence[]
     */
    public function analyze(string $url): array
    {
        $evidences = [];
        $source = 'threat_intel';
        $anySourceChecked = false;
        $anyThreatDetected = false;

        // 1. URLhaus API (abuse.ch) - Bebas API Key
        if (!empty($this->config['urlhaus_enabled'])) {
            $anySourceChecked = true;
            $urlhaus = $this->checkUrlhaus($url);
            if (!empty($urlhaus['is_malicious'])) {
                $anyThreatDetected = true;
                $evidences[] = Evidence::create(
                    'urlhaus_hit',
                    true,
                    $source,
                    [
                        'provider'   => 'URLhaus (abuse.ch)',
                        'threat'     => $urlhaus['threat'] ?? 'Malware URL',
                        'url_status' => $urlhaus['url_status'] ?? 'online',
                        'detail'     => 'URL terdaftar aktif sebagai sumber distribusi malware di database abuse.ch URLhaus (' . ($urlhaus['threat'] ?? '') . ').'
                    ],
                    1.0
                );
            }
        }

        // 2. Google Safe Browsing API
        $gsbKey = $this->config['google_safe_browsing_api_key'] ?? '';
        if (!empty($gsbKey)) {
            $anySourceChecked = true;
            $gsb = $this->checkGoogleSafeBrowsing($url, $gsbKey);
            if (!empty($gsb['is_malicious'])) {
                $anyThreatDetected = true;
                $evidences[] = Evidence::create(
                    'google_safebrowsing_hit',
                    true,
                    $source,
                    [
                        'provider'     => 'Google Safe Browsing',
                        'threat_types' => $gsb['threat_types'] ?? [],
                        'detail'       => 'Google Safe Browsing menandai URL ini sebagai ancaman berbahaya: ' . implode(', ', $gsb['threat_types'] ?? [])
                    ],
                    1.0
                );
            }
        }

        // 3. VirusTotal API
        $vtKey = $this->config['virustotal_api_key'] ?? '';
        if (!empty($vtKey)) {
            $anySourceChecked = true;
            $vt = $this->checkVirusTotal($url, $vtKey);
            if (!empty($vt['is_malicious'])) {
                $anyThreatDetected = true;
                $evidences[] = Evidence::create(
                    'virustotal_hit',
                    $vt['positives'],
                    $source,
                    [
                        'provider'  => 'VirusTotal',
                        'positives' => $vt['positives'],
                        'detail'    => $vt['positives'] . ' engine keamanan di VirusTotal menandai URL ini berbahaya.'
                    ],
                    0.95
                );
            }
        }

        // 4. PhishTank API
        $ptKey = $this->config['phishtank_api_key'] ?? '';
        $pt = PhishTankClient::check($url, $ptKey);
        if (!empty($pt['checked'])) {
            $anySourceChecked = true;
            foreach ($pt['findings'] as $f) {
                if ($f['rule_name'] === 'PHISHTANK_CONFIRMED') {
                    $anyThreatDetected = true;
                    $evidences[] = Evidence::create(
                        'phishtank_hit',
                        true,
                        $source,
                        [
                            'provider' => 'PhishTank',
                            'detail'   => $f['description'] ?? 'Terverifikasi aktif sebagai situs phishing oleh PhishTank.'
                        ],
                        1.0
                    );
                }
            }
        }

        // Jika ada database yang dicek dan hasilnya bersih
        if ($anySourceChecked && !$anyThreatDetected) {
            $evidences[] = Evidence::create(
                'threat_intel_clean',
                true,
                $source,
                [
                    'detail' => 'URL tidak tercantum pada database ancaman siber yang diperiksa.'
                ],
                0.9
            );
        }

        return $evidences;
    }

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
            CURLOPT_USERAGENT      => 'LinkTester/2.0',
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 200 && !empty($response)) {
            $data = json_decode($response, true);
            if (isset($data['query_status']) && $data['query_status'] === 'ok') {
                return [
                    'is_malicious' => true,
                    'threat'       => $data['threat'] ?? 'Malicious URL',
                    'url_status'   => $data['url_status'] ?? 'online',
                ];
            }
        }

        return ['is_malicious' => false];
    }

    private function checkGoogleSafeBrowsing(string $url, string $apiKey): array
    {
        $endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . urlencode($apiKey);

        $payload = [
            'client' => [
                'clientId'      => 'link-tester-app',
                'clientVersion' => '2.0.0',
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

    private function checkVirusTotal(string $url, string $apiKey): array
    {
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
                'positives'    => $malicious,
            ];
        }

        return ['is_malicious' => false, 'positives' => 0];
    }
}
