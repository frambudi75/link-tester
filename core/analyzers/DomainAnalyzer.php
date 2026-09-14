<?php
/**
 * Domain Analyzer - LinkTester
 * 
 * Memeriksa reputasi dan metadata domain via RDAP (Registration Data Access Protocol).
 * Menghasilkan Evidence objects untuk usia domain, registrar, dan status pendaftaran.
 */

require_once __DIR__ . '/../Evidence.php';

class DomainAnalyzer
{
    /**
     * Analisis domain dan kembalikan array Evidence.
     * 
     * @param string $domain Nama domain murni (misal: "example.com")
     * @return Evidence[] Daftar bukti domain
     */
    public static function analyze(string $domain): array
    {
        $evidences = [];
        $source = 'domain';

        if (empty($domain) || filter_var($domain, FILTER_VALIDATE_IP)) {
            return $evidences;
        }

        $info = self::queryRdap($domain);
        $ageDays = $info['age_days'] ?? null;
        $registeredDate = $info['registered_date'] ?? null;
        $registrar = $info['registrar'] ?? null;

        if ($ageDays !== null) {
            $meta = [
                'age_days'        => $ageDays,
                'registered_date' => $registeredDate,
                'registrar'       => $registrar,
            ];

            // Base evidence: Usia domain dalam hari
            $evidences[] = Evidence::create('domain_age_days', $ageDays, $source, $meta, 1.0);

            if ($ageDays <= 14) {
                $evidences[] = Evidence::create(
                    'domain_very_new',
                    true,
                    $source,
                    array_merge($meta, [
                        'detail' => 'Domain baru berumur ' . $ageDays . ' hari (< 14 hari). Domain baru sangat rentan dipakai phishing disposable.'
                    ]),
                    0.9
                );
            } elseif ($ageDays <= 30) {
                $evidences[] = Evidence::create(
                    'domain_new',
                    true,
                    $source,
                    array_merge($meta, [
                        'detail' => 'Domain berumur ' . $ageDays . ' hari (< 30 hari).'
                    ]),
                    0.8
                );
            } elseif ($ageDays >= 365) {
                $evidences[] = Evidence::create(
                    'domain_established',
                    true,
                    $source,
                    array_merge($meta, [
                        'years' => round($ageDays / 365, 1),
                        'detail' => 'Domain telah aktif selama ' . round($ageDays / 365, 1) . ' tahun. Menunjukkan kredibilitas mapan.'
                    ]),
                    0.9
                );
            }

            if (!empty($registrar)) {
                $evidences[] = Evidence::create(
                    'domain_registrar',
                    $registrar,
                    $source,
                    ['registrar' => $registrar],
                    1.0
                );
            }
        }

        return $evidences;
    }

    /**
     * Query data RDAP publik via HTTP REST
     */
    private static function queryRdap(string $domain): array
    {
        $url = 'https://rdap.org/domain/' . urlencode($domain);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 3,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT      => 'LinkTester/2.0 (Security Scanner)',
            CURLOPT_HTTPHEADER     => ['Accept: application/rdap+json, application/json'],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || empty($response)) {
            return [];
        }

        $data = json_decode($response, true);
        if (!is_array($data)) {
            return [];
        }

        $registeredDate = null;
        $registrar = null;

        // Ambil event registration
        if (isset($data['events']) && is_array($data['events'])) {
            foreach ($data['events'] as $event) {
                $action = strtolower($event['eventAction'] ?? '');
                if (in_array($action, ['registration', 'registered'], true)) {
                    $registeredDate = $event['eventDate'] ?? null;
                    break;
                }
            }
        }

        // Ambil nama registrar jika ada
        if (isset($data['entities']) && is_array($data['entities'])) {
            foreach ($data['entities'] as $entity) {
                $roles = $entity['roles'] ?? [];
                if (in_array('registrar', $roles, true)) {
                    $registrar = $entity['vcardArray'][1][1][3] ?? ($entity['handle'] ?? null);
                    break;
                }
            }
        }

        $ageDays = null;
        if ($registeredDate) {
            $regTime = strtotime($registeredDate);
            if ($regTime > 0) {
                $ageDays = max(0, (int) floor((time() - $regTime) / 86400));
            }
        }

        return [
            'registered_date' => $registeredDate ? date('Y-m-d', strtotime($registeredDate)) : null,
            'registrar'       => $registrar,
            'age_days'        => $ageDays,
        ];
    }
}
