<?php
/**
 * Domain Intelligence & WHOIS/RDAP Checker - LinkTester
 * Memeriksa tanggal lahir domain via protokol standar RDAP (Registration Data Access Protocol)
 */

class WhoisLookup
{
    /**
     * Dapatkan informasi domain (Umur dalam hari, Registrar, Tanggal Buat)
     */
    public static function check(string $domain): array
    {
        if (filter_var($domain, FILTER_VALIDATE_IP) || empty($domain)) {
            return [
                'domain_age_days' => null,
                'registered_date' => null,
                'registrar' => null,
                'findings' => [],
                'penalty' => 0,
            ];
        }

        $info = self::queryRdap($domain);
        $ageDays = $info['age_days'] ?? null;
        $findings = [];
        $penalty = 0;

        if ($ageDays !== null) {
            if ($ageDays <= 14) {
                $findings[] = [
                    'rule_name' => 'DOMAIN_VERY_NEW',
                    'category' => 'whois',
                    'severity' => 'high',
                    'score_impact' => 35,
                    'description' => 'Domain ini SANGAT BARU terdaftar (kurang dari ' . $ageDays . ' hari yang lalu). Lebih dari 70% link phishing menggunakan domain yang berumur kurang dari 2 minggu.',
                ];
                $penalty += 35;
            } elseif ($ageDays <= 30) {
                $findings[] = [
                    'rule_name' => 'DOMAIN_NEW',
                    'category' => 'whois',
                    'severity' => 'medium',
                    'score_impact' => 20,
                    'description' => 'Domain tergolong baru terdaftar (' . $ageDays . ' hari yang lalu). Harap berhati-hati sebelum membagikan informasi rahasia.',
                ];
                $penalty += 20;
            } elseif ($ageDays >= 365) {
                $findings[] = [
                    'rule_name' => 'DOMAIN_ESTABLISHED',
                    'category' => 'whois',
                    'severity' => 'info',
                    'score_impact' => -15,
                    'description' => 'Domain sudah berumur mapan (' . round($ageDays / 365, 1) . ' tahun). Domain yang telah aktif bertahun-tahun cenderung memiliki kredibilitas lebih tinggi.',
                ];
                $penalty -= 15;
            }
        }

        return [
            'domain_age_days' => $ageDays,
            'registered_date' => $info['registered_date'] ?? null,
            'registrar' => $info['registrar'] ?? null,
            'findings' => $findings,
            'penalty' => $penalty,
        ];
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
            CURLOPT_USERAGENT      => 'LinkTester/1.0 (Security Scanner)',
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
            'registrar' => $registrar,
            'age_days' => $ageDays,
        ];
    }
}
