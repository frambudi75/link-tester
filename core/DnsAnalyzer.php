<?php
/**
 * DNS Record Analyzer - LinkTester v2.0
 * Memeriksa SPF, DMARC, dan MX records untuk menilai legitimasi domain.
 */

class DnsAnalyzer
{
    /**
     * Analisis DNS records sebuah domain
     */
    public static function analyze(string $domain): array
    {
        $findings = [];
        $penalty = 0;

        if (empty($domain) || filter_var($domain, FILTER_VALIDATE_IP)) {
            return [
                'findings' => $findings,
                'penalty'  => 0,
                'details'  => [
                    'has_spf'   => null,
                    'has_dmarc' => null,
                    'has_mx'    => null,
                    'spf_record'   => null,
                    'dmarc_record' => null,
                    'mx_records'   => [],
                    'ns_records'   => [],
                ],
            ];
        }

        $details = [
            'has_spf'      => false,
            'has_dmarc'    => false,
            'has_mx'       => false,
            'spf_record'   => null,
            'dmarc_record' => null,
            'mx_records'   => [],
            'ns_records'   => [],
        ];

        // 1. Cek SPF Record
        $spfResult = self::checkSpf($domain);
        $details['has_spf'] = $spfResult['exists'];
        $details['spf_record'] = $spfResult['record'];

        if (!$spfResult['exists']) {
            $findings[] = [
                'rule_name'    => 'DNS_NO_SPF',
                'category'     => 'dns',
                'severity'     => 'low',
                'score_impact' => 10,
                'description'  => 'Domain tidak memiliki record SPF (Sender Policy Framework). Domain resmi biasanya mengonfigurasi SPF untuk mencegah spoofing email.',
            ];
            $penalty += 10;
        } elseif ($spfResult['is_permissive']) {
            $findings[] = [
                'rule_name'    => 'DNS_SPF_PERMISSIVE',
                'category'     => 'dns',
                'severity'     => 'info',
                'score_impact' => 0,
                'description'  => 'SPF record ditemukan namun bersifat permisif (+all). Konfigurasi ini memperbolehkan siapapun mengirim email atas nama domain ini.',
            ];
        }

        // 2. Cek DMARC Record
        $dmarcResult = self::checkDmarc($domain);
        $details['has_dmarc'] = $dmarcResult['exists'];
        $details['dmarc_record'] = $dmarcResult['record'];

        if (!$dmarcResult['exists']) {
            $findings[] = [
                'rule_name'    => 'DNS_NO_DMARC',
                'category'     => 'dns',
                'severity'     => 'low',
                'score_impact' => 10,
                'description'  => 'Domain tidak memiliki record DMARC (Domain-based Message Authentication). Ini menunjukkan kurangnya konfigurasi keamanan email yang biasa dimiliki organisasi profesional.',
            ];
            $penalty += 10;
        }

        // 3. Cek MX Record
        $mxResult = self::checkMx($domain);
        $details['has_mx'] = $mxResult['exists'];
        $details['mx_records'] = $mxResult['records'];

        if (!$mxResult['exists']) {
            $findings[] = [
                'rule_name'    => 'DNS_NO_MX',
                'category'     => 'dns',
                'severity'     => 'low',
                'score_impact' => 5,
                'description'  => 'Domain tidak memiliki record MX (mail server). Domain yang didedikasikan hanya untuk phishing biasanya tidak mengonfigurasi layanan email.',
            ];
            $penalty += 5;
        }

        // 4. Cek NS Record
        $nsRecords = self::checkNs($domain);
        $details['ns_records'] = $nsRecords;

        // Bonus: jika domain punya SPF + DMARC + MX → sinyal positif
        if ($details['has_spf'] && $details['has_dmarc'] && $details['has_mx']) {
            $findings[] = [
                'rule_name'    => 'DNS_FULL_CONFIG',
                'category'     => 'dns',
                'severity'     => 'info',
                'score_impact' => -10,
                'description'  => 'Domain memiliki konfigurasi DNS lengkap (SPF + DMARC + MX). Ini menunjukkan domain dikelola secara profesional.',
            ];
            $penalty -= 10;
        }

        return [
            'findings' => $findings,
            'penalty'  => max(0, $penalty),
            'details'  => $details,
        ];
    }

    /**
     * Cek SPF record via DNS TXT
     */
    private static function checkSpf(string $domain): array
    {
        $txtRecords = @dns_get_record($domain, DNS_TXT);
        if (!is_array($txtRecords)) {
            return ['exists' => false, 'record' => null, 'is_permissive' => false];
        }

        foreach ($txtRecords as $record) {
            $txt = $record['txt'] ?? '';
            if (stripos($txt, 'v=spf1') === 0) {
                return [
                    'exists'        => true,
                    'record'        => $txt,
                    'is_permissive' => str_contains(strtolower($txt), '+all'),
                ];
            }
        }

        return ['exists' => false, 'record' => null, 'is_permissive' => false];
    }

    /**
     * Cek DMARC record via DNS TXT (_dmarc.domain)
     */
    private static function checkDmarc(string $domain): array
    {
        $dmarcDomain = '_dmarc.' . $domain;
        $txtRecords = @dns_get_record($dmarcDomain, DNS_TXT);
        if (!is_array($txtRecords)) {
            return ['exists' => false, 'record' => null];
        }

        foreach ($txtRecords as $record) {
            $txt = $record['txt'] ?? '';
            if (stripos($txt, 'v=DMARC1') === 0 || stripos($txt, 'v=dmarc1') === 0) {
                return ['exists' => true, 'record' => $txt];
            }
        }

        return ['exists' => false, 'record' => null];
    }

    /**
     * Cek MX record
     */
    private static function checkMx(string $domain): array
    {
        $mxRecords = @dns_get_record($domain, DNS_MX);
        if (!is_array($mxRecords) || empty($mxRecords)) {
            return ['exists' => false, 'records' => []];
        }

        $records = array_map(fn($r) => $r['target'] ?? '', $mxRecords);
        $records = array_filter($records);

        return ['exists' => !empty($records), 'records' => array_values($records)];
    }

    /**
     * Cek NS record
     */
    private static function checkNs(string $domain): array
    {
        $nsRecords = @dns_get_record($domain, DNS_NS);
        if (!is_array($nsRecords) || empty($nsRecords)) {
            return [];
        }

        return array_values(array_filter(array_map(fn($r) => $r['target'] ?? '', $nsRecords)));
    }
}
