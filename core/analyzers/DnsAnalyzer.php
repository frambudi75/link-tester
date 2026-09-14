<?php
/**
 * DNS Analyzer - LinkTester
 * 
 * Memeriksa konfigurasi DNS: SPF, DMARC, MX, dan NS records untuk menilai
 * integritas operasional domain.
 * 
 * Menghasilkan Evidence objects untuk diproses oleh RiskScorer.
 */

require_once __DIR__ . '/../Evidence.php';

class DnsAnalyzer
{
    /**
     * Analisis DNS records dari domain target.
     * 
     * @param string $domain Nama domain murni
     * @return array ['evidences' => Evidence[], 'details' => array]
     */
    public static function analyze(string $domain): array
    {
        $evidences = [];
        $source = 'dns';

        $details = [
            'has_spf'      => false,
            'has_dmarc'    => false,
            'has_mx'       => false,
            'spf_record'   => null,
            'dmarc_record' => null,
            'mx_records'   => [],
            'ns_records'   => [],
        ];

        if (empty($domain) || filter_var($domain, FILTER_VALIDATE_IP)) {
            return ['evidences' => $evidences, 'details' => $details];
        }

        // 1. Cek SPF Record
        $spf = self::checkSpf($domain);
        $details['has_spf'] = $spf['exists'];
        $details['spf_record'] = $spf['record'];

        if (!$spf['exists']) {
            $evidences[] = Evidence::create(
                'dns_no_spf',
                true,
                $source,
                ['detail' => 'Domain tidak memiliki record SPF (Sender Policy Framework). Domain resmi umumnya mengonfigurasi SPF.'],
                0.7
            );
        } elseif (!empty($spf['is_permissive'])) {
            $evidences[] = Evidence::create(
                'dns_spf_permissive',
                true,
                $source,
                ['detail' => 'SPF record bersifat permisif (+all), memungkinkan siapa pun memalsukan email dari domain ini.'],
                0.6
            );
        }

        // 2. Cek DMARC Record
        $dmarc = self::checkDmarc($domain);
        $details['has_dmarc'] = $dmarc['exists'];
        $details['dmarc_record'] = $dmarc['record'];

        if (!$dmarc['exists']) {
            $evidences[] = Evidence::create(
                'dns_no_dmarc',
                true,
                $source,
                ['detail' => 'Domain tidak mengaktifkan proteksi email DMARC.'],
                0.65
            );
        }

        // 3. Cek MX Record
        $mx = self::checkMx($domain);
        $details['has_mx'] = $mx['exists'];
        $details['mx_records'] = $mx['records'];

        if (!$mx['exists']) {
            $evidences[] = Evidence::create(
                'dns_no_mx',
                true,
                $source,
                ['detail' => 'Domain tidak memiliki server email MX yang terkonfigurasi.'],
                0.6
            );
        }

        // 4. NS Records
        $details['ns_records'] = self::checkNs($domain);

        // Good Reputation Signal: Domain memiliki SPF + DMARC + MX
        if ($details['has_spf'] && $details['has_dmarc'] && $details['has_mx']) {
            $evidences[] = Evidence::create(
                'dns_full_config',
                true,
                $source,
                ['detail' => 'Domain memiliki infrastruktur DNS profesional lengkap (SPF, DMARC, MX).'],
                0.9
            );
        }

        return ['evidences' => $evidences, 'details' => $details];
    }

    private static function checkSpf(string $domain): array
    {
        $records = @dns_get_record($domain, DNS_TXT);
        if (!is_array($records)) {
            return ['exists' => false, 'record' => null, 'is_permissive' => false];
        }

        foreach ($records as $r) {
            $txt = $r['txt'] ?? '';
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

    private static function checkDmarc(string $domain): array
    {
        $dmarcDomain = '_dmarc.' . $domain;
        $records = @dns_get_record($dmarcDomain, DNS_TXT);
        if (!is_array($records)) {
            return ['exists' => false, 'record' => null];
        }

        foreach ($records as $r) {
            $txt = $r['txt'] ?? '';
            if (stripos($txt, 'v=DMARC1') === 0 || stripos($txt, 'v=dmarc1') === 0) {
                return ['exists' => true, 'record' => $txt];
            }
        }

        return ['exists' => false, 'record' => null];
    }

    private static function checkMx(string $domain): array
    {
        $records = @dns_get_record($domain, DNS_MX);
        if (!is_array($records) || empty($records)) {
            return ['exists' => false, 'records' => []];
        }

        $targets = array_filter(array_map(fn($r) => $r['target'] ?? '', $records));
        return ['exists' => !empty($targets), 'records' => array_values($targets)];
    }

    private static function checkNs(string $domain): array
    {
        $records = @dns_get_record($domain, DNS_NS);
        if (!is_array($records) || empty($records)) {
            return [];
        }

        return array_values(array_filter(array_map(fn($r) => $r['target'] ?? '', $records)));
    }
}
