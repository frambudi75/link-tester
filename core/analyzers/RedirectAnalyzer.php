<?php
/**
 * Redirect Analyzer - LinkTester
 * 
 * Menganalisis perilaku pengalihan URL, rantai redirect (hops), cloaking,
 * cross-domain jumping, serta Traffic Distribution System (TDS).
 * 
 * Menghasilkan Evidence objects untuk diproses oleh RiskScorer.
 */

require_once __DIR__ . '/../Evidence.php';

class RedirectAnalyzer
{
    /**
     * Analisis rantai pengalihan URL.
     * 
     * @param array $redirectInfo Hasil dari SafeUrlResolver::traceRedirects()
     * @return Evidence[] Daftar bukti redirect
     */
    public static function analyze(array $redirectInfo): array
    {
        $evidences = [];
        $source = 'redirect';

        $redirectCount = $redirectInfo['redirect_count'] ?? 0;
        $isCrossDomain = !empty($redirectInfo['is_cross_domain']);
        $origDomain    = $redirectInfo['original_domain'] ?? '';
        $finalDomain   = $redirectInfo['final_domain'] ?? '';
        $chain         = $redirectInfo['redirect_chain'] ?? [];
        $hasTds        = !empty($redirectInfo['has_tds_router']);

        // 1. Redirect Count
        $evidences[] = Evidence::create(
            'redirect_count',
            $redirectCount,
            $source,
            [
                'count' => $redirectCount,
                'total_hops' => $redirectCount,
                'chain_length' => count($chain)
            ],
            1.0
        );

        // 2. Cross Domain Redirect (Cloaking)
        if ($isCrossDomain) {
            $evidences[] = Evidence::create(
                'cross_domain_redirect',
                true,
                $source,
                [
                    'original_domain' => $origDomain,
                    'final_domain'    => $finalDomain,
                    'detail'          => 'Tautan awal menunjuk ke "' . $origDomain . '", namun dialihkan ke domain berbeda "' . $finalDomain . '".'
                ],
                0.95
            );
        }

        // 3. Excessive Redirects (Rantai Lompatan >= 2)
        if ($redirectCount >= 2) {
            $evidences[] = Evidence::create(
                'excessive_redirects',
                $redirectCount,
                $source,
                [
                    'count'  => $redirectCount,
                    'detail' => 'Tautan dialihkan sebanyak ' . $redirectCount . ' kali beruntun sebelum sampai di tujuan akhir.'
                ],
                0.85
            );
        }

        // 4. Traffic Distribution System (TDS) / Ad Cloaker
        if ($hasTds) {
            $evidences[] = Evidence::create(
                'traffic_distribution_system',
                true,
                $source,
                [
                    'tds_signatures' => $redirectInfo['tds_signatures'] ?? [],
                    'detail'         => 'Halaman menggunakan skrip Traffic Distribution System (TDS) / Ad-Router untuk memutar pengunjung dinamis ke landing page/iklan mencurigakan.'
                ],
                0.9
            );
        }

        // 5. Scheme Downgrade (HTTPS -> HTTP)
        $schemes = [];
        foreach ($chain as $hop) {
            if (!empty($hop['scheme'])) {
                $schemes[] = strtolower($hop['scheme']);
            }
        }
        for ($i = 0; $i < count($schemes) - 1; $i++) {
            if ($schemes[$i] === 'https' && $schemes[$i + 1] === 'http') {
                $evidences[] = Evidence::create(
                    'scheme_downgrade',
                    true,
                    $source,
                    [
                        'detail' => 'Rantai redirect mengalami penurunan keamanan dari HTTPS terenkripsi menjadi HTTP terbuka (SSL Striping indicator).'
                    ],
                    0.9
                );
                break;
            }
        }

        // 6. Redirect Loop or Max Hops Hit
        if (!empty($redirectInfo['loop_detected'])) {
            $evidences[] = Evidence::create(
                'redirect_loop_detected',
                true,
                $source,
                [
                    'detail' => 'Terdeteksi perputaran redirect tanpa akhir (Redirect Loop).'
                ],
                1.0
            );
        }

        return $evidences;
    }
}
