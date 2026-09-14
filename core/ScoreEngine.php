<?php
/**
 * Score & Verdict Engine - LinkTester
 * Menghitung skor risiko gabungan (0 - 100) dan menyusun rekomendasi mitigasi.
 */

class ScoreEngine
{
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Hitung total skor risiko dan tentukan verdict
     */
    public function evaluate(
        array $heuristicResult,
        array $whoisResult,
        array $threatIntelResult,
        ?array $reputationDb = null
    ): array {
        $findings = array_merge(
            $heuristicResult['findings'] ?? [],
            $whoisResult['findings'] ?? [],
            $threatIntelResult['findings'] ?? []
        );

        $baseScore = 0;

        // Cek Whitelist & Blacklist lokal dari database
        if ($reputationDb) {
            if (!empty($reputationDb['is_whitelisted'])) {
                return [
                    'risk_score' => 0,
                    'verdict' => 'safe',
                    'findings' => array_merge([[
                        'rule_name' => 'LOCAL_WHITELIST_HIT',
                        'category' => 'reputation',
                        'severity' => 'info',
                        'score_impact' => 0,
                        'description' => 'DOMAIN RESMI TERVERIFIKASI: Domain ini tercatat dalam daftar putih (whitelist) resmi terpercaya.',
                    ]], $findings),
                    'recommendations' => [
                        'Domain ini terverifikasi aman dan merupakan situs resmi.',
                        'Tetap periksa sertifikat SSL di address bar peramban Anda.',
                    ],
                ];
            }

            if (!empty($reputationDb['is_blacklisted'])) {
                $baseScore = 100;
                $findings[] = [
                    'rule_name' => 'LOCAL_BLACKLIST_HIT',
                    'category' => 'reputation',
                    'severity' => 'critical',
                    'score_impact' => 100,
                    'description' => 'DOMAIN TERDAFTAR BLACKLIST: Domain ini telah dimasukkan ke daftar hitam situs berbahaya/penipuan oleh analis keamanan.',
                ];
            }
        }

        // Akumulasi penalti
        $totalPenalty = $baseScore
            + ($heuristicResult['penalty'] ?? 0)
            + ($whoisResult['penalty'] ?? 0)
            + ($threatIntelResult['penalty'] ?? 0);

        // Jika ada temuan berstatus CRITICAL (misal URLhaus / Google Safe Browsing / direct APK download),
        // paksa skor minimal 80 (DANGEROUS)
        $hasCritical = false;
        foreach ($findings as $f) {
            if (($f['severity'] ?? '') === 'critical') {
                $hasCritical = true;
                break;
            }
        }

        if ($hasCritical) {
            $totalPenalty = max(80, $totalPenalty);
        }

        // Normalisasi skor ke rentang 0 - 100
        $riskScore = max(0, min(100, (int) round($totalPenalty)));

        // Tentukan Verdict
        $safeMax = $this->config['thresholds']['safe_max'] ?? 25;
        $suspiciousMax = $this->config['thresholds']['suspicious_max'] ?? 60;

        if ($riskScore <= $safeMax) {
            $verdict = 'safe';
        } elseif ($riskScore <= $suspiciousMax) {
            $verdict = 'suspicious';
        } else {
            $verdict = 'dangerous';
        }

        // Susun saran mitigasi edukatif
        $recommendations = $this->generateRecommendations($verdict, $findings);

        return [
            'risk_score' => $riskScore,
            'verdict' => $verdict,
            'findings' => $findings,
            'recommendations' => $recommendations,
        ];
    }

    /**
     * Susun panduan keamanan praktis sesuai level bahaya
     */
    private function generateRecommendations(string $verdict, array $findings): array
    {
        $tips = [];

        if ($verdict === 'dangerous') {
            $tips[] = 'JANGAN BUKA link ini atau klik apapun di dalamnya!';
            $tips[] = 'JANGAN PERNAH mengunduh atau menginstal file berekstensi .apk, .exe, atau sejenisnya.';
            $tips[] = 'JANGAN masukkan password, nomor kartu ATM/kredit, atau kode OTP.';
            $tips[] = 'Jika sudah terlanjur membuka dan memasukkan data, segera ganti password akun Anda dan blokir kartu perbankan Anda.';
        } elseif ($verdict === 'suspicious') {
            $tips[] = 'Harap berhati-hati. Link ini menunjukkan beberapa kejanggalan atau baru saja dibuat.';
            $tips[] = 'Pastikan nama domain di address bar benar-benar milik institusi resmi sebelum berinteraksi.';
            $tips[] = 'Hindari mengunduh file atau melakukan transfer uang melalui instruksi pada halaman tersebut.';
        } else {
            $tips[] = 'Link ini tidak menunjukkan indikator ancaman yang dikenal.';
            $tips[] = 'Tetap biasakan memeriksa gembok keamanan (HTTPS) saat melakukan transaksi sensitif.';
        }

        return $tips;
    }
}
