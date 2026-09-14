<?php
/**
 * Risk Scorer - LinkTester
 * 
 * Sentralisasi kalkulasi skor risiko dan penentuan verdict berbasis Evidence Layer.
 * Menerima Evidence objects dari seluruh analyzer, memetakan ke rule engine,
 * menghitung skor 0–100, menentukan 5-tier verdict, dan menyusun penjelasan investigatif.
 */

require_once __DIR__ . '/Evidence.php';

class RiskScorer
{
    private array $config;

    /**
     * Definisi bobot dan metadata untuk setiap detection signal.
     */
    private array $ruleDefinitions = [
        // Heuristic signals
        'ip_as_host' => [
            'weight'      => 40,
            'severity'    => 'high',
            'title'       => 'Direct IP Address Host',
            'category'    => 'heuristic',
            'description' => 'URL mengarah langsung ke alamat IP numerik tanpa nama domain terdaftar (sering dipakai C2 malware / phishing).'
        ],
        'punycode_detected' => [
            'weight'      => 35,
            'severity'    => 'high',
            'title'       => 'Homoglyph / Punycode Deception',
            'category'    => 'heuristic',
            'description' => 'URL menggunakan encoding Punycode untuk meniru alfabet latin dengan karakter aksara asing serupa (Homograph attack).'
        ],
        'subdomain_deception' => [
            'weight'      => 40,
            'severity'    => 'high',
            'title'       => 'Subdomain Deception',
            'category'    => 'heuristic',
            'description' => 'Nama brand resmi diselipkan pada subdomain untuk mengelabui pengguna dari domain asli.'
        ],
        'suspicious_tld' => [
            'weight'      => 20,
            'severity'    => 'medium',
            'title'       => 'Suspicious Top-Level Domain (TLD)',
            'category'    => 'heuristic',
            'description' => 'Domain menggunakan ekstensi TLD yang memiliki reputasi buruk atau sering disalahgunakan untuk spam/phishing.'
        ],
        'phishing_keywords' => [
            'weight'      => 25,
            'severity'    => 'medium',
            'title'       => 'Sensitive Credential Keywords',
            'category'    => 'heuristic',
            'description' => 'Ditemukan kombinasi kata kunci yang lazim digunakan dalam rekayasa sosial atau pencurian kredensial.'
        ],
        'excessive_dashes' => [
            'weight'      => 15,
            'severity'    => 'low',
            'title'       => 'Excessive Hyphens in Hostname',
            'category'    => 'heuristic',
            'description' => 'Hostname mengandung banyak tanda hubung (-) untuk menyamarkan tautan agar menyerupai nama institusi resmi.'
        ],
        'at_symbol_in_url' => [
            'weight'      => 30,
            'severity'    => 'medium',
            'title'       => 'Host Deception via @ Symbol',
            'category'    => 'heuristic',
            'description' => 'Simbol @ dalam URL digunakan untuk mengecoh pembacaan nama host pada peramban web.'
        ],
        'non_standard_port' => [
            'weight'      => 20,
            'severity'    => 'low',
            'title'       => 'Non-Standard Network Port',
            'category'    => 'heuristic',
            'description' => 'URL menggunakan port non-standar (di luar 80, 443, 8080, 8443).'
        ],
        'http_no_ssl' => [
            'weight'      => 10,
            'severity'    => 'low',
            'title'       => 'Unencrypted HTTP Connection',
            'category'    => 'heuristic',
            'description' => 'Koneksi tidak menggunakan enkripsi TLS/SSL sehingga rentan intersepsi Man-in-the-Middle.'
        ],
        'dangerous_file_ext' => [
            'weight'      => 50,
            'severity'    => 'critical',
            'title'       => 'Executable File Download Link',
            'category'    => 'heuristic',
            'description' => 'Tautan mengarah langsung ke unduhan file eksekusi/installer (.apk, .exe) yang umum dipakai payload malware.'
        ],
        'deep_subdomains' => [
            'weight'      => 15,
            'severity'    => 'low',
            'title'       => 'Excessive Subdomain Depth',
            'category'    => 'heuristic',
            'description' => 'Hierarki subdomain memiliki 3 tingkat atau lebih.'
        ],

        // Domain signals
        'domain_very_new' => [
            'weight'      => 35,
            'severity'    => 'high',
            'title'       => 'Newly Registered Domain (< 14 Days)',
            'category'    => 'domain',
            'description' => 'Domain baru berumur kurang dari 14 hari. Sebagian besar infrastruktur phishing berumur sangat muda.'
        ],
        'domain_new' => [
            'weight'      => 20,
            'severity'    => 'medium',
            'title'       => 'Recent Domain Registration (< 30 Days)',
            'category'    => 'domain',
            'description' => 'Domain baru didaftarkan dalam 30 hari terakhir.'
        ],
        'domain_established' => [
            'weight'      => -15,
            'severity'    => 'info',
            'title'       => 'Established Domain History',
            'category'    => 'domain',
            'description' => 'Domain telah berumur mapan (>= 1 tahun), menunjukkan reputasi keberlanjutan yang baik.'
        ],

        // Redirect signals
        'cross_domain_redirect' => [
            'weight'      => 35,
            'severity'    => 'high',
            'title'       => 'Cross-Domain Jumping (Cloaking)',
            'category'    => 'redirect',
            'description' => 'URL awal dialihkan ke domain yang berbeda (indikator cloaking atau tautan pancingan).'
        ],
        'excessive_redirects' => [
            'weight'      => 25,
            'severity'    => 'medium',
            'title'       => 'Multi-Hop Redirect Chain',
            'category'    => 'redirect',
            'description' => 'Tautan melewati pengalihan berantai 2 kali atau lebih untuk mengaburkan tujuan akhir.'
        ],
        'traffic_distribution_system' => [
            'weight'      => 40,
            'severity'    => 'high',
            'title'       => 'Traffic Distribution System (TDS) Detected',
            'category'    => 'redirect',
            'description' => 'Terdeteksi skrip Traffic Distribution System (TDS) yang merutekan target pengunjung secara dinamis.'
        ],
        'scheme_downgrade' => [
            'weight'      => 30,
            'severity'    => 'high',
            'title'       => 'SSL Striping / Protocol Downgrade',
            'category'    => 'redirect',
            'description' => 'Rantai redirect diturunkan dari koneksi HTTPS terenkripsi ke HTTP terbuka.'
        ],
        'redirect_loop_detected' => [
            'weight'      => 25,
            'severity'    => 'medium',
            'title'       => 'Circular Redirect Loop',
            'category'    => 'redirect',
            'description' => 'Pengalihan URL terjebak dalam perputaran tanpa akhir.'
        ],

        // Threat Intel signals
        'urlhaus_hit' => [
            'weight'      => 80,
            'severity'    => 'critical',
            'title'       => 'Active Malware Distribution (URLhaus)',
            'category'    => 'threat_intel',
            'description' => 'URL tercatat aktif menyebarkan malware pada basis data abuse.ch URLhaus.'
        ],
        'google_safebrowsing_hit' => [
            'weight'      => 80,
            'severity'    => 'critical',
            'title'       => 'Google Safe Browsing Flag',
            'category'    => 'threat_intel',
            'description' => 'Google Safe Browsing menandai URL ini sebagai malware atau social engineering.'
        ],
        'virustotal_hit' => [
            'weight'      => 75,
            'severity'    => 'critical',
            'title'       => 'VirusTotal Multi-Engine Flag',
            'category'    => 'threat_intel',
            'description' => 'Beberapa antivirus/security engine mendeteksi URL ini berbahaya di VirusTotal.'
        ],
        'phishtank_hit' => [
            'weight'      => 80,
            'severity'    => 'critical',
            'title'       => 'PhishTank Verified Phishing',
            'category'    => 'threat_intel',
            'description' => 'Terverifikasi aktif sebagai situs phishing oleh komunitas riset PhishTank.'
        ],

        // SSL signals
        'ssl_expired' => [
            'weight'      => 25,
            'severity'    => 'high',
            'title'       => 'Expired SSL/TLS Certificate',
            'category'    => 'ssl',
            'description' => 'Sertifikat keamanan situs telah kedaluwarsa.'
        ],
        'ssl_self_signed' => [
            'weight'      => 30,
            'severity'    => 'high',
            'title'       => 'Self-Signed Certificate',
            'category'    => 'ssl',
            'description' => 'Sertifikat SSL ditandatangani sendiri dan tidak divalidasi oleh Certificate Authority terpercaya.'
        ],
        'ssl_fetch_failed' => [
            'weight'      => 20,
            'severity'    => 'medium',
            'title'       => 'SSL Handshake Failure',
            'category'    => 'ssl',
            'description' => 'Gagal menegosiasikan enkripsi SSL/TLS dengan server.'
        ],
        'ssl_expiring_soon' => [
            'weight'      => 5,
            'severity'    => 'low',
            'title'       => 'SSL Certificate Expiring Soon',
            'category'    => 'ssl',
            'description' => 'Sertifikat keamanan akan kedaluwarsa dalam 7 hari.'
        ],

        // Content signals
        'phishing_login_form' => [
            'weight'      => 35,
            'severity'    => 'high',
            'title'       => 'Credential Harvesting Login Form',
            'category'    => 'content',
            'description' => 'Halaman menyajikan formulir input password (potensi pencurian akun).'
        ],
        'hidden_iframe' => [
            'weight'      => 30,
            'severity'    => 'high',
            'title'       => 'Hidden / Invisible Iframe',
            'category'    => 'content',
            'description' => 'Ditemukan iframe tak terlihat untuk memuat payload tersembunyi.'
        ],
        'crypto_miner' => [
            'weight'      => 40,
            'severity'    => 'critical',
            'title'       => 'Browser Cryptocurrency Miner',
            'category'    => 'content',
            'description' => 'Skrip terdeteksi mengeksploitasi resource CPU/GPU pengunjung untuk menambang kripto.'
        ],
        'obfuscated_javascript' => [
            'weight'      => 20,
            'severity'    => 'medium',
            'title'       => 'Obfuscated JavaScript Code',
            'category'    => 'content',
            'description' => 'Kode JavaScript disamarkan menggunakan fungsi enkoding/eval untuk menghindari deteksi.'
        ],
        'auto_download_trigger' => [
            'weight'      => 35,
            'severity'    => 'high',
            'title'       => 'Automatic Drive-by Download',
            'category'    => 'content',
            'description' => 'Halaman mencoba memaksa browser mengunduh file secara otomatis.'
        ],

        // DNS signals
        'dns_no_spf' => [
            'weight'      => 10,
            'severity'    => 'low',
            'title'       => 'Missing SPF DNS Record',
            'category'    => 'dns',
            'description' => 'Domain tidak memiliki konfigurasi SPF untuk validasi pengiriman email.'
        ],
        'dns_no_dmarc' => [
            'weight'      => 10,
            'severity'    => 'low',
            'title'       => 'Missing DMARC Policy',
            'category'    => 'dns',
            'description' => 'Domain tidak menerapkan aturan proteksi DMARC anti-spoofing.'
        ],
        'dns_no_mx' => [
            'weight'      => 5,
            'severity'    => 'low',
            'title'       => 'No MX Mail Exchange Record',
            'category'    => 'dns',
            'description' => 'Domain tidak memiliki server email aktif.'
        ],
        'dns_full_config' => [
            'weight'      => -10,
            'severity'    => 'info',
            'title'       => 'Comprehensive DNS Hardening',
            'category'    => 'dns',
            'description' => 'Domain memiliki record SPF, DMARC, dan MX lengkap.'
        ],
    ];

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * Hitung total skor risiko, susun temuan terperinci, dan tentukan 5-tier verdict.
     * 
     * @param Evidence[] $evidences
     * @param array|null $localReputation Status whitelist/blacklist lokal
     * @return array
     */
    public function calculate(array $evidences, ?array $localReputation = null): array
    {
        $rawScore = 0;
        $findings = [];
        $hasCritical = false;

        // Cek Local Whitelist
        if (!empty($localReputation['is_whitelisted'])) {
            return [
                'risk_score'      => 0,
                'verdict'         => 'clean',
                'verdict_label'   => 'CLEAN',
                'verdict_color'   => '#22c55e',
                'findings'        => [[
                    'signal'      => 'local_whitelist',
                    'title'       => 'Verified Trusted Whitelist',
                    'category'    => 'reputation',
                    'severity'    => 'info',
                    'confidence'  => 1.0,
                    'weight'      => 0,
                    'explanation' => [
                        'title'    => 'Domain Resmi Terverifikasi',
                        'detail'   => 'Domain ini terdaftar dalam daftar putih (whitelist) resmi terpercaya.',
                        'evidence' => $localReputation
                    ]
                ]],
                'recommendations' => [
                    'Domain ini terverifikasi aman dan merupakan situs resmi.',
                    'Tetap pastikan gembok enkripsi SSL menyala di peramban Anda saat transaksi.'
                ]
            ];
        }

        // Cek Local Blacklist
        if (!empty($localReputation['is_blacklisted'])) {
            $rawScore = 100;
            $hasCritical = true;
            $findings[] = [
                'signal'      => 'local_blacklist',
                'title'       => 'Listed on Security Blacklist',
                'category'    => 'reputation',
                'severity'    => 'critical',
                'confidence'  => 1.0,
                'weight'      => 100,
                'explanation' => [
                    'title'    => 'Domain Terdaftar Blacklist',
                    'detail'   => 'Domain ini telah diblokir secara manual oleh analis keamanan karena terbukti berbahaya/penipuan.',
                    'evidence' => $localReputation
                ]
            ];
        }

        // Proses setiap Evidence
        foreach ($evidences as $ev) {
            if (!$ev instanceof Evidence) {
                continue;
            }

            $sig = $ev->signal;
            if (!isset($this->ruleDefinitions[$sig])) {
                continue;
            }

            $rule = $this->ruleDefinitions[$sig];
            $weight = $rule['weight'];
            $confidence = $ev->confidence;

            // Hitung dampak skor: weight * confidence
            $impact = (int) round($weight * $confidence);
            $rawScore += $impact;

            if ($rule['severity'] === 'critical') {
                $hasCritical = true;
            }

            $findings[] = [
                'signal'      => $sig,
                'title'       => $rule['title'],
                'category'    => $rule['category'],
                'severity'    => $rule['severity'],
                'confidence'  => $confidence,
                'weight'      => $impact,
                'explanation' => [
                    'title'    => $rule['title'],
                    'detail'   => $ev->metadata['detail'] ?? $rule['description'],
                    'evidence' => $ev->metadata
                ]
            ];
        }

        // Jika ada temuan CRITICAL, paksa minimal level High/Critical (minimal skor 86)
        if ($hasCritical) {
            $rawScore = max(86, $rawScore);
        }

        // Batasi rentang skor 0 - 100
        $riskScore = max(0, min(100, $rawScore));

        // 5-Tier Verdict Mapping
        $tier = $this->determineTier($riskScore);

        // Rekomendasi tindakan keamanan
        $recommendations = $this->generateRecommendations($tier['verdict'], $findings);

        return [
            'risk_score'      => $riskScore,
            'verdict'         => $tier['verdict'],
            'verdict_label'   => $tier['label'],
            'verdict_color'   => $tier['color'],
            'findings'        => $findings,
            'recommendations' => $recommendations,
        ];
    }

    /**
     * Tentukan 5-tier verdict dari skor risiko:
     * 0–15: clean
     * 16–40: low_risk
     * 41–65: medium_risk
     * 66–85: high_risk
     * 86–100: critical
     */
    private function determineTier(int $score): array
    {
        if ($score <= 15) {
            return ['verdict' => 'clean', 'label' => 'CLEAN', 'color' => '#22c55e'];
        }
        if ($score <= 40) {
            return ['verdict' => 'low_risk', 'label' => 'LOW RISK', 'color' => '#3b82f6'];
        }
        if ($score <= 65) {
            return ['verdict' => 'medium_risk', 'label' => 'MEDIUM RISK', 'color' => '#eab308'];
        }
        if ($score <= 85) {
            return ['verdict' => 'high_risk', 'label' => 'HIGH RISK', 'color' => '#f97316'];
        }
        return ['verdict' => 'critical', 'label' => 'CRITICAL', 'color' => '#ef4444'];
    }

    /**
     * Rekomendasi mitigasi berdasarkan verdict dan temuan.
     */
    private function generateRecommendations(string $verdict, array $findings): array
    {
        $recs = [];

        switch ($verdict) {
            case 'critical':
                $recs[] = 'BAHAYA TINGGI: JANGAN BUKA LINK INI! Link ini terindikasi kuat sebagai malware, phishing aktif, atau penipuan finansial.';
                $recs[] = 'JANGAN PERNAH mengunduh atau mengeksekusi file yang diberikan dari tautan ini (terutama file .apk atau .exe).';
                $recs[] = 'JANGAN memasukkan nomor rekening, PIN, password, ataupun kode OTP SMS/WhatsApp.';
                $recs[] = 'Jika sudah terlanjur membuka dan memasukkan data pribadi, SEGERA ubah password akun Anda dan hubungi bank terkait untuk blokir akun/kartu.';
                break;

            case 'high_risk':
                $recs[] = 'PERINGATAN: Tautan ini memiliki risiko tinggi. Terdapat anomali pengalihan atau manipulasi nama domain.';
                $recs[] = 'Hindari melakukan login atau mengisi formulir apapun pada halaman tujuan.';
                $recs[] = 'Cek address bar browser untuk memastikan ejaan domain sesuai dengan situs resmi yang Anda tuju.';
                break;

            case 'medium_risk':
                $recs[] = 'WASPADA: Ditemukan beberapa kejanggalan pada konfigurasi domain atau usia registrasi yang masih baru.';
                $recs[] = 'Periksa ulang keaslian pengirim sebelum mempercayai instruksi pada halaman tersebut.';
                $recs[] = 'Hindari mengunduh file atau mengizinkan notifikasi browser pada situs ini.';
                break;

            case 'low_risk':
                $recs[] = 'Tautan memiliki indikator risiko minor. Tetap waspada saat berinteraksi.';
                $recs[] = 'Pastikan koneksi menggunakan gembok keamanan SSL/TLS resmi.';
                break;

            case 'clean':
            default:
                $recs[] = 'Tidak ditemukan indikator ancaman yang mencurigakan.';
                $recs[] = 'Tetap biasakan memeriksa identitas situs web saat membagikan data sensitif.';
                break;
        }

        // Rekomendasi spesifik berdasarkan temuan
        $signals = array_column($findings, 'signal');

        if (in_array('dangerous_file_ext', $signals, true)) {
            $recs[] = 'PENTING: Tautan ini mengunduh file aplikasi secara langsung. Jangan instal aplikasi dari luar Google Play Store atau Apple App Store.';
        }
        if (in_array('crypto_miner', $signals, true)) {
            $recs[] = 'Tutup tab halaman ini segera untuk menghentikan pemborosan daya dan penambangan kripto ilegal di perangkat Anda.';
        }
        if (in_array('cross_domain_redirect', $signals, true) || in_array('traffic_distribution_system', $signals, true)) {
            $recs[] = 'Tautan menggunakan sistem pengalihan berantai (TDS). Halaman yang terbuka mungkin berbeda dari apa yang dijanjikan pengirim.';
        }
        if (in_array('ssl_expired', $signals, true) || in_array('ssl_self_signed', $signals, true)) {
            $recs[] = 'Enkripsi koneksi tidak valid atau kedaluwarsa — komunikasi Anda dapat diintip pihak ketiga.';
        }

        return array_unique($recs);
    }
}
