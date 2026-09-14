<?php
/**
 * SSL/TLS Certificate Checker - LinkTester v2.0
 * Memverifikasi validitas sertifikat SSL, tanggal berlaku, issuer, dan protocol version.
 */

class SslChecker
{
    /**
     * Periksa sertifikat SSL untuk sebuah URL
     */
    public static function check(string $url): array
    {
        $findings = [];
        $penalty = 0;
        $sslInfo = [
            'is_https'       => false,
            'ssl_valid'      => null,
            'ssl_issuer'     => null,
            'ssl_subject'    => null,
            'ssl_protocol'   => null,
            'ssl_expires'    => null,
            'ssl_days_left'  => null,
            'ssl_self_signed'=> false,
            'ssl_error'      => null,
        ];

        $parsed = parse_url($url);
        $scheme = strtolower($parsed['scheme'] ?? 'http');
        $host = $parsed['host'] ?? '';

        if (empty($host)) {
            return ['info' => $sslInfo, 'findings' => $findings, 'penalty' => 0];
        }

        // Jika HTTP (bukan HTTPS), tidak ada sertifikat untuk diperiksa
        if ($scheme !== 'https') {
            $sslInfo['is_https'] = false;
            // Penalti HTTP sudah ditangani HeuristicEngine (HTTP_NO_SSL)
            return ['info' => $sslInfo, 'findings' => $findings, 'penalty' => 0];
        }

        $sslInfo['is_https'] = true;
        $port = $parsed['port'] ?? 443;

        // Ambil sertifikat SSL via stream_socket_client
        $certData = self::fetchCertificate($host, $port);

        if ($certData === null) {
            $sslInfo['ssl_valid'] = false;
            $sslInfo['ssl_error'] = 'Gagal mengambil sertifikat SSL dari server.';
            $findings[] = [
                'rule_name'    => 'SSL_FETCH_FAILED',
                'category'     => 'ssl',
                'severity'     => 'medium',
                'score_impact' => 20,
                'description'  => 'Tidak dapat memverifikasi sertifikat SSL. Server mungkin menggunakan konfigurasi SSL yang tidak standar.',
            ];
            $penalty += 20;
            return ['info' => $sslInfo, 'findings' => $findings, 'penalty' => $penalty];
        }

        // Parse informasi sertifikat
        $certInfo = openssl_x509_parse($certData['cert']);
        if (!$certInfo) {
            $sslInfo['ssl_valid'] = false;
            $sslInfo['ssl_error'] = 'Sertifikat tidak dapat diparse.';
            return ['info' => $sslInfo, 'findings' => $findings, 'penalty' => 0];
        }

        // Issuer & Subject
        $issuerCN = $certInfo['issuer']['CN'] ?? ($certInfo['issuer']['O'] ?? 'Unknown');
        $issuerO  = $certInfo['issuer']['O'] ?? '';
        $subjectCN = $certInfo['subject']['CN'] ?? '';

        $sslInfo['ssl_issuer']  = $issuerCN;
        $sslInfo['ssl_subject'] = $subjectCN;
        $sslInfo['ssl_protocol'] = $certData['protocol'] ?? null;

        // Tanggal kedaluwarsa
        $validTo = $certInfo['validTo_time_t'] ?? 0;
        $validFrom = $certInfo['validFrom_time_t'] ?? 0;
        $now = time();

        if ($validTo > 0) {
            $sslInfo['ssl_expires'] = date('Y-m-d', $validTo);
            $daysLeft = (int) floor(($validTo - $now) / 86400);
            $sslInfo['ssl_days_left'] = $daysLeft;

            // Sertifikat Expired
            if ($daysLeft < 0) {
                $sslInfo['ssl_valid'] = false;
                $findings[] = [
                    'rule_name'    => 'SSL_EXPIRED',
                    'category'     => 'ssl',
                    'severity'     => 'high',
                    'score_impact' => 25,
                    'description'  => 'Sertifikat SSL telah KEDALUWARSA sejak ' . abs($daysLeft) . ' hari yang lalu. Situs resmi tidak akan membiarkan sertifikat expired.',
                ];
                $penalty += 25;
            }
            // Sertifikat Hampir Expired (< 7 hari)
            elseif ($daysLeft <= 7) {
                $sslInfo['ssl_valid'] = true;
                $findings[] = [
                    'rule_name'    => 'SSL_EXPIRING_SOON',
                    'category'     => 'ssl',
                    'severity'     => 'low',
                    'score_impact' => 5,
                    'description'  => 'Sertifikat SSL akan kedaluwarsa dalam ' . $daysLeft . ' hari. Situs yang terkelola dengan baik biasanya memperbarui sertifikat lebih awal.',
                ];
                $penalty += 5;
            } else {
                $sslInfo['ssl_valid'] = true;
            }
        }

        // Deteksi Self-Signed Certificate
        if (self::isSelfSigned($certInfo)) {
            $sslInfo['ssl_self_signed'] = true;
            $sslInfo['ssl_valid'] = false;
            $findings[] = [
                'rule_name'    => 'SSL_SELF_SIGNED',
                'category'     => 'ssl',
                'severity'     => 'high',
                'score_impact' => 30,
                'description'  => 'Sertifikat SSL adalah SELF-SIGNED (ditandatangani sendiri). Ini berarti identitas server tidak diverifikasi oleh otoritas sertifikat terpercaya. Sangat tidak lazim untuk situs publik resmi.',
            ];
            $penalty += 30;
        }

        // Deteksi sertifikat Let's Encrypt pada domain baru (sinyal tambahan, bukan penalti berat)
        $isLetsEncrypt = (
            stripos($issuerO, "Let's Encrypt") !== false ||
            stripos($issuerCN, 'R3') !== false ||
            stripos($issuerCN, 'R10') !== false ||
            stripos($issuerCN, 'R11') !== false ||
            stripos($issuerCN, 'E5') !== false ||
            stripos($issuerCN, 'E6') !== false
        );

        if ($isLetsEncrypt) {
            $findings[] = [
                'rule_name'    => 'SSL_FREE_CERT',
                'category'     => 'ssl',
                'severity'     => 'info',
                'score_impact' => 0,
                'description'  => 'Menggunakan sertifikat SSL gratis (Let\'s Encrypt: ' . $issuerCN . '). Ini umum dan sah, namun situs phishing juga sering menggunakan sertifikat gratis.',
            ];
        }

        return ['info' => $sslInfo, 'findings' => $findings, 'penalty' => $penalty];
    }

    /**
     * Ambil sertifikat SSL dari server via stream_socket_client
     */
    private static function fetchCertificate(string $host, int $port = 443): ?array
    {
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'allow_self_signed' => true,
                'SNI_enabled'       => true,
                'peer_name'         => $host,
            ],
        ]);

        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client(
            "ssl://{$host}:{$port}",
            $errno,
            $errstr,
            5,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$socket) {
            return null;
        }

        $params = stream_context_get_params($socket);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        
        // Ambil protocol version
        $meta = stream_get_meta_data($socket);
        $protocol = $meta['crypto']['protocol'] ?? null;

        fclose($socket);

        if (!$cert) {
            return null;
        }

        return [
            'cert'     => $cert,
            'protocol' => $protocol,
        ];
    }

    /**
     * Deteksi apakah sertifikat self-signed
     */
    private static function isSelfSigned(array $certInfo): bool
    {
        $issuer = $certInfo['issuer'] ?? [];
        $subject = $certInfo['subject'] ?? [];

        // Self-signed: issuer identik dengan subject
        $issuerStr = implode(',', array_map(
            fn($k, $v) => "$k=$v",
            array_keys($issuer),
            array_values($issuer)
        ));
        $subjectStr = implode(',', array_map(
            fn($k, $v) => "$k=$v",
            array_keys($subject),
            array_values($subject)
        ));

        return $issuerStr === $subjectStr;
    }
}
