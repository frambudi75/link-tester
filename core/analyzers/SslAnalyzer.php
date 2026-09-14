<?php
/**
 * SSL Analyzer - LinkTester
 * 
 * Memeriksa sertifikat SSL/TLS, masa berlaku, issuer, enkripsi, dan status self-signed.
 * Menghasilkan Evidence objects untuk diproses oleh RiskScorer.
 */

require_once __DIR__ . '/../Evidence.php';

class SslAnalyzer
{
    /**
     * Analisis sertifikat SSL dari URL
     * 
     * @param string $url URL target
     * @return array ['evidences' => Evidence[], 'info' => array]
     */
    public static function analyze(string $url): array
    {
        $evidences = [];
        $source = 'ssl';

        $sslInfo = [
            'is_https'        => false,
            'ssl_valid'       => null,
            'ssl_issuer'      => null,
            'ssl_subject'     => null,
            'ssl_protocol'    => null,
            'ssl_expires'     => null,
            'ssl_days_left'   => null,
            'ssl_self_signed' => false,
            'ssl_error'       => null,
        ];

        $parsed = parse_url($url);
        $scheme = strtolower($parsed['scheme'] ?? 'http');
        $host = $parsed['host'] ?? '';

        if (empty($host) || $scheme !== 'https') {
            return ['evidences' => $evidences, 'info' => $sslInfo];
        }

        $sslInfo['is_https'] = true;
        $port = $parsed['port'] ?? 443;

        $certData = self::fetchCertificate($host, $port);
        if ($certData === null) {
            $sslInfo['ssl_valid'] = false;
            $sslInfo['ssl_error'] = 'Gagal mengambil sertifikat SSL dari server.';

            $evidences[] = Evidence::create(
                'ssl_fetch_failed',
                true,
                $source,
                ['detail' => 'Koneksi SSL gagal atau server menolak handshake SSL.'],
                0.8
            );

            return ['evidences' => $evidences, 'info' => $sslInfo];
        }

        $certInfo = openssl_x509_parse($certData['cert']);
        if (!$certInfo) {
            $sslInfo['ssl_valid'] = false;
            $sslInfo['ssl_error'] = 'Sertifikat tidak dapat diparse.';
            return ['evidences' => $evidences, 'info' => $sslInfo];
        }

        $issuerCN = $certInfo['issuer']['CN'] ?? ($certInfo['issuer']['O'] ?? 'Unknown');
        $issuerO  = $certInfo['issuer']['O'] ?? '';
        $subjectCN = $certInfo['subject']['CN'] ?? '';

        $sslInfo['ssl_issuer']   = $issuerCN;
        $sslInfo['ssl_subject']  = $subjectCN;
        $sslInfo['ssl_protocol'] = $certData['protocol'] ?? null;

        $validTo = $certInfo['validTo_time_t'] ?? 0;
        $now = time();

        if ($validTo > 0) {
            $sslInfo['ssl_expires'] = date('Y-m-d', $validTo);
            $daysLeft = (int) floor(($validTo - $now) / 86400);
            $sslInfo['ssl_days_left'] = $daysLeft;

            if ($daysLeft < 0) {
                $sslInfo['ssl_valid'] = false;
                $evidences[] = Evidence::create(
                    'ssl_expired',
                    true,
                    $source,
                    [
                        'days_ago' => abs($daysLeft),
                        'expires'  => $sslInfo['ssl_expires'],
                        'detail'   => 'Sertifikat SSL kedaluwarsa sejak ' . abs($daysLeft) . ' hari yang lalu.'
                    ],
                    1.0
                );
            } elseif ($daysLeft <= 7) {
                $sslInfo['ssl_valid'] = true;
                $evidences[] = Evidence::create(
                    'ssl_expiring_soon',
                    $daysLeft,
                    $source,
                    [
                        'days_left' => $daysLeft,
                        'expires'   => $sslInfo['ssl_expires'],
                        'detail'    => 'Sertifikat SSL akan kedaluwarsa dalam ' . $daysLeft . ' hari.'
                    ],
                    0.7
                );
            } else {
                $sslInfo['ssl_valid'] = true;
                $evidences[] = Evidence::create(
                    'ssl_valid',
                    true,
                    $source,
                    [
                        'issuer'    => $issuerCN,
                        'days_left' => $daysLeft,
                        'expires'   => $sslInfo['ssl_expires'],
                        'detail'    => 'Sertifikat SSL valid dan aktif (' . $daysLeft . ' hari tersisa).'
                    ],
                    1.0
                );
            }
        }

        // Self-signed check
        if (self::isSelfSigned($certInfo)) {
            $sslInfo['ssl_self_signed'] = true;
            $sslInfo['ssl_valid'] = false;
            $evidences[] = Evidence::create(
                'ssl_self_signed',
                true,
                $source,
                [
                    'issuer'  => $issuerCN,
                    'detail'  => 'Sertifikat SSL adalah SELF-SIGNED (identitas server tidak diverifikasi oleh CA publik).'
                ],
                0.95
            );
        }

        // Free Cert check (Let's Encrypt)
        $isLetsEncrypt = (
            stripos($issuerO, "Let's Encrypt") !== false ||
            stripos($issuerCN, 'R3') !== false ||
            stripos($issuerCN, 'R10') !== false ||
            stripos($issuerCN, 'R11') !== false ||
            stripos($issuerCN, 'E5') !== false ||
            stripos($issuerCN, 'E6') !== false
        );

        if ($isLetsEncrypt) {
            $evidences[] = Evidence::create(
                'ssl_free_cert',
                true,
                $source,
                [
                    'issuer' => $issuerCN,
                    'detail' => 'Menggunakan sertifikat gratis (Let\'s Encrypt: ' . $issuerCN . ').'
                ],
                0.5
            );
        }

        return ['evidences' => $evidences, 'info' => $sslInfo];
    }

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
            4,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$socket) {
            return null;
        }

        $params = stream_context_get_params($socket);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
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

    private static function isSelfSigned(array $certInfo): bool
    {
        $issuer = $certInfo['issuer'] ?? [];
        $subject = $certInfo['subject'] ?? [];

        $issuerStr = implode(',', array_map(fn($k, $v) => "$k=$v", array_keys($issuer), array_values($issuer)));
        $subjectStr = implode(',', array_map(fn($k, $v) => "$k=$v", array_keys($subject), array_values($subject)));

        return !empty($issuerStr) && $issuerStr === $subjectStr;
    }
}
