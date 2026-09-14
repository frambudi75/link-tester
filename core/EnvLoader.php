<?php
/**
 * Env Loader - LinkTester
 * 
 * Simple, zero-dependency .env file parser.
 * Memuat variabel lingkungan dari file .env ke getenv(), $_ENV, dan $_SERVER.
 */

class EnvLoader
{
    /**
     * Muat file .env jika file tersebut ada.
     * 
     * @param string $path Path absolut ke file .env
     */
    public static function load(string $path): void
    {
        if (!file_exists($path) || !is_readable($path)) {
            return;
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return;
        }

        foreach ($lines as $line) {
            $line = trim($line);

            // Lewati komentar
            if (empty($line) || str_starts_with($line, '#')) {
                continue;
            }

            // Parse format KEY=VALUE
            if (!str_contains($line, '=')) {
                continue;
            }

            [$key, $value] = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value);

            // Bersihkan kutipan pembungkus
            if ((str_starts_with($value, '"') && str_ends_with($value, '"')) ||
                (str_starts_with($value, "'") && str_ends_with($value, "'"))) {
                $value = substr($value, 1, -1);
            }

            if (!empty($key)) {
                putenv("$key=$value");
                $_ENV[$key] = $value;
                $_SERVER[$key] = $value;
            }
        }
    }
}
