<?php
/**
 * Database Singleton Handler - LinkTester
 * Menggunakan PDO dengan Prepared Statements
 */

require_once __DIR__ . '/../config/database.php';

class Database
{
    private static ?PDO $instance = null;
    private static bool $connectionFailed = false;
    private static string $errorMessage = '';

    private function __construct() {}
    private function __clone() {}

    public static function getConnection(): ?PDO
    {
        if (self::$connectionFailed) {
            return null;
        }

        if (self::$instance === null) {
            try {
                $dsn = sprintf(
                    'mysql:host=%s;port=%s;dbname=%s;charset=%s',
                    DB_HOST,
                    DB_PORT,
                    DB_NAME,
                    DB_CHARSET
                );

                $options = [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES   => false,
                    PDO::ATTR_TIMEOUT            => 5,
                ];

                self::$instance = new PDO($dsn, DB_USER, DB_PASS, $options);
            } catch (PDOException $e) {
                self::$connectionFailed = true;
                self::$errorMessage = $e->getMessage();
                error_log('Database Connection Error: ' . $e->getMessage());
                return null;
            }
        }

        return self::$instance;
    }

    public static function isConnected(): bool
    {
        return self::getConnection() !== null;
    }

    public static function getErrorMessage(): string
    {
        return self::$errorMessage;
    }
}
