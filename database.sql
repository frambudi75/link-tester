-- =========================================================
-- Database Schema for LinkTester (Phishing & Malicious Link Detector)
-- Compatible with MySQL 5.7+, MySQL 8.0+, and MariaDB 10.3+
-- =========================================================

CREATE DATABASE IF NOT EXISTS `link_tester` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `link_tester`;

-- --------------------------------------------------------
-- Table: scans
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `scans` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `url_hash` CHAR(64) NOT NULL,
    `original_url` TEXT NOT NULL,
    `final_url` TEXT NOT NULL,
    `domain` VARCHAR(255) NOT NULL,
    `ip_address` VARCHAR(45) DEFAULT NULL,
    `risk_score` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `verdict` ENUM('safe', 'suspicious', 'dangerous') NOT NULL DEFAULT 'safe',
    `is_redirected` TINYINT(1) NOT NULL DEFAULT 0,
    `redirect_count` INT NOT NULL DEFAULT 0,
    `domain_age_days` INT DEFAULT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_url_hash` (`url_hash`),
    INDEX `idx_domain` (`domain`),
    INDEX `idx_verdict` (`verdict`),
    INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: scan_details
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `scan_details` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `category` VARCHAR(50) NOT NULL,
    `rule_name` VARCHAR(100) NOT NULL,
    `severity` ENUM('info', 'low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
    `score_impact` INT NOT NULL DEFAULT 0,
    `description` TEXT NOT NULL,
    INDEX `idx_scan_id` (`scan_id`),
    CONSTRAINT `fk_scan_details_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: domain_reputation
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `domain_reputation` (
    `domain` VARCHAR(255) PRIMARY KEY,
    `is_whitelisted` TINYINT(1) NOT NULL DEFAULT 0,
    `is_blacklisted` TINYINT(1) NOT NULL DEFAULT 0,
    `registrar` VARCHAR(255) DEFAULT NULL,
    `registered_date` DATE DEFAULT NULL,
    `last_checked` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `notes` VARCHAR(255) DEFAULT NULL,
    INDEX `idx_whitelist` (`is_whitelisted`),
    INDEX `idx_blacklist` (`is_blacklisted`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Seed Data: Official Trusted Domains (Whitelist)
-- --------------------------------------------------------
INSERT IGNORE INTO `domain_reputation` (`domain`, `is_whitelisted`, `is_blacklisted`, `notes`) VALUES
('google.com', 1, 0, 'Official Google Services'),
('google.co.id', 1, 0, 'Official Google Indonesia'),
('microsoft.com', 1, 0, 'Official Microsoft'),
('apple.com', 1, 0, 'Official Apple'),
('bca.co.id', 1, 0, 'Official Bank Central Asia'),
('klikbca.com', 1, 0, 'Official KlikBCA Internet Banking'),
('bankmandiri.co.id', 1, 0, 'Official Bank Mandiri'),
('bri.co.id', 1, 0, 'Official Bank Rakyat Indonesia'),
('bni.co.id', 1, 0, 'Official Bank Negara Indonesia'),
('github.com', 1, 0, 'Official GitHub'),
('kominfo.go.id', 1, 0, 'Official Kementerian Kominfo RI'),
('wa.me', 1, 0, 'Official WhatsApp Direct Link'),
('whatsapp.com', 1, 0, 'Official WhatsApp'),
('telegram.org', 1, 0, 'Official Telegram');
