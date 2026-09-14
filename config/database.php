<?php
/**
 * Database Configuration - LinkTester
 * 
 * Mendukung konfigurasi via Environment Variable (Docker/aaPanel)
 * dan default fallback untuk XAMPP lokal serta cPanel.
 */

defined('DB_HOST') or define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
defined('DB_PORT') or define('DB_PORT', getenv('DB_PORT') ?: '3306');
defined('DB_NAME') or define('DB_NAME', getenv('DB_NAME') ?: 'link_tester');
defined('DB_USER') or define('DB_USER', getenv('DB_USER') ?: 'root');
defined('DB_PASS') or define('DB_PASS', getenv('DB_PASS') !== false ? getenv('DB_PASS') : '');
defined('DB_CHARSET') or define('DB_CHARSET', 'utf8mb4');






// defined('DB_HOST') or define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
// defined('DB_PORT') or define('DB_PORT', getenv('DB_PORT') ?: '3306');
// defined('DB_NAME') or define('DB_NAME', getenv('DB_NAME') ?: 'diarynot_link');
// defined('DB_USER') or define('DB_USER', getenv('DB_USER') ?: 'diarynot_link');
// defined('DB_PASS') or define('DB_PASS', getenv('DB_PASS') !== false ? getenv('DB_PASS') : 'B2Gvh8TSr5Akwk3AFfvt');
// defined('DB_CHARSET') or define('DB_CHARSET', 'utf8mb4');
