<?php
// ============================================================
// config.php — Central Security Configuration
// Reads from environment variables for production deployment
// ============================================================

// 🔐 AES-256-CBC Encryption
define("ENC_ALGO", "AES-256-CBC");
define("ENC_KEY", hash('sha256', getenv('ENC_KEY_SECRET') ?: 'your_very_secure_random_key_123', true));
define("ENC_IV",  substr(hash('sha256', getenv('ENC_IV_SECRET') ?: 'your_iv_secret_456'), 0, 16));

// 🔐 Session config
define("SESSION_LIFETIME", 1800); // 30 minutes

// 🔐 Login limits
define("MAX_LOGIN_ATTEMPTS", 5);
define("LOGIN_LOCKOUT_TIME", 900); // 15 minutes

// 🔐 OTP config
define("OTP_EXPIRY", 120);        // 2 minutes
define("OTP_MAX_ATTEMPTS", 3);

// 🔐 App info
define("APP_NAME", "SecurePortal");
define("APP_VERSION", "2.0");
