<?php
// ============================================================
// security_helpers.php — Shared Security Utilities
// ============================================================

require_once "config.php";

// ────────────────────────────────────────────────────────────
// 🔐 Set all security headers
// ────────────────────────────────────────────────────────────
function set_security_headers() {
    header("X-Frame-Options: DENY");
    header("X-Content-Type-Options: nosniff");
    header("X-XSS-Protection: 1; mode=block");
    header("Referrer-Policy: no-referrer");
    header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'");
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
}

// ────────────────────────────────────────────────────────────
// 🔐 Secure session start
// ────────────────────────────────────────────────────────────
function secure_session_start() {
    session_set_cookie_params([
        'lifetime' => SESSION_LIFETIME,
        'path'     => '/',
        'secure'   => isset($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

// ────────────────────────────────────────────────────────────
// 🔐 AES-256 Encrypt / Decrypt
// ────────────────────────────────────────────────────────────
function encrypt_data(string $data): string {
    return base64_encode(openssl_encrypt($data, ENC_ALGO, ENC_KEY, 0, ENC_IV));
}

function decrypt_data(string $data): string {
    return openssl_decrypt(base64_decode($data), ENC_ALGO, ENC_KEY, 0, ENC_IV);
}

// ────────────────────────────────────────────────────────────
// 🔐 CSRF helpers
// ────────────────────────────────────────────────────────────
function generate_csrf(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function verify_csrf(string $token): bool {
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token);
}

function csrf_input(): string {
    return '<input type="hidden" name="csrf" value="' . htmlspecialchars(generate_csrf()) . '">';
}

// ────────────────────────────────────────────────────────────
// 🔐 Rate limiting (session-based)
// ────────────────────────────────────────────────────────────
function check_rate_limit(string $key, int $max, int $lockout): bool {
    $attempts_key = "rl_{$key}_attempts";
    $time_key     = "rl_{$key}_time";

    if (!isset($_SESSION[$attempts_key])) {
        $_SESSION[$attempts_key] = 0;
        $_SESSION[$time_key]     = time();
    }

    // Reset if lockout window passed
    if ((time() - $_SESSION[$time_key]) > $lockout) {
        $_SESSION[$attempts_key] = 0;
        $_SESSION[$time_key]     = time();
    }

    return $_SESSION[$attempts_key] < $max;
}

function increment_rate_limit(string $key): void {
    $_SESSION["rl_{$key}_attempts"] = ($_SESSION["rl_{$key}_attempts"] ?? 0) + 1;
}

function reset_rate_limit(string $key): void {
    unset($_SESSION["rl_{$key}_attempts"], $_SESSION["rl_{$key}_time"]);
}

// ────────────────────────────────────────────────────────────
// 🔐 Classify data sensitivity
// ────────────────────────────────────────────────────────────
function classify_data(string $field): string {
    $critical    = ['password', 'ssn', 'credit_card', 'bank_account'];
    $sensitive   = ['email', 'phone', 'dob', 'address', 'national_id'];
    $internal    = ['username', 'role', 'department'];

    if (in_array($field, $critical))  return 'CRITICAL';
    if (in_array($field, $sensitive)) return 'SENSITIVE';
    if (in_array($field, $internal))  return 'INTERNAL';
    return 'PUBLIC';
}

// ────────────────────────────────────────────────────────────
// 🔐 Safe redirect
// ────────────────────────────────────────────────────────────
function safe_redirect(string $url): void {
    $allowed = ['index.php','login.php','dashboard.php','admin.php','verify.php','register.php'];
    if (!in_array(basename($url), $allowed)) {
        $url = 'index.php';
    }
    header("Location: $url");
    exit();
}
