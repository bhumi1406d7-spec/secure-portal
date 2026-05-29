<?php
// ============================================================
// login.php — Secure Authentication Handler
// ============================================================

require_once "security_helpers.php";
require_once "logger.php";

set_security_headers();
secure_session_start();

// Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    safe_redirect('index.php');
}

// 🔐 CSRF validation
if (!verify_csrf($_POST['csrf'] ?? '')) {
    logAction('SYSTEM', 'CSRF token mismatch on login', 'CRITICAL');
    safe_redirect('index.php?error=Security+token+invalid.+Please+try+again.');
}

// 🔐 Rate limiting — max 5 attempts per 15 min
if (!check_rate_limit('login', MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_TIME)) {
    logAction('SYSTEM', 'Login rate limit exceeded from IP: ' . ($_SERVER['REMOTE_ADDR'] ?? ''), 'CRITICAL');
    safe_redirect('index.php?error=Too+many+login+attempts.+Try+again+in+15+minutes.');
}

// 🔐 Sanitize & validate inputs
$email    = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
$password = $_POST['password'] ?? '';

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    safe_redirect('index.php?error=Invalid+email+format.');
}

if (strlen($password) < 6 || strlen($password) > 128) {
    safe_redirect('index.php?error=Invalid+credentials.');
}

require_once "db.php";

// 🔐 Encrypt email with AES-256 before lookup
$encrypted_email = encrypt_data($email);

// 🔐 Parameterised query — prevents SQL injection
$stmt = $conn->prepare("SELECT username, password, role FROM users WHERE email = ? LIMIT 1");
$stmt->bind_param("s", $encrypted_email);
$stmt->execute();
$result = $stmt->get_result();
$user   = $result->fetch_assoc();
$stmt->close();

// 🔐 Constant-time password verification
if ($user && password_verify($password, $user['password'])) {

    // 🔐 Reset rate limit on success
    reset_rate_limit('login');

    // 🔐 Regenerate session to prevent fixation
    session_regenerate_id(true);

    // 🔐 Generate 6-digit OTP (cryptographically secure)
    $otp = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

    // Store OTP details in session (not plain int)
    $_SESSION['otp']          = password_hash($otp, PASSWORD_DEFAULT); // hashed OTP
    $_SESSION['otp_plain']    = $otp;   // remove after email integration
    $_SESSION['otp_time']     = time();
    $_SESSION['otp_attempts'] = 0;
    $_SESSION['temp_user']    = $user['username'];
    $_SESSION['temp_role']    = $user['role'];

    // Regenerate CSRF after login step
    $_SESSION['csrf'] = bin2hex(random_bytes(32));

    logAction($user['username'], 'OTP generated — awaiting MFA verification', 'INFO');

    safe_redirect('verify.php');

} else {
    // 🔐 Increment attempt counter
    increment_rate_limit('login');

    $user_label = $user ? ($user['username'] ?? 'unknown') : 'unknown';
    logAction($user_label, 'Failed login attempt for email: ' . $email, 'WARNING');

    safe_redirect('index.php?error=Invalid+email+or+password.');
}
