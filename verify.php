<?php
// ============================================================
// verify.php — MFA OTP Verification
// ============================================================

require_once "security_helpers.php";
require_once "logger.php";

set_security_headers();
secure_session_start();

// Guard: must have an active OTP session
if (!isset($_SESSION['otp'], $_SESSION['temp_user'])) {
    safe_redirect('index.php');
}

// 🔐 OTP expiry check
if ((time() - ($_SESSION['otp_time'] ?? 0)) > OTP_EXPIRY) {
    logAction($_SESSION['temp_user'] ?? 'SYSTEM', 'OTP expired', 'WARNING');
    session_destroy();
    safe_redirect('index.php?error=OTP+expired.+Please+login+again.');
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // 🔐 CSRF
    if (!verify_csrf($_POST['csrf'] ?? '')) {
        logAction($_SESSION['temp_user'], 'CSRF mismatch on OTP', 'CRITICAL');
        safe_redirect('index.php?error=Security+error.+Try+again.');
    }

    // 🔐 Max OTP attempts
    if ($_SESSION['otp_attempts'] >= OTP_MAX_ATTEMPTS) {
        logAction($_SESSION['temp_user'], 'OTP max attempts exceeded', 'CRITICAL');
        session_destroy();
        safe_redirect('index.php?error=Too+many+OTP+attempts.');
    }

    $submitted_otp = trim($_POST['otp'] ?? '');

    // 🔐 Validate OTP format
    if (!preg_match('/^\d{6}$/', $submitted_otp)) {
        $error = "OTP must be 6 digits.";
    } elseif (password_verify($submitted_otp, $_SESSION['otp'])) {

        // ✅ OTP correct — promote session
        $_SESSION['user'] = $_SESSION['temp_user'];
        $_SESSION['role'] = $_SESSION['temp_role'];

        // 🔐 New session ID after full login
        session_regenerate_id(true);

        // Clear temporary data
        unset($_SESSION['otp'], $_SESSION['otp_plain'], $_SESSION['otp_time'],
              $_SESSION['otp_attempts'], $_SESSION['temp_user'], $_SESSION['temp_role']);

        // Regenerate CSRF
        $_SESSION['csrf'] = bin2hex(random_bytes(32));

        logAction($_SESSION['user'], 'Successful login via MFA', 'INFO');

        safe_redirect($_SESSION['role'] === 'admin' ? 'admin.php' : 'dashboard.php');

    } else {
        $_SESSION['otp_attempts']++;
        $remaining = OTP_MAX_ATTEMPTS - $_SESSION['otp_attempts'];
        $error = "Invalid OTP. {$remaining} attempt(s) remaining.";
        logAction($_SESSION['temp_user'], 'Invalid OTP entered', 'WARNING');
    }
}

$remaining_seconds = OTP_EXPIRY - (time() - $_SESSION['otp_time']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MFA Verification — <?php echo APP_NAME; ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #0f172a; display: flex; justify-content: center; align-items: center; min-height: 100vh; color: white; }
.container { background: #1e293b; padding: 36px; border-radius: 14px; width: 340px; box-shadow: 0 0 40px rgba(0,0,0,0.6); text-align: center; }
h2 { color: #38bdf8; margin-bottom: 8px; }
.subtitle { font-size: 13px; color: #94a3b8; margin-bottom: 24px; }
.otp-demo { background: #0f172a; border: 1px solid #38bdf8; border-radius: 8px; padding: 14px; margin-bottom: 20px; }
.otp-demo span { font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #38bdf8; }
.otp-demo p { font-size: 11px; color: #64748b; margin-top: 6px; }
input[type=text] {
    width: 100%; padding: 12px; text-align: center; font-size: 22px; letter-spacing: 8px;
    border: 1px solid #334155; border-radius: 8px; background: #0f172a; color: white; outline: none;
    margin-bottom: 16px; transition: border 0.2s;
}
input:focus { border-color: #38bdf8; }
button { width: 100%; padding: 11px; background: #38bdf8; border: none; border-radius: 8px; color: #0f172a; font-weight: 600; font-size: 15px; cursor: pointer; }
button:hover { background: #0284c7; color: white; }
.error { background: #450a0a; color: #fca5a5; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; }
.timer { font-size: 13px; color: #64748b; margin-top: 14px; }
#countdown { color: #f59e0b; font-weight: bold; }
.back { display: block; margin-top: 12px; font-size: 13px; color: #64748b; text-decoration: none; }
.back:hover { color: #38bdf8; }
</style>
</head>
<body>
<div class="container">
    <h2>🔑 MFA Verification</h2>
    <p class="subtitle">Enter the 6-digit OTP sent to your device</p>

    <!-- In production, OTP is emailed. Shown here for demo. -->
    <div class="otp-demo">
        <span><?php echo htmlspecialchars($_SESSION['otp_plain'] ?? '------'); ?></span>
        <p>Demo mode — OTP displayed here (remove in production)</p>
    </div>

    <?php if ($error): ?>
        <div class="error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>

    <form method="POST">
        <?php echo csrf_input(); ?>
        <input type="text" name="otp" maxlength="6" placeholder="000000" pattern="\d{6}" required autofocus>
        <button type="submit">Verify OTP</button>
    </form>

    <div class="timer">OTP expires in <span id="countdown"><?php echo $remaining_seconds; ?></span>s</div>
    <a href="index.php" class="back">← Back to Login</a>
</div>
<script>
let t = <?php echo (int)$remaining_seconds; ?>;
const el = document.getElementById('countdown');
const iv = setInterval(() => {
    t--;
    el.textContent = t;
    if (t <= 10) el.style.color = '#ef4444';
    if (t <= 0) { clearInterval(iv); window.location = 'index.php?error=OTP+expired.'; }
}, 1000);
</script>
</body>
</html>
