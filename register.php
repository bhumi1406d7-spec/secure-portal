<?php
// ============================================================
// register.php — Secure User Registration
// ============================================================

require_once "security_helpers.php";
require_once "db.php";
require_once "logger.php";

set_security_headers();
secure_session_start();

generate_csrf();
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // 🔐 CSRF check
    if (!verify_csrf($_POST['csrf'] ?? '')) {
        logAction('SYSTEM', 'CSRF mismatch on registration', 'CRITICAL');
        $error = "Security token invalid. Please refresh and try again.";
    } else {

        // 🔐 Rate limiting
        if (!check_rate_limit('register', 5, 3600)) {
            $error = "Too many registration attempts. Please try again later.";
        } else {

            $username = trim($_POST['username'] ?? '');
            $email    = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
            $password = $_POST['password'] ?? '';
            $confirm  = $_POST['confirm_password'] ?? '';

            // 🔐 Validation
            if (strlen($username) < 3 || strlen($username) > 30) {
                $error = "Username must be 3–30 characters.";
            } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
                $error = "Username may only contain letters, numbers and underscores.";
            } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $error = "Invalid email address.";
            } elseif (strlen($password) < 8) {
                $error = "Password must be at least 8 characters.";
            } elseif (!preg_match('/[A-Z]/', $password) || !preg_match('/[0-9]/', $password)) {
                $error = "Password must contain at least one uppercase letter and one number.";
            } elseif ($password !== $confirm) {
                $error = "Passwords do not match.";
            } else {

                // 🔐 Encrypt email (AES-256) before storing
                $encrypted_email = encrypt_data($email);

                // Check duplicate (by encrypted email)
                $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
                $stmt->bind_param("s", $encrypted_email);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows > 0) {
                    $error = "An account with this email already exists.";
                } else {
                    $stmt->close();

                    // 🔐 Hash password with bcrypt
                    $hashed = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

                    // 🔐 Classify & log data fields stored
                    $fields = ['email' => classify_data('email'), 'password' => classify_data('password')];

                    $stmt = $conn->prepare(
                        "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')"
                    );
                    $stmt->bind_param("sss", $username, $encrypted_email, $hashed);

                    if ($stmt->execute()) {
                        increment_rate_limit('register');
                        // Regenerate CSRF after success
                        $_SESSION['csrf'] = bin2hex(random_bytes(32));
                        logAction($username, 'New user registered. Data fields stored: ' . json_encode($fields), 'INFO');
                        $success = "Account created! You can now <a href='index.php'>login</a>.";
                    } else {
                        $error = "Registration failed. Please try again.";
                    }
                    $stmt->close();
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Register — <?php echo APP_NAME; ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #0f172a; display: flex; justify-content: center; align-items: center; min-height: 100vh; color: white; }
.container { background: #1e293b; padding: 36px; border-radius: 14px; width: 360px; box-shadow: 0 0 40px rgba(0,0,0,0.6); }
h2 { color: #38bdf8; text-align: center; margin-bottom: 6px; }
.subtitle { text-align: center; font-size: 13px; color: #94a3b8; margin-bottom: 24px; }
label { font-size: 13px; color: #94a3b8; display: block; margin-bottom: 4px; }
input[type=text], input[type=email], input[type=password] {
    width: 100%; padding: 10px 12px; margin-bottom: 14px;
    border: 1px solid #334155; border-radius: 8px;
    background: #0f172a; color: white; font-size: 14px; outline: none; transition: border 0.2s;
}
input:focus { border-color: #38bdf8; }
button { width: 100%; padding: 11px; background: #38bdf8; border: none; border-radius: 8px; color: #0f172a; font-weight: 600; font-size: 15px; cursor: pointer; }
button:hover { background: #0284c7; color: white; }
.error { background: #450a0a; color: #fca5a5; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; }
.success { background: #052e16; color: #86efac; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; }
.success a { color: #38bdf8; }
.link { text-align: center; margin-top: 14px; font-size: 13px; color: #94a3b8; }
.link a { color: #38bdf8; text-decoration: none; }
.hint { font-size: 11px; color: #475569; margin-top: -10px; margin-bottom: 14px; }
</style>
</head>
<body>
<div class="container">
    <h2>📝 Create Account</h2>
    <p class="subtitle">Your data is encrypted &amp; stored securely</p>

    <?php if ($error): ?><div class="error"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
    <?php if ($success): ?><div class="success"><?php echo $success; ?></div><?php endif; ?>

    <?php if (!$success): ?>
    <form method="POST" autocomplete="off">
        <?php echo csrf_input(); ?>

        <label>Username</label>
        <input type="text" name="username" placeholder="john_doe" required>

        <label>Email Address</label>
        <input type="email" name="email" placeholder="you@example.com" required>

        <label>Password</label>
        <input type="password" name="password" placeholder="Min 8 chars, 1 uppercase, 1 number" required>
        <p class="hint">Min 8 characters • 1 uppercase letter • 1 number</p>

        <label>Confirm Password</label>
        <input type="password" name="confirm_password" placeholder="Re-enter password" required>

        <button type="submit">Create Account</button>
    </form>
    <?php endif; ?>

    <div class="link">Already have an account? <a href="index.php">Login</a></div>
</div>
</body>
</html>
