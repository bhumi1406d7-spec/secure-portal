<?php
require_once "security_helpers.php";
set_security_headers();
secure_session_start();

// Already logged in?
if (isset($_SESSION['user'])) {
    safe_redirect('dashboard.php');
}

generate_csrf();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secure Login — <?php echo APP_NAME; ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Segoe UI', sans-serif;
    background: #0f172a;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    color: white;
}
.container {
    background: #1e293b;
    padding: 36px;
    border-radius: 14px;
    width: 340px;
    box-shadow: 0 0 40px rgba(0,0,0,0.6);
    animation: fadeIn 0.6s ease;
}
h2 { text-align: center; margin-bottom: 6px; color: #38bdf8; font-size: 22px; }
.subtitle { text-align: center; font-size: 13px; color: #94a3b8; margin-bottom: 24px; }
label { font-size: 13px; color: #94a3b8; display: block; margin-bottom: 4px; }
input[type=email], input[type=password] {
    width: 100%; padding: 10px 12px; margin-bottom: 16px;
    border: 1px solid #334155; border-radius: 8px;
    background: #0f172a; color: white; font-size: 14px; outline: none;
    transition: border 0.2s;
}
input:focus { border-color: #38bdf8; }
button {
    width: 100%; padding: 11px; background: #38bdf8;
    border: none; border-radius: 8px; color: #0f172a;
    font-weight: 600; font-size: 15px; cursor: pointer; transition: 0.2s;
}
button:hover { background: #0284c7; color: white; }
.link { text-align: center; margin-top: 16px; font-size: 13px; color: #94a3b8; }
.link a { color: #38bdf8; text-decoration: none; }
.error { background: #450a0a; color: #fca5a5; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; }
@keyframes fadeIn { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
.badge { display: flex; align-items: center; gap: 6px; justify-content: center; font-size: 12px; color: #64748b; margin-top: 20px; }
</style>
</head>
<body>
<div class="container">
    <h2>🔐 <?php echo APP_NAME; ?></h2>
    <p class="subtitle">Sign in securely to continue</p>

    <?php if (!empty($_GET['error'])): ?>
        <div class="error"><?php echo htmlspecialchars($_GET['error']); ?></div>
    <?php endif; ?>

    <form method="POST" action="login.php" autocomplete="off">
        <?php echo csrf_input(); ?>
        <label>Email Address</label>
        <input type="email" name="email" placeholder="you@example.com" required autofocus>
        <label>Password</label>
        <input type="password" name="password" placeholder="••••••••" required>
        <button type="submit">Sign In</button>
    </form>

    <div class="link">
        Don't have an account? <a href="register.php">Register</a>
    </div>
    <div class="badge">🛡️ Protected by AES-256 Encryption &amp; MFA</div>
</div>
</body>
</html>
