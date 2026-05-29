<?php
// ============================================================
// dashboard.php — User Dashboard
// ============================================================

require_once "security_helpers.php";

set_security_headers();
secure_session_start();

if (!isset($_SESSION['user'])) {
    safe_redirect('index.php');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard — <?php echo APP_NAME; ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #0f172a, #1e3a8a); min-height: 100vh; display: flex; justify-content: center; align-items: center; color: white; }
.card { background: rgba(30,41,59,0.92); padding: 44px; border-radius: 16px; text-align: center; width: 380px; backdrop-filter: blur(10px); box-shadow: 0 10px 50px rgba(0,0,0,0.6); }
.avatar { width: 64px; height: 64px; border-radius: 50%; background: #38bdf8; display: flex; align-items: center; justify-content: center; font-size: 26px; font-weight: bold; color: #0f172a; margin: 0 auto 16px; }
h2 { color: #38bdf8; margin-bottom: 6px; font-size: 22px; }
.role-badge { display: inline-block; padding: 3px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; background: #1e3a5f; color: #38bdf8; margin-bottom: 20px; }
p { color: #94a3b8; font-size: 14px; margin-bottom: 24px; }
.info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px; }
.info-box { background: #0f172a; border-radius: 10px; padding: 12px; font-size: 13px; }
.info-box .label { color: #64748b; font-size: 11px; margin-bottom: 4px; }
.info-box .val { color: #e2e8f0; font-weight: 500; }
a { display: block; margin: 8px 0; padding: 10px; border-radius: 8px; text-decoration: none; color: white; font-size: 14px; font-weight: 500; transition: 0.2s; }
.logout { background: #ef4444; }
.logout:hover { background: #dc2626; }
.admin-btn { background: #22c55e; }
.admin-btn:hover { background: #16a34a; }
</style>
</head>
<body>
<div class="card">
    <div class="avatar"><?php echo strtoupper(substr($_SESSION['user'], 0, 1)); ?></div>
    <h2>Welcome, <?php echo htmlspecialchars($_SESSION['user']); ?></h2>
    <span class="role-badge"><?php echo strtoupper(htmlspecialchars($_SESSION['role'])); ?></span>
    <p>You are authenticated securely via MFA 🔐</p>

    <div class="info-grid">
        <div class="info-box">
            <div class="label">Encryption</div>
            <div class="val">AES-256-CBC</div>
        </div>
        <div class="info-box">
            <div class="label">Session</div>
            <div class="val">HTTPOnly · Strict</div>
        </div>
        <div class="info-box">
            <div class="label">Auth Method</div>
            <div class="val">Password + OTP</div>
        </div>
        <div class="info-box">
            <div class="label">Login Time</div>
            <div class="val"><?php echo date("H:i:s"); ?></div>
        </div>
    </div>

    <a href="logout.php" class="logout">🚪 Logout</a>
    <?php if ($_SESSION['role'] === 'admin'): ?>
        <a href="admin.php" class="admin-btn">⚙️ Admin Panel</a>
    <?php endif; ?>
</div>
</body>
</html>
