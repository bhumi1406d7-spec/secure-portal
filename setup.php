<?php
// ============================================================
// setup.php — One-time Database Setup
// Visit this URL once after deployment, then DELETE it
// ============================================================

require_once "db.php";

$errors = [];
$success = [];

$sql_statements = [
    "CREATE TABLE IF NOT EXISTS users (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        username   VARCHAR(50)  NOT NULL UNIQUE,
        email      TEXT         NOT NULL,
        password   VARCHAR(255) NOT NULL,
        role       ENUM('user','admin') DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

    "CREATE TABLE IF NOT EXISTS logs (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        user       VARCHAR(100) NOT NULL,
        action     TEXT         NOT NULL,
        severity   ENUM('INFO','WARNING','CRITICAL') DEFAULT 'INFO',
        ip_address VARCHAR(45)  DEFAULT NULL,
        user_agent VARCHAR(255) DEFAULT NULL,
        time       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
];

foreach ($sql_statements as $sql) {
    if ($conn->query($sql)) {
        $success[] = "✅ " . substr($sql, 0, 60) . "...";
    } else {
        $errors[] = "❌ " . $conn->error;
    }
}

// Insert default admin (password: Admin@1234)
require_once "config.php";
$admin_email    = base64_encode(openssl_encrypt('admin@secureportal.com', ENC_ALGO, ENC_KEY, 0, ENC_IV));
$admin_password = password_hash('Admin@1234', PASSWORD_BCRYPT, ['cost' => 12]);

$stmt = $conn->prepare("INSERT IGNORE INTO users (username, email, password, role) VALUES (?, ?, ?, 'admin')");
$stmt->bind_param("sss", ...[' admin', $admin_email, $admin_password]);

// Use correct encryption
$enc_email = base64_encode(openssl_encrypt('admin@secureportal.com', ENC_ALGO, ENC_KEY, 0, ENC_IV));
$stmt2 = $conn->prepare("INSERT IGNORE INTO users (username, email, password, role) VALUES ('admin', ?, ?, 'admin')");
$stmt2->bind_param("ss", $enc_email, $admin_password);
if ($stmt2->execute()) {
    $success[] = "✅ Admin user created (or already exists)";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecurePortal Setup</title>
<style>
body { font-family: monospace; background: #0f172a; color: #e2e8f0; padding: 40px; }
h2 { color: #38bdf8; }
.ok { color: #22c55e; }
.err { color: #ef4444; }
.box { background: #1e293b; padding: 20px; border-radius: 10px; margin-top: 20px; }
.warn { background: #451a03; border: 1px solid #f59e0b; border-radius: 8px; padding: 14px; margin-top: 20px; color: #f59e0b; }
a { color: #38bdf8; }
</style>
</head>
<body>
<h2>🔧 SecurePortal — Database Setup</h2>
<div class="box">
<?php foreach ($success as $s) echo "<p class='ok'>{$s}</p>"; ?>
<?php foreach ($errors  as $e) echo "<p class='err'>{$e}</p>"; ?>
</div>

<div class="warn">
⚠️ <strong>IMPORTANT:</strong> Delete or rename this file after setup!<br>
Default admin login: <code>admin@secureportal.com</code> / <code>Admin@1234</code><br>
<strong>Change the password immediately after first login!</strong>
</div>

<p style="margin-top:20px"><a href="index.php">→ Go to Login Page</a></p>
</body>
</html>
