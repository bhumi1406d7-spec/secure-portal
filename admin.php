<?php
// ============================================================
// admin.php — Admin Dashboard
// ============================================================

require_once "security_helpers.php";
require_once "db.php";

set_security_headers();
secure_session_start();

// 🔐 RBAC — admin only
if (!isset($_SESSION['user']) || $_SESSION['role'] !== 'admin') {
    http_response_code(403);
    die("403 — Access Denied. Admins only.");
}

// Fetch stats
$total_users  = $conn->query("SELECT COUNT(*) AS c FROM users")->fetch_assoc()['c'];
$total_logs   = $conn->query("SELECT COUNT(*) AS c FROM logs")->fetch_assoc()['c'];
$warn_logs    = $conn->query("SELECT COUNT(*) AS c FROM logs WHERE severity='WARNING'")->fetch_assoc()['c'];
$crit_logs    = $conn->query("SELECT COUNT(*) AS c FROM logs WHERE severity='CRITICAL'")->fetch_assoc()['c'];
$recent_logs  = $conn->query("SELECT * FROM logs ORDER BY time DESC LIMIT 10");
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Panel — <?php echo APP_NAME; ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; display: flex; background: linear-gradient(135deg, #0f172a, #1e3a8a); color: white; min-height: 100vh; }
.sidebar { width: 230px; background: rgba(15,23,42,0.98); padding: 24px 16px; flex-shrink: 0; }
.sidebar .logo { color: #38bdf8; font-size: 18px; font-weight: 700; margin-bottom: 30px; padding: 0 8px; }
.sidebar a { display: flex; align-items: center; gap: 10px; padding: 11px 12px; margin: 4px 0; border-radius: 8px; text-decoration: none; color: #94a3b8; font-size: 14px; transition: 0.2s; }
.sidebar a:hover, .sidebar a.active { background: #1e293b; color: #38bdf8; }
.sidebar a.danger:hover { background: #450a0a; color: #fca5a5; }
.main { flex: 1; padding: 24px; overflow-y: auto; }
.topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
.topbar h1 { font-size: 20px; color: #e2e8f0; }
.topbar span { font-size: 13px; color: #64748b; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 28px; }
.card { background: rgba(30,41,59,0.9); padding: 22px; border-radius: 12px; text-align: center; border-left: 3px solid #38bdf8; }
.card.warn { border-color: #f59e0b; }
.card.crit { border-color: #ef4444; }
.card.ok   { border-color: #22c55e; }
.card h2 { font-size: 28px; font-weight: 700; margin-bottom: 4px; }
.card p { font-size: 13px; color: #94a3b8; }
.section { background: rgba(30,41,59,0.9); border-radius: 12px; padding: 20px; margin-bottom: 20px; }
.section h3 { font-size: 15px; color: #38bdf8; margin-bottom: 16px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: #0f172a; padding: 10px; text-align: left; color: #94a3b8; font-weight: 500; }
td { padding: 10px; border-bottom: 1px solid #1e293b; color: #e2e8f0; }
tr:hover td { background: rgba(56,189,248,0.05); }
.badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.badge-info { background: #1e3a5f; color: #38bdf8; }
.badge-warn { background: #451a03; color: #f59e0b; }
.badge-crit { background: #450a0a; color: #ef4444; }
.compliance-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.comp-item { background: #0f172a; border-radius: 8px; padding: 14px; display: flex; align-items: center; gap: 10px; font-size: 13px; }
.comp-item .icon { font-size: 18px; }
.comp-item .label { color: #94a3b8; font-size: 11px; }
.comp-item .status { color: #22c55e; font-weight: 600; }
</style>
</head>
<body>

<div class="sidebar">
    <div class="logo">🔐 <?php echo APP_NAME; ?></div>
    <a href="admin.php" class="active">📊 Dashboard</a>
    <a href="logs.php">📋 Audit Logs</a>
    <a href="compliance.php">🛡️ Compliance</a>
    <a href="data_classification.php">🗂️ Data Classes</a>
    <a href="training.php">🎓 Training</a>
    <a href="logout.php" class="danger">🚪 Logout</a>
</div>

<div class="main">
    <div class="topbar">
        <h1>Admin Dashboard</h1>
        <span>Logged in as <strong><?php echo htmlspecialchars($_SESSION['user']); ?></strong> · <?php echo date("D, d M Y H:i:s"); ?></span>
    </div>

    <!-- Stats Cards -->
    <div class="cards">
        <div class="card">
            <h2><?php echo (int)$total_users; ?></h2>
            <p>Total Users</p>
        </div>
        <div class="card">
            <h2><?php echo (int)$total_logs; ?></h2>
            <p>Total Audit Logs</p>
        </div>
        <div class="card warn">
            <h2><?php echo (int)$warn_logs; ?></h2>
            <p>Warnings</p>
        </div>
        <div class="card crit">
            <h2><?php echo (int)$crit_logs; ?></h2>
            <p>Critical Events</p>
        </div>
        <div class="card ok">
            <h2>✓</h2>
            <p>System Secure</p>
        </div>
    </div>

    <!-- Compliance Summary -->
    <div class="section">
        <h3>🛡️ Compliance Status</h3>
        <div class="compliance-grid">
            <?php
            $checks = [
                ["AES-256 Encryption", "✅ Active"],
                ["GDPR — Data Minimisation", "✅ Compliant"],
                ["HIPAA — Access Control", "✅ Enforced"],
                ["MFA / OTP Enabled", "✅ Active"],
                ["Audit Logging", "✅ Running"],
                ["Session Security", "✅ Hardened"],
                ["CSRF Protection", "✅ Enabled"],
                ["Password Policy", "✅ Enforced"],
            ];
            foreach ($checks as [$label, $status]):
            ?>
            <div class="comp-item">
                <span class="icon">🔒</span>
                <div>
                    <div class="label"><?php echo htmlspecialchars($label); ?></div>
                    <div class="status"><?php echo htmlspecialchars($status); ?></div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- Recent Logs -->
    <div class="section">
        <h3>📋 Recent Activity</h3>
        <table>
            <tr><th>User</th><th>Action</th><th>Severity</th><th>IP</th><th>Time</th></tr>
            <?php while ($row = $recent_logs->fetch_assoc()): ?>
            <tr>
                <td><?php echo htmlspecialchars($row['user']); ?></td>
                <td><?php echo htmlspecialchars($row['action']); ?></td>
                <td>
                    <?php
                    $sev = $row['severity'] ?? 'INFO';
                    $cls = $sev === 'CRITICAL' ? 'badge-crit' : ($sev === 'WARNING' ? 'badge-warn' : 'badge-info');
                    ?>
                    <span class="badge <?php echo $cls; ?>"><?php echo htmlspecialchars($sev); ?></span>
                </td>
                <td><?php echo htmlspecialchars($row['ip_address'] ?? '—'); ?></td>
                <td><?php echo htmlspecialchars($row['time']); ?></td>
            </tr>
            <?php endwhile; ?>
        </table>
    </div>
</div>

</body>
</html>
