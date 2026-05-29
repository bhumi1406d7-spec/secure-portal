<?php
// ============================================================
// logs.php — Full Audit Log Viewer (Admin Only)
// ============================================================

require_once "security_helpers.php";
require_once "db.php";

set_security_headers();
secure_session_start();

// 🔐 Admin only
if (!isset($_SESSION['user']) || $_SESSION['role'] !== 'admin') {
    http_response_code(403);
    die("403 — Access Denied.");
}

// 🔐 Filtering (whitelist values)
$allowed_severity = ['ALL', 'INFO', 'WARNING', 'CRITICAL'];
$filter_sev = $_GET['severity'] ?? 'ALL';
if (!in_array($filter_sev, $allowed_severity)) {
    $filter_sev = 'ALL';
}

if ($filter_sev === 'ALL') {
    $result = $conn->query("SELECT * FROM logs ORDER BY time DESC LIMIT 200");
} else {
    $stmt = $conn->prepare("SELECT * FROM logs WHERE severity = ? ORDER BY time DESC LIMIT 200");
    $stmt->bind_param("s", $filter_sev);
    $stmt->execute();
    $result = $stmt->get_result();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Audit Logs — <?php echo APP_NAME; ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: white; padding: 24px; }
h2 { color: #38bdf8; margin-bottom: 20px; }
.filter-bar { display: flex; gap: 10px; margin-bottom: 20px; align-items: center; flex-wrap: wrap; }
.filter-bar a { padding: 6px 16px; border-radius: 20px; text-decoration: none; font-size: 13px; font-weight: 500; background: #1e293b; color: #94a3b8; border: 1px solid #334155; transition: 0.2s; }
.filter-bar a.active, .filter-bar a:hover { background: #38bdf8; color: #0f172a; border-color: #38bdf8; }
.filter-bar a.warn.active { background: #f59e0b; color: #0f172a; border-color: #f59e0b; }
.filter-bar a.crit.active { background: #ef4444; color: white; border-color: #ef4444; }
table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; font-size: 13px; }
th { background: #0f172a; padding: 12px; text-align: left; color: #64748b; font-weight: 500; }
td { padding: 10px 12px; border-bottom: 1px solid #0f172a; }
tr:hover td { background: rgba(56,189,248,0.05); }
.badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.badge-INFO     { background: #1e3a5f; color: #38bdf8; }
.badge-WARNING  { background: #451a03; color: #f59e0b; }
.badge-CRITICAL { background: #450a0a; color: #ef4444; }
.back { display: inline-block; margin-top: 20px; color: #38bdf8; text-decoration: none; font-size: 14px; }
.back:hover { text-decoration: underline; }
</style>
</head>
<body>

<h2>📋 Audit Logs</h2>

<div class="filter-bar">
    <span style="color:#64748b; font-size:13px;">Filter:</span>
    <a href="logs.php?severity=ALL"      class="<?php echo $filter_sev==='ALL'?'active':''; ?>">All</a>
    <a href="logs.php?severity=INFO"     class="<?php echo $filter_sev==='INFO'?'active':''; ?>">Info</a>
    <a href="logs.php?severity=WARNING"  class="warn <?php echo $filter_sev==='WARNING'?'active':''; ?>">Warning</a>
    <a href="logs.php?severity=CRITICAL" class="crit <?php echo $filter_sev==='CRITICAL'?'active':''; ?>">Critical</a>
</div>

<table>
    <tr>
        <th>User</th>
        <th>Action</th>
        <th>Severity</th>
        <th>IP Address</th>
        <th>User Agent</th>
        <th>Time</th>
    </tr>
    <?php while ($row = $result->fetch_assoc()): ?>
    <tr>
        <td><?php echo htmlspecialchars($row['user']); ?></td>
        <td><?php echo htmlspecialchars($row['action']); ?></td>
        <td>
            <?php $s = htmlspecialchars($row['severity'] ?? 'INFO'); ?>
            <span class="badge badge-<?php echo $s; ?>"><?php echo $s; ?></span>
        </td>
        <td><?php echo htmlspecialchars($row['ip_address'] ?? '—'); ?></td>
        <td style="max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#64748b;">
            <?php echo htmlspecialchars(substr($row['user_agent'] ?? '', 0, 60)); ?>
        </td>
        <td><?php echo htmlspecialchars($row['time']); ?></td>
    </tr>
    <?php endwhile; ?>
</table>

<a href="admin.php" class="back">← Back to Dashboard</a>

</body>
</html>
