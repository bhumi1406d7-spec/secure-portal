<?php
// ============================================================
// data_classification.php — Data Classification Module
// (Requirement 4a from Problem Statement)
// ============================================================

require_once "security_helpers.php";

set_security_headers();
secure_session_start();

if (!isset($_SESSION['user']) || $_SESSION['role'] !== 'admin') {
    http_response_code(403);
    die("403 — Access Denied.");
}

$classifications = [
    'CRITICAL' => [
        'color'  => '#ef4444',
        'bg'     => '#450a0a',
        'desc'   => 'Highest sensitivity. Encrypted at rest + in transit. Access restricted to system only.',
        'fields' => ['password', 'ssn', 'credit_card', 'bank_account', 'private_key'],
        'rules'  => 'AES-256 encryption mandatory. No logging of values. No export allowed.',
    ],
    'SENSITIVE' => [
        'color'  => '#f59e0b',
        'bg'     => '#451a03',
        'desc'   => 'Personal Identifiable Information (PII). Encrypted at rest. Access logged.',
        'fields' => ['email', 'phone', 'date_of_birth', 'address', 'national_id'],
        'rules'  => 'AES-256 encryption. Access logged. GDPR/HIPAA applies.',
    ],
    'INTERNAL' => [
        'color'  => '#38bdf8',
        'bg'     => '#1e3a5f',
        'desc'   => 'Internal organisational data. Not publicly accessible. Stored in plain text.',
        'fields' => ['username', 'role', 'department', 'employee_id'],
        'rules'  => 'Access restricted to authenticated users. RBAC enforced.',
    ],
    'PUBLIC' => [
        'color'  => '#22c55e',
        'bg'     => '#052e16',
        'desc'   => 'No sensitivity. Freely accessible and shareable.',
        'fields' => ['app_name', 'version', 'public_announcements'],
        'rules'  => 'No encryption required. No access restriction.',
    ],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Data Classification — <?php echo APP_NAME; ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: white; padding: 30px; }
h2 { color: #38bdf8; margin-bottom: 8px; }
.subtitle { color: #64748b; font-size: 14px; margin-bottom: 28px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 30px; }
.class-card { border-radius: 12px; padding: 22px; border-left: 4px solid; }
.class-card h3 { font-size: 16px; margin-bottom: 6px; }
.class-card .desc { font-size: 13px; color: #94a3b8; margin-bottom: 14px; line-height: 1.5; }
.class-card .fields { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
.field-tag { padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.class-card .rule { font-size: 12px; color: #64748b; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 12px; }
.matrix { background: #1e293b; border-radius: 12px; padding: 20px; }
.matrix h3 { color: #38bdf8; margin-bottom: 16px; font-size: 15px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: #0f172a; padding: 10px 12px; text-align: left; color: #64748b; font-weight: 500; }
td { padding: 10px 12px; border-bottom: 1px solid #0f172a; }
.check { color: #22c55e; } .cross { color: #ef4444; }
.back { display: inline-block; margin-top: 20px; color: #38bdf8; text-decoration: none; font-size: 14px; }
</style>
</head>
<body>

<h2>🗂️ Data Classification</h2>
<p class="subtitle">Identifying and classifying all sensitive data within Cloud Counselage IAC platform</p>

<div class="grid">
    <?php foreach ($classifications as $level => $info): ?>
    <div class="class-card" style="background: <?php echo $info['bg']; ?>; border-color: <?php echo $info['color']; ?>;">
        <h3 style="color: <?php echo $info['color']; ?>;"><?php echo $level; ?></h3>
        <p class="desc"><?php echo htmlspecialchars($info['desc']); ?></p>
        <div class="fields">
            <?php foreach ($info['fields'] as $field): ?>
            <span class="field-tag" style="background: rgba(255,255,255,0.08); color: <?php echo $info['color']; ?>;">
                <?php echo htmlspecialchars($field); ?>
            </span>
            <?php endforeach; ?>
        </div>
        <div class="rule">📋 <?php echo htmlspecialchars($info['rules']); ?></div>
    </div>
    <?php endforeach; ?>
</div>

<!-- Protection Matrix -->
<div class="matrix">
    <h3>🔐 Protection Controls Matrix</h3>
    <table>
        <tr>
            <th>Control</th>
            <th>CRITICAL</th>
            <th>SENSITIVE</th>
            <th>INTERNAL</th>
            <th>PUBLIC</th>
        </tr>
        <?php
        $matrix = [
            ["AES-256 Encryption",          true,  true,  false, false],
            ["TLS/HTTPS in Transit",         true,  true,  true,  true],
            ["Access Logging",               true,  true,  true,  false],
            ["MFA Required",                 true,  true,  false, false],
            ["RBAC Enforced",                true,  true,  true,  false],
            ["GDPR Applies",                 true,  true,  false, false],
            ["Exportable",                   false, false, true,  true],
        ];
        foreach ($matrix as [$ctrl, $crit, $sens, $int, $pub]):
        ?>
        <tr>
            <td><?php echo htmlspecialchars($ctrl); ?></td>
            <td><?php echo $crit ? '<span class="check">✅</span>' : '<span class="cross">❌</span>'; ?></td>
            <td><?php echo $sens ? '<span class="check">✅</span>' : '<span class="cross">❌</span>'; ?></td>
            <td><?php echo $int  ? '<span class="check">✅</span>' : '<span class="cross">❌</span>'; ?></td>
            <td><?php echo $pub  ? '<span class="check">✅</span>' : '<span class="cross">❌</span>'; ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
</div>

<a href="admin.php" class="back">← Back to Dashboard</a>

</body>
</html>
