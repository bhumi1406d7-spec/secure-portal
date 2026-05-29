<?php
// ============================================================
// compliance.php — GDPR / HIPAA / IT Act Compliance Module
// (Requirement 10 from Problem Statement)
// ============================================================

require_once "security_helpers.php";

set_security_headers();
secure_session_start();

if (!isset($_SESSION['user']) || $_SESSION['role'] !== 'admin') {
    http_response_code(403);
    die("403 — Access Denied.");
}

$gdpr = [
    ["Lawful basis for data processing",        true,  "User consent obtained at registration"],
    ["Right to erasure (Right to be forgotten)", false, "Not yet implemented — planned Sprint 3"],
    ["Data minimisation",                        true,  "Only email, username, password stored"],
    ["Encryption of personal data",              true,  "AES-256-CBC applied to PII fields"],
    ["Breach notification process",              false, "Policy documented, automation pending"],
    ["Privacy policy published",                 true,  "Linked at registration"],
    ["Data retention policy",                    false, "Not yet defined"],
];

$hipaa = [
    ["Access controls (RBAC)",                   true,  "Role-based access enforced on all pages"],
    ["Audit controls (logging)",                 true,  "Severity-based audit log with IP tracking"],
    ["Integrity controls",                       true,  "Parameterised queries prevent data tampering"],
    ["Transmission security (TLS)",              true,  "HTTPS enforced via Strict-Transport-Security header"],
    ["Authentication (MFA)",                     true,  "OTP MFA enforced on every login"],
    ["Automatic session timeout",                true,  "30-minute session lifetime configured"],
];

$it_act = [
    ["Section 43A — Reasonable security",        true,  "AES-256, bcrypt, CSRF, rate limiting in place"],
    ["Section 72A — Data disclosure",            true,  "No data shared without consent"],
    ["Encryption of sensitive data",             true,  "All PII encrypted at rest"],
];

function compliance_table(array $rows): void {
    $pass  = array_filter($rows, fn($r) => $r[1]);
    $score = count($pass) . '/' . count($rows);
    echo "<div class='score'>Compliance Score: <strong>{$score}</strong></div>";
    echo "<table><tr><th>Requirement</th><th>Status</th><th>Notes</th></tr>";
    foreach ($rows as [$req, $ok, $note]) {
        $icon  = $ok ? '✅' : '⚠️';
        $color = $ok ? '' : 'style="color:#f59e0b;"';
        echo "<tr><td {$color}>{$req}</td><td>{$icon}</td><td style='color:#94a3b8'>{$note}</td></tr>";
    }
    echo "</table>";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compliance — <?php echo APP_NAME; ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: white; padding: 30px; }
h2 { color: #38bdf8; margin-bottom: 6px; }
.subtitle { color: #64748b; font-size: 14px; margin-bottom: 28px; }
.section { background: #1e293b; border-radius: 12px; padding: 22px; margin-bottom: 22px; }
.section h3 { font-size: 16px; color: #38bdf8; margin-bottom: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }
th { background: #0f172a; padding: 10px 12px; text-align: left; color: #64748b; font-weight: 500; }
td { padding: 10px 12px; border-bottom: 1px solid #0f172a; }
.score { font-size: 14px; color: #22c55e; margin-bottom: 12px; }
.score strong { font-size: 18px; }
.gap-box { background: #451a03; border-left: 3px solid #f59e0b; border-radius: 8px; padding: 14px 18px; margin-top: 20px; }
.gap-box h4 { color: #f59e0b; margin-bottom: 8px; font-size: 14px; }
.gap-box ul { padding-left: 18px; color: #94a3b8; font-size: 13px; line-height: 2; }
.back { display: inline-block; margin-top: 20px; color: #38bdf8; text-decoration: none; font-size: 14px; }
</style>
</head>
<body>

<h2>🛡️ Compliance Documentation</h2>
<p class="subtitle">GDPR · HIPAA · IT Act 2000 — Status & Gap Analysis</p>

<div class="section">
    <h3>🇪🇺 GDPR — General Data Protection Regulation</h3>
    <?php compliance_table($gdpr); ?>
</div>

<div class="section">
    <h3>🏥 HIPAA — Health Insurance Portability and Accountability Act</h3>
    <?php compliance_table($hipaa); ?>
</div>

<div class="section">
    <h3>🇮🇳 IT Act 2000 (India)</h3>
    <?php compliance_table($it_act); ?>
</div>

<!-- Gap Analysis -->
<div class="gap-box">
    <h4>⚠️ Identified Gaps — Action Required</h4>
    <ul>
        <li>GDPR: Right to erasure not yet implemented — add DELETE user endpoint</li>
        <li>GDPR: Data retention policy must be defined and enforced</li>
        <li>GDPR: Automated breach notification system not in place</li>
        <li>Recommendation: Schedule quarterly security audit and penetration test</li>
    </ul>
</div>

<a href="admin.php" class="back">← Back to Dashboard</a>

</body>
</html>
