<?php
// ============================================================
// training.php — Security Awareness Training Module
// (Requirement 9 from Problem Statement)
// ============================================================

require_once "security_helpers.php";
require_once "logger.php";

set_security_headers();
secure_session_start();

if (!isset($_SESSION['user'])) {
    safe_redirect('index.php');
}

$questions = [
    [
        "q"    => "Which encryption standard does this system use to protect sensitive data at rest?",
        "opts" => ["MD5", "AES-128", "AES-256-CBC", "DES"],
        "ans"  => 2,
        "exp"  => "AES-256-CBC (Advanced Encryption Standard, 256-bit key) is the industry gold standard for data at rest encryption, as recommended by NIST."
    ],
    [
        "q"    => "What does MFA stand for and why is it important?",
        "opts" => ["Multi-Factor Authentication — adds a second verification step beyond password", "Main Firewall Application — protects the server", "Managed File Access — controls file permissions", "Multi-Form Architecture — design pattern"],
        "ans"  => 0,
        "exp"  => "MFA (Multi-Factor Authentication) requires users to verify identity through a second factor (e.g., OTP) after their password, preventing account takeover even if the password is compromised."
    ],
    [
        "q"    => "What is GDPR and who must comply?",
        "opts" => ["A Python library for encryption", "General Data Protection Regulation — applies to organisations handling EU citizens' personal data", "A firewall configuration standard", "A database query language"],
        "ans"  => 1,
        "exp"  => "GDPR (General Data Protection Regulation) is an EU law protecting personal data. Any organisation processing EU residents' data must comply, regardless of where the organisation is based."
    ],
    [
        "q"    => "What does RBAC stand for and what does it prevent?",
        "opts" => ["Random Block Access Control", "Role-Based Access Control — ensures users only access what their role permits", "Remote Backup And Copy", "Routing Based Application Cache"],
        "ans"  => 1,
        "exp"  => "RBAC (Role-Based Access Control) assigns permissions based on a user's role (e.g., admin vs user). It prevents privilege escalation and limits damage if an account is compromised."
    ],
    [
        "q"    => "Which of the following is a safe password practice?",
        "opts" => ["Use your name and birthday", "Use the same password everywhere for convenience", "Use a minimum 8-character password with uppercase, numbers, and special characters", "Share your password with a trusted colleague"],
        "ans"  => 2,
        "exp"  => "Strong passwords use 8+ characters with mixed case, numbers, and symbols. Never reuse passwords or share them. Use a password manager if needed."
    ],
    [
        "q"    => "What is a CSRF attack?",
        "opts" => ["A virus that encrypts files", "Cross-Site Request Forgery — tricks a logged-in user into unknowingly submitting a malicious request", "A brute-force attack on passwords", "A type of SQL injection"],
        "ans"  => 1,
        "exp"  => "CSRF (Cross-Site Request Forgery) exploits a user's active session to make unauthorised requests on their behalf. Our system prevents this using unique CSRF tokens on every form."
    ],
    [
        "q"    => "If you suspect a data breach, what should you do first?",
        "opts" => ["Delete the logs to avoid evidence", "Ignore it and hope it resolves itself", "Immediately notify the security/admin team and document the incident", "Change only your own password"],
        "ans"  => 2,
        "exp"  => "Immediate reporting enables the team to contain the breach, notify affected parties (required under GDPR within 72 hours), and prevent further damage."
    ],
];

$score    = null;
$answers  = [];
$total    = count($questions);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && verify_csrf($_POST['csrf'] ?? '')) {
    $score = 0;
    foreach ($questions as $i => $q) {
        $submitted = intval($_POST["q{$i}"] ?? -1);
        $answers[$i] = $submitted;
        if ($submitted === $q['ans']) $score++;
    }
    $pct = round(($score / $total) * 100);
    logAction($_SESSION['user'], "Completed security training: {$score}/{$total} ({$pct}%)", 'INFO');
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Training — <?php echo APP_NAME; ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: white; padding: 30px; max-width: 800px; margin: 0 auto; }
h2 { color: #38bdf8; margin-bottom: 6px; }
.subtitle { color: #64748b; font-size: 14px; margin-bottom: 28px; }
.q-card { background: #1e293b; border-radius: 12px; padding: 22px; margin-bottom: 20px; border-left: 3px solid #334155; }
.q-card.correct { border-color: #22c55e; }
.q-card.wrong   { border-color: #ef4444; }
.q-card h4 { font-size: 14px; color: #e2e8f0; margin-bottom: 14px; line-height: 1.5; }
.q-num { font-size: 11px; color: #38bdf8; margin-bottom: 6px; font-weight: 600; }
.option { display: flex; align-items: flex-start; gap: 10px; margin: 8px 0; cursor: pointer; }
.option input { margin-top: 2px; accent-color: #38bdf8; }
.option label { font-size: 13px; color: #94a3b8; cursor: pointer; line-height: 1.4; }
.option.selected label { color: #e2e8f0; }
button[type=submit] { width: 100%; padding: 13px; background: #38bdf8; border: none; border-radius: 10px; color: #0f172a; font-weight: 700; font-size: 16px; cursor: pointer; margin-top: 10px; }
button[type=submit]:hover { background: #0284c7; color: white; }
.result-box { background: #1e293b; border-radius: 12px; padding: 28px; text-align: center; margin-bottom: 24px; }
.result-box .big { font-size: 52px; font-weight: 700; }
.result-box p { color: #94a3b8; font-size: 14px; margin-top: 6px; }
.pass { color: #22c55e; } .fail { color: #ef4444; }
.explanation { background: #0f172a; border-radius: 8px; padding: 12px 14px; margin-top: 12px; font-size: 13px; color: #94a3b8; line-height: 1.6; border-left: 3px solid #38bdf8; }
.correct-label { color: #22c55e; font-size: 12px; font-weight: 600; }
.wrong-label   { color: #ef4444; font-size: 12px; font-weight: 600; }
.back { display: inline-block; margin-top: 20px; color: #38bdf8; text-decoration: none; font-size: 14px; }
.progress { height: 6px; background: #1e293b; border-radius: 3px; margin-bottom: 24px; overflow: hidden; }
.progress-fill { height: 100%; border-radius: 3px; background: #38bdf8; transition: width 0.5s; }
</style>
</head>
<body>

<h2>🎓 Security Awareness Training</h2>
<p class="subtitle">Complete all <?php echo $total; ?> questions to earn your security certification</p>

<?php if ($score !== null): ?>
    <?php $pct = round(($score / $total) * 100); $pass = $pct >= 70; ?>
    <div class="result-box">
        <div class="big <?php echo $pass ? 'pass' : 'fail'; ?>"><?php echo $pct; ?>%</div>
        <p><?php echo $pass
            ? "🎉 Excellent! You passed the security training ({$score}/{$total} correct)."
            : "⚠️ You scored {$score}/{$total}. Score 70%+ to pass. Review the explanations below and retake.";
        ?></p>
    </div>
    <div class="progress">
        <div class="progress-fill" style="width: <?php echo $pct; ?>%;"></div>
    </div>
<?php endif; ?>

<form method="POST">
    <?php echo csrf_input(); ?>

    <?php foreach ($questions as $i => $q):
        $submitted  = $answers[$i] ?? null;
        $is_correct = $score !== null && $submitted === $q['ans'];
        $is_wrong   = $score !== null && $submitted !== $q['ans'];
        $card_class = $score === null ? '' : ($is_correct ? 'correct' : 'wrong');
    ?>
    <div class="q-card <?php echo $card_class; ?>">
        <div class="q-num">Question <?php echo $i + 1; ?> of <?php echo $total; ?></div>
        <h4><?php echo htmlspecialchars($q['q']); ?></h4>

        <?php foreach ($q['opts'] as $j => $opt):
            $checked   = $submitted === $j ? 'checked' : '';
            $opt_class = '';
            if ($score !== null && $j === $q['ans']) $opt_class = 'correct-label';
            if ($score !== null && $submitted === $j && $j !== $q['ans']) $opt_class = 'wrong-label';
        ?>
        <div class="option <?php echo $checked ? 'selected' : ''; ?>">
            <input type="radio" name="q<?php echo $i; ?>" id="q<?php echo $i; ?>o<?php echo $j; ?>"
                   value="<?php echo $j; ?>" <?php echo $checked; ?>
                   <?php echo $score !== null ? 'disabled' : ''; ?>>
            <label for="q<?php echo $i; ?>o<?php echo $j; ?>" class="<?php echo $opt_class; ?>">
                <?php echo htmlspecialchars($opt); ?>
                <?php if ($score !== null && $j === $q['ans']): ?> ✅<?php endif; ?>
                <?php if ($score !== null && $submitted === $j && $j !== $q['ans']): ?> ❌<?php endif; ?>
            </label>
        </div>
        <?php endforeach; ?>

        <?php if ($score !== null): ?>
        <div class="explanation">
            💡 <strong>Explanation:</strong> <?php echo htmlspecialchars($q['exp']); ?>
        </div>
        <?php endif; ?>
    </div>
    <?php endforeach; ?>

    <?php if ($score === null): ?>
        <button type="submit">Submit Answers</button>
    <?php else: ?>
        <a href="training.php" style="display:block; text-align:center; padding:13px; background:#334155; border-radius:10px; color:#e2e8f0; text-decoration:none; font-weight:600; margin-top:10px;">🔄 Retake Training</a>
    <?php endif; ?>
</form>

<a href="<?php echo $_SESSION['role'] === 'admin' ? 'admin.php' : 'dashboard.php'; ?>" class="back">← Back</a>

</body>
</html>
