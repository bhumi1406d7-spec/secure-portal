<?php
// ============================================================
// logger.php — Audit Logger
// ============================================================

require_once "db.php";

function logAction(string $user, string $action, string $severity = 'INFO'): void {
    global $conn;

    $allowed = ['INFO', 'WARNING', 'CRITICAL'];
    if (!in_array($severity, $allowed)) $severity = 'INFO';

    $ip         = $_SERVER['REMOTE_ADDR']     ?? null;
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? null;

    // Truncate user_agent to fit column
    if ($user_agent) $user_agent = substr($user_agent, 0, 255);

    $stmt = $conn->prepare(
        "INSERT INTO logs (user, action, severity, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)"
    );
    if ($stmt) {
        $stmt->bind_param("sssss", $user, $action, $severity, $ip, $user_agent);
        $stmt->execute();
        $stmt->close();
    }
}
