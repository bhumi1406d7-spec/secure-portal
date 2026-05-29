<?php
// ============================================================
// logout.php — Secure Session Termination
// ============================================================

require_once "security_helpers.php";
require_once "logger.php";

secure_session_start();

if (isset($_SESSION['user'])) {
    logAction($_SESSION['user'], 'User logged out', 'INFO');
}

// 🔐 Fully destroy session
$_SESSION = [];

if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

session_destroy();

safe_redirect('index.php');
