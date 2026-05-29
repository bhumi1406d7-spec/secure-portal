<?php
// ============================================================
// db.php — Secure Database Connection (Production Ready)
// ============================================================

$db_host = getenv('MYSQLHOST')     ?: getenv('DB_HOST') ?: 'localhost';
$db_user = getenv('MYSQLUSER')     ?: getenv('DB_USER') ?: 'root';
$db_pass = getenv('MYSQLPASSWORD') ?: getenv('DB_PASS') ?: '';
$db_name = getenv('MYSQLDATABASE') ?: getenv('DB_NAME') ?: 'security_project';
$db_port = (int)(getenv('MYSQLPORT') ?: getenv('DB_PORT') ?: 3306);

$conn = new mysqli($db_host, $db_user, $db_pass, $db_name, $db_port);

if ($conn->connect_error) {
    error_log("DB connection failed: " . $conn->connect_error);
    http_response_code(500);
    die(json_encode(["error" => "Service temporarily unavailable"]));
}

$conn->set_charset("utf8mb4");
$conn->query("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO'");
