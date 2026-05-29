-- ============================================================
-- schema.sql — Database Setup for Security Project
-- Run this once to create the required tables
-- ============================================================

CREATE DATABASE IF NOT EXISTS security_project CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE security_project;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    username   VARCHAR(50)  NOT NULL UNIQUE,
    email      TEXT         NOT NULL,          -- AES-256 encrypted
    password   VARCHAR(255) NOT NULL,          -- bcrypt hashed
    role       ENUM('user','admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit logs table (upgraded with severity, IP, user_agent)
CREATE TABLE IF NOT EXISTS logs (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user       VARCHAR(100) NOT NULL,
    action     TEXT         NOT NULL,
    severity   ENUM('INFO','WARNING','CRITICAL') DEFAULT 'INFO',
    ip_address VARCHAR(45)  DEFAULT NULL,
    user_agent VARCHAR(255) DEFAULT NULL,
    time       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);
CREATE INDEX IF NOT EXISTS idx_logs_time     ON logs(time);
CREATE INDEX IF NOT EXISTS idx_users_role    ON users(role);

-- Insert default admin (password: Admin@1234)
-- ⚠️ Change this password immediately after first login!
INSERT IGNORE INTO users (username, email, password, role)
VALUES (
    'admin',
    'REPLACE_WITH_ENCRYPTED_ADMIN_EMAIL',
    '$2y$12$exampleHashReplaceWithRealBcryptHash',
    'admin'
);
