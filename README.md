# 🔐 SecurePortal

A secure PHP web application demonstrating modern authentication and data protection practices — including AES-256 encryption, bcrypt password hashing, MFA via OTP, CSRF protection, rate limiting, RBAC, and a full audit logging system.

---

## ✨ Features

- **AES-256-CBC Encryption** — sensitive fields (e.g. email) encrypted at rest before database storage
- **bcrypt Password Hashing** — cost factor 12; never stored in plaintext
- **Multi-Factor Authentication (MFA)** — cryptographically secure 6-digit OTP required after password login
- **CSRF Protection** — unique per-session tokens on every form, verified server-side
- **Rate Limiting** — login locked after 5 failed attempts per 15 minutes; registration limited to 5 per hour
- **Session Security** — HttpOnly + SameSite=Strict cookies, session ID regeneration on login/privilege change
- **Security Headers** — `X-Frame-Options`, `Content-Security-Policy`, `HSTS`, `X-Content-Type-Options`, and more
- **Role-Based Access Control (RBAC)** — `admin` and `user` roles with separate dashboards
- **Audit Logging** — every significant action logged with severity, IP, user agent, and timestamp
- **Security Awareness Training** — built-in quiz module covering encryption, GDPR, RBAC, CSRF, and password hygiene
- **Data Classification** — fields tagged `CRITICAL / SENSITIVE / INTERNAL / PUBLIC` at registration

---

## 🗂️ Project Structure

```
├── index.php              # Login page
├── register.php           # User registration
├── login.php              # Authentication handler
├── verify.php             # MFA / OTP verification
├── logout.php             # Secure session teardown
├── logs.php               # Audit log viewer (admin only)
├── training.php           # Security awareness training module
├── security_helpers.php   # Encryption, CSRF, rate limiting, headers
├── logger.php             # Audit logger
├── schema.sql             # Database schema + default admin seed
├── setup.php              # One-time DB setup script
└── Dockerfile             # PHP 8.2 + Apache container
```

---

## 🚀 Getting Started

### Prerequisites

- [Docker](https://www.docker.com/) — or a local PHP 8.2 + Apache + MySQL stack

### Run with Docker

```bash
# 1. Clone the repository
git clone https://github.com/your-username/secureportal.git
cd secureportal

# 2. Build the image
docker build -t secureportal .

# 3. Run the container (attach to your MySQL instance)
docker run -p 8080:80 secureportal
```

> You will need a running MySQL instance. Update `config.php` with your database credentials before building.

### Database Setup

1. Import `schema.sql` into your MySQL database, **or** visit `/setup.php` once after deployment — it creates all tables and seeds the default admin user.
2. **Delete `setup.php` immediately after running it.**

Default admin credentials (change immediately):
```
Email:    admin@secureportal.com
Password: Admin@1234
```

---

## ⚙️ Configuration

Create a `config.php` file (not included for security reasons) with the following constants:

```php
<?php
define('APP_NAME',            'SecurePortal');
define('DB_HOST',             'localhost');
define('DB_USER',             'your_db_user');
define('DB_PASS',             'your_db_password');
define('DB_NAME',             'security_project');

define('ENC_ALGO',            'AES-256-CBC');
define('ENC_KEY',             'your-32-byte-secret-key-here!!!'); // exactly 32 chars
define('ENC_IV',              'your-16-byte-iv!');                // exactly 16 chars

define('SESSION_LIFETIME',    1800);   // seconds
define('OTP_EXPIRY',          300);    // seconds
define('OTP_MAX_ATTEMPTS',    3);
define('MAX_LOGIN_ATTEMPTS',  5);
define('LOGIN_LOCKOUT_TIME',  900);    // seconds
```

> ⚠️ **Never commit `config.php` to version control.** Add it to `.gitignore`.

---

## 🔒 Security Notes

| Area | Implementation |
|---|---|
| Passwords | bcrypt, cost 12 (`PASSWORD_BCRYPT`) |
| Email storage | AES-256-CBC, base64-encoded |
| Session cookies | `HttpOnly`, `SameSite=Strict`, `Secure` (on HTTPS) |
| SQL queries | 100% prepared statements — no raw interpolation |
| OTP | `random_int()` (CSPRNG), hashed with `password_hash()` in session |
| CSRF | `hash_equals()` constant-time comparison |
| Redirects | Allowlist-based — no open redirect possible |

> In production, OTP should be delivered via email or SMS. The demo displays it on-screen — remove this before going live.

---

## 📋 Compliance Notes

This project demonstrates practices aligned with:

- **GDPR** — data minimisation, encryption at rest, audit trails
- **OWASP Top 10** — protections against SQLi, XSS, CSRF, broken authentication, and security misconfiguration
- **NIST guidelines** — AES-256, bcrypt, MFA

---

## 📄 License

MIT License — see `LICENSE` for details.
