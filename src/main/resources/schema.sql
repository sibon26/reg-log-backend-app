-- ─────────────────────────────────────────────────────
-- auth_db – Database Schema
-- Run this file in MySQL to set up the database.
-- ─────────────────────────────────────────────────────

CREATE DATABASE IF NOT EXISTS auth_db;
USE auth_db;

-- ── Users Table ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    full_name      VARCHAR(100) NOT NULL,
    email          VARCHAR(255) NOT NULL UNIQUE,
    mobile_number  VARCHAR(10)  NOT NULL UNIQUE,
    password       VARCHAR(255) NOT NULL,
    created_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Revoked Tokens Table (JWT blacklist) ─────────────
CREATE TABLE IF NOT EXISTS revoked_tokens (
    id          BIGINT   NOT NULL AUTO_INCREMENT,
    token       LONGTEXT NOT NULL,
    revoked_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── OTP Records Table ─────────────────────────────────
CREATE TABLE IF NOT EXISTS otp_records (
    id          BIGINT      NOT NULL AUTO_INCREMENT,
    email       VARCHAR(255) NOT NULL,
    otp         VARCHAR(6)  NOT NULL,
    used        TINYINT(1)  DEFAULT 0,
    expires_at  DATETIME    NOT NULL,
    created_at  DATETIME    DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_otp_email (email),
    INDEX idx_otp_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
