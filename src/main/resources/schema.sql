-- ─────────────────────────────────────────────────────────────────────────
-- auth_db – Database Schema
-- Run this file in MySQL to set up the database for the auth application.
-- ─────────────────────────────────────────────────────────────────────────

CREATE DATABASE IF NOT EXISTS auth_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE auth_db;

-- ── Users Table ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    full_name      VARCHAR(100) NOT NULL,
    email          VARCHAR(255) NOT NULL UNIQUE,
    mobile_number  VARCHAR(10)  NOT NULL UNIQUE,
    password       VARCHAR(255) NOT NULL,   -- BCrypt hash only
    created_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_users_email         (email),
    INDEX idx_users_mobile_number (mobile_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Auth Sessions Table (server-side JWT sessions) ──────────────────────
CREATE TABLE IF NOT EXISTS auth_sessions (
    id          BIGINT       NOT NULL AUTO_INCREMENT,
    user_id     BIGINT       NOT NULL,
    token_id    VARCHAR(64)  NOT NULL UNIQUE,   -- JWT jti
    created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME     NOT NULL,
    revoked     TINYINT(1)   DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE  INDEX idx_session_jti     (token_id),
    INDEX         idx_session_user_id (user_id),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── OTP Records Table (hashed OTPs for password reset) ──────────────────
CREATE TABLE IF NOT EXISTS otp_records (
    id                BIGINT       NOT NULL AUTO_INCREMENT,
    email             VARCHAR(255) NOT NULL,
    otp_hash          VARCHAR(64)  NOT NULL,   -- SHA-256 of OTP; never plaintext
    used              TINYINT(1)   DEFAULT 0,
    attempts          INT          DEFAULT 0,
    expires_at        DATETIME     NOT NULL,
    reset_token_hash  VARCHAR(64),              -- SHA-256 of single-use reset token
    reset_expires_at  DATETIME,
    created_at        DATETIME     DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_otp_email   (email),
    INDEX idx_otp_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
