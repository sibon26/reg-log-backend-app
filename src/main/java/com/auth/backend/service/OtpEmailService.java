package com.auth.backend.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Mock email service for development purposes.
 * In production, replace this with JavaMailSender / SendGrid / AWS SES etc.
 * OTPs are printed to the console log ONLY – never included in API responses.
 */
@Service
@Slf4j
public class OtpEmailService {

    public void sendOtp(String email, String fullName, String otp) {
        // ──────────────────────────────────────────────────────────────────
        // DEVELOPMENT MOCK: print OTP to console so you can test it easily.
        // Replace this block with a real email-sending integration for prod.
        // ──────────────────────────────────────────────────────────────────
        log.info("╔══════════════════════════════════════════════╗");
        log.info("║          PASSWORD RESET OTP (DEV MODE)       ║");
        log.info("╠══════════════════════════════════════════════╣");
        log.info("║  To      : {}",  email);
        log.info("║  Name    : {}",  fullName);
        log.info("║  OTP     : {}  (valid 10 min)", otp);
        log.info("╚══════════════════════════════════════════════╝");
    }
}
