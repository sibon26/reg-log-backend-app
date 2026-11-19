package com.auth.backend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * Sends OTP emails via Spring Mail (Brevo SMTP or any SMTP provider).
 * Configure MAIL_* environment variables to enable real email delivery.
 * When mail.enabled=false the OTP is logged to the console for development use.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OtpEmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.from:noreply@secureauth.dev}")
    private String mailFrom;

    @Value("${mail.enabled:false}")
    private boolean mailEnabled;

    public void sendOtp(String toEmail, String fullName, String otp) {
        if (mailEnabled) {
            try {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setFrom(mailFrom);
                message.setTo(toEmail);
                message.setSubject("SecureAuth – Your Password Reset OTP");
                message.setText(buildOtpEmailBody(fullName, otp));
                mailSender.send(message);
                log.info("OTP email sent to: {}", toEmail);
            } catch (Exception ex) {
                // Log error but never expose OTP to caller
                log.error("Failed to send OTP email to {}: {}", toEmail, ex.getMessage());
                // Re-throw so the caller can surface a generic error
                throw new RuntimeException("Email delivery failed – please try again later");
            }
        } else {
            // Development fallback – print OTP to server console only
            log.info("╔═══════════════════════════════════════════════╗");
            log.info("║       PASSWORD RESET OTP  [DEV MODE]          ║");
            log.info("╠═══════════════════════════════════════════════╣");
            log.info("║  To   : {}", toEmail);
            log.info("║  Name : {}", fullName);
            log.info("║  OTP  : {}   (valid {} minutes)", otp, 5);
            log.info("╚═══════════════════════════════════════════════╝");
        }
    }

    private String buildOtpEmailBody(String fullName, String otp) {
        return String.format("""
                Hello %s,

                Your SecureAuth password reset OTP is:

                    %s

                This OTP is valid for 5 minutes and can only be used once.

                If you did not request a password reset, please ignore this email.
                Your account remains secure.

                — The SecureAuth Team
                """, fullName, otp);
    }
}
