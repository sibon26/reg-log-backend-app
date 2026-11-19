package com.auth.backend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Stores OTP state for password reset flows.
 * Only the SHA-256 hash of the OTP is persisted – the plaintext OTP is never stored.
 */
@Entity
@Table(name = "otp_records", indexes = {
        @Index(name = "idx_otp_email",   columnList = "email"),
        @Index(name = "idx_otp_expires", columnList = "expires_at")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "email", nullable = false, length = 255)
    private String email;

    /** SHA-256 hash of the OTP – never store plaintext. */
    @Column(name = "otp_hash", nullable = false, length = 64)
    private String otpHash;

    @Builder.Default
    @Column(name = "used", nullable = false)
    private boolean used = false;

    @Builder.Default
    @Column(name = "attempts", nullable = false)
    private int attempts = 0;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    /** Optional: single-use reset token issued after successful OTP verification. */
    @Column(name = "reset_token_hash", length = 64)
    private String resetTokenHash;

    @Column(name = "reset_expires_at")
    private LocalDateTime resetExpiresAt;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
}
