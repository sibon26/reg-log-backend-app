package com.auth.backend.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

/**
 * Reset-password request.
 * Supports either resetToken or (email + otp).
 */
@Data
public class ResetPasswordRequest {

    private String resetToken;

    private String email;

    private String otp;

    @NotBlank(message = "New password is required")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
        message = "Password must be at least 8 characters with uppercase, lowercase, number and special character"
    )
    private String newPassword;

    @NotBlank(message = "Confirm password is required")
    private String confirmPassword;

    @AssertTrue(message = "Reset token or email with OTP is required")
    public boolean isValidResetIdentifier() {
        return (resetToken != null && !resetToken.isBlank()) ||
               (email != null && !email.isBlank() && otp != null && !otp.isBlank());
    }
}
