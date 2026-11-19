package com.auth.backend.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Login request DTO.
 * Accepts either {@code identifier} (email or mobile) or {@code email}.
 */
@Data
public class LoginRequest {

    private String identifier;

    private String email;

    @NotBlank(message = "Password is required")
    private String password;

    public String getIdentifier() {
        if (identifier != null && !identifier.isBlank()) {
            return identifier;
        }
        return email;
    }

    @AssertTrue(message = "Email or mobile number is required")
    public boolean isValidIdentifier() {
        return (identifier != null && !identifier.isBlank()) ||
               (email != null && !email.isBlank());
    }
}
