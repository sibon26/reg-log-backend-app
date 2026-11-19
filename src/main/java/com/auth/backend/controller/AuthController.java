package com.auth.backend.controller;

import com.auth.backend.dto.*;
import com.auth.backend.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

/**
 * Authentication REST controller.
 * JWT is delivered via HttpOnly cookie – never in the response body.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // POST /api/auth/register or /api/auth/signup
    @PostMapping({"/register", "/signup"})
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody SignupRequest request,
            HttpServletResponse response) {
        AuthResponse res = authService.signup(request, response);
        return ResponseEntity.status(HttpStatus.CREATED).body(res);
    }

    // POST /api/auth/login
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response) {
        AuthResponse res = authService.login(request, response);
        return ResponseEntity.ok(res);
    }

    // POST /api/auth/logout
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logout(
            HttpServletRequest request,
            HttpServletResponse response) {
        authService.logout(request, response);
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully"));
    }

    // POST /api/auth/forgot-password
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {
        return ResponseEntity.ok(authService.forgotPassword(request));
    }

    // POST /api/auth/verify-otp
    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse> verifyOtp(
            @Valid @RequestBody VerifyOtpRequest request) {
        return ResponseEntity.ok(authService.verifyOtp(request));
    }

    // POST /api/auth/reset-password
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {
        return ResponseEntity.ok(authService.resetPassword(request));
    }

    // GET /api/auth/me – returns the authenticated user's profile
    @GetMapping("/me")
    public ResponseEntity<ApiResponse> getMe(
            @AuthenticationPrincipal UserDetails userDetails) {
        UserDto user = authService.getMe(userDetails.getUsername());
        return ResponseEntity.ok(ApiResponse.success("User details retrieved", user));
    }

    // PUT /api/auth/change-password  (requires authentication)
    @PutMapping("/change-password")
    public ResponseEntity<ApiResponse> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse,
            @AuthenticationPrincipal UserDetails userDetails) {
        ApiResponse res = authService.changePassword(request, httpRequest, httpResponse,
                userDetails.getUsername());
        return ResponseEntity.ok(res);
    }
}
