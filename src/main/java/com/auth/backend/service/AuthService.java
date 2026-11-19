package com.auth.backend.service;

import com.auth.backend.dto.*;
import com.auth.backend.entity.AuthSession;
import com.auth.backend.entity.OtpRecord;
import com.auth.backend.entity.User;
import com.auth.backend.exception.BadRequestException;
import com.auth.backend.exception.ResourceNotFoundException;
import com.auth.backend.exception.UnauthorizedException;
import com.auth.backend.repository.AuthSessionRepository;
import com.auth.backend.repository.OtpRepository;
import com.auth.backend.repository.UserRepository;
import com.auth.backend.security.JwtTokenProvider;
import com.auth.backend.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HexFormat;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final AuthSessionRepository authSessionRepository;
    private final OtpRepository otpRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final OtpEmailService otpEmailService;
    private final CookieUtil cookieUtil;

    @Value("${otp.expiry-minutes:5}")
    private int otpExpiryMinutes;

    @Value("${otp.max-attempts:5}")
    private int otpMaxAttempts;

    // ─────────────────────────────── SIGNUP ───────────────────────────────────

    @Transactional
    public AuthResponse signup(SignupRequest request, HttpServletResponse response) {
        // Validate passwords match
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("Passwords do not match");
        }

        // Check uniqueness
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("Email address is already registered");
        }
        if (userRepository.existsByMobileNumber(request.getMobileNumber())) {
            throw new BadRequestException("Mobile number is already registered");
        }

        // Build and save user
        User user = User.builder()
                .fullName(request.getFullName())
                .email(request.getEmail().toLowerCase().trim())
                .mobileNumber(request.getMobileNumber().trim())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        user = userRepository.save(user);
        log.info("New user registered: {}", user.getEmail());

        // Generate JWT and set HttpOnly cookie
        String token = jwtTokenProvider.generateToken(user.getEmail());
        String jti   = jwtTokenProvider.getJtiFromToken(token);

        LocalDateTime expiresAt = jwtTokenProvider.getExpirationFromToken(token)
                .toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();

        authSessionRepository.save(AuthSession.builder()
                .user(user)
                .tokenId(jti)
                .expiresAt(expiresAt)
                .build());

        cookieUtil.setJwtCookie(response, token);

        return AuthResponse.builder()
                .success(true)
                .message("Account created successfully!")
                .token(token)
                .user(mapToUserDto(user))
                .build();
    }

    // ─────────────────────────────── LOGIN ────────────────────────────────────

    @Transactional
    public AuthResponse login(LoginRequest request, HttpServletResponse response) {
        String identifier = request.getIdentifier().trim();

        // Resolve the email from email-or-mobile identifier
        String email = resolveEmail(identifier);

        try {
            // Authenticate using email principal (CustomUserDetailsService handles both)
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(identifier, request.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (BadCredentialsException e) {
            throw new UnauthorizedException("Invalid credentials");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));

        // Generate JWT and set HttpOnly cookie
        String token = jwtTokenProvider.generateToken(user.getEmail());
        String jti   = jwtTokenProvider.getJtiFromToken(token);

        // Create server-side session record
        LocalDateTime expiresAt = jwtTokenProvider.getExpirationFromToken(token)
                .toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();

        AuthSession session = AuthSession.builder()
                .user(user)
                .tokenId(jti)
                .expiresAt(expiresAt)
                .revoked(false)
                .build();
        authSessionRepository.save(session);

        // Set the HttpOnly cookie – JWT never goes in the response body
        cookieUtil.setJwtCookie(response, token);

        log.info("User logged in: {}", user.getEmail());

        return AuthResponse.builder()
                .success(true)
                .message("Welcome back, " + user.getFullName() + "!")
                .token(token)
                .user(mapToUserDto(user))
                .build();
    }

    // ─────────────────────────────── LOGOUT ───────────────────────────────────

    @Transactional
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String token = cookieUtil.getJwtFromCookie(request);

        if (token != null && jwtTokenProvider.validateToken(token)) {
            String jti = jwtTokenProvider.getJtiFromToken(token);
            authSessionRepository.revokeByTokenId(jti);
            log.info("Session revoked: {}", jti);
        }

        // Clear the cookie regardless (idempotent)
        cookieUtil.clearJwtCookie(response);
    }

    // ─────────────────────────────── GET ME ───────────────────────────────────

    public UserDto getMe(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return mapToUserDto(user);
    }

    // ─────────────────────────── FORGOT PASSWORD ──────────────────────────────

    @Transactional
    public ApiResponse forgotPassword(ForgotPasswordRequest request) {
        // Always return success to avoid user enumeration
        String email = request.getEmail().toLowerCase().trim();

        userRepository.findByEmail(email).ifPresent(user -> {
            // Invalidate any existing OTPs
            otpRepository.invalidateAllOtpForEmail(email);

            // Generate & hash OTP
            String otp    = generateOtp();
            String otpHash = sha256(otp);

            OtpRecord otpRecord = OtpRecord.builder()
                    .email(email)
                    .otpHash(otpHash)
                    .used(false)
                    .attempts(0)
                    .expiresAt(LocalDateTime.now().plusMinutes(otpExpiryMinutes))
                    .build();

            otpRepository.save(otpRecord);

            // Send OTP (real email if mail.enabled=true, console otherwise)
            try {
                otpEmailService.sendOtp(email, user.getFullName(), otp);
            } catch (Exception ex) {
                log.warn("OTP email delivery issue for {}: {}", email, ex.getMessage());
                // Still continue – user sees generic message
            }
        });

        // Generic response – does not reveal whether email exists
        return ApiResponse.success(
                "If that email is registered, an OTP has been sent. Check your inbox (or server console in dev mode).");
    }

    // ─────────────────────────────── VERIFY OTP ───────────────────────────────

    @Transactional
    public ApiResponse verifyOtp(VerifyOtpRequest request) {
        String email = request.getEmail().toLowerCase().trim();

        OtpRecord otpRecord = otpRepository
                .findLatestValidOtp(email, LocalDateTime.now())
                .orElseThrow(() -> new BadRequestException("Invalid or expired OTP. Please request a new one."));

        // Increment attempt counter
        otpRecord.setAttempts(otpRecord.getAttempts() + 1);
        if (otpRecord.getAttempts() > otpMaxAttempts) {
            otpRecord.setUsed(true);
            otpRepository.save(otpRecord);
            throw new BadRequestException("Too many incorrect attempts. Please request a new OTP.");
        }

        // Verify hash
        if (!sha256(request.getOtp()).equals(otpRecord.getOtpHash())) {
            otpRepository.save(otpRecord);
            throw new BadRequestException("Invalid OTP. Please try again.");
        }

        // OTP verified – issue single-use reset token
        String resetToken = UUID.randomUUID().toString();
        otpRecord.setResetTokenHash(sha256(resetToken));
        otpRecord.setResetExpiresAt(LocalDateTime.now().plusMinutes(10));
        otpRepository.save(otpRecord);

        return ApiResponse.success("OTP verified. Use the reset token to set your new password.", resetToken);
    }

    // ──────────────────────────── RESET PASSWORD ──────────────────────────────

    @Transactional
    public ApiResponse resetPassword(ResetPasswordRequest request) {
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("Passwords do not match");
        }

        OtpRecord otpRecord;
        if (request.getResetToken() != null && !request.getResetToken().isBlank()) {
            String tokenHash = sha256(request.getResetToken());
            otpRecord = otpRepository
                    .findByResetTokenHash(tokenHash, LocalDateTime.now())
                    .orElseThrow(() -> new BadRequestException("Invalid or expired reset token. Please start over."));
        } else {
            String email = request.getEmail().toLowerCase().trim();
            otpRecord = otpRepository
                    .findLatestValidOtp(email, LocalDateTime.now())
                    .orElseThrow(() -> new BadRequestException("Invalid or expired OTP. Please start over."));
            if (!sha256(request.getOtp()).equals(otpRecord.getOtpHash())) {
                throw new BadRequestException("Invalid OTP. Please check and try again.");
            }
        }

        // Consume the token
        otpRecord.setUsed(true);
        otpRecord.setResetTokenHash(null);
        otpRepository.save(otpRecord);

        // Update password
        User user = userRepository.findByEmail(otpRecord.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Revoke all existing sessions
        int revoked = authSessionRepository.revokeAllByUserId(user.getId());
        log.info("Password reset for {}. {} session(s) revoked.", user.getEmail(), revoked);

        return ApiResponse.success("Password reset successfully. Please sign in with your new password.");
    }

    // ──────────────────────────── CHANGE PASSWORD ─────────────────────────────

    @Transactional
    public ApiResponse changePassword(ChangePasswordRequest request,
                                       HttpServletRequest httpRequest,
                                       HttpServletResponse httpResponse,
                                       String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new BadRequestException("Current password is incorrect");
        }

        // New password must differ
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new BadRequestException("New password must be different from the current password");
        }

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("Passwords do not match");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Revoke all sessions including the current one
        authSessionRepository.revokeAllByUserId(user.getId());

        // Clear the cookie
        cookieUtil.clearJwtCookie(httpResponse);

        log.info("Password changed for user: {}", email);

        return ApiResponse.success("Password changed successfully. Please sign in again.");
    }

    // ─────────────────────────────── HELPERS ──────────────────────────────────

    private String resolveEmail(String identifier) {
        // Mobile number (10 digits)
        if (identifier.matches("^[0-9]{10}$")) {
            return userRepository.findByMobileNumber(identifier)
                    .map(User::getEmail)
                    .orElse(identifier); // fallback – auth manager will reject anyway
        }
        return identifier.toLowerCase().trim();
    }

    private UserDto mapToUserDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .mobileNumber(user.getMobileNumber())
                .createdAt(user.getCreatedAt())
                .build();
    }

    private String generateOtp() {
        SecureRandom random = new SecureRandom();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
