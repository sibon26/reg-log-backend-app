package com.auth.backend.service;

import com.auth.backend.dto.*;
import com.auth.backend.entity.OtpRecord;
import com.auth.backend.entity.RevokedToken;
import com.auth.backend.entity.User;
import com.auth.backend.exception.BadRequestException;
import com.auth.backend.exception.ResourceNotFoundException;
import com.auth.backend.exception.UnauthorizedException;
import com.auth.backend.repository.OtpRepository;
import com.auth.backend.repository.RevokedTokenRepository;
import com.auth.backend.repository.UserRepository;
import com.auth.backend.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Date;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RevokedTokenRepository revokedTokenRepository;
    private final OtpRepository otpRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final OtpEmailService otpEmailService;

    // ─────────────────────────────── SIGNUP ───────────────────────────────────

    @Transactional
    public AuthResponse signup(SignupRequest request) {
        // Validate confirm password
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("Passwords do not match");
        }

        // Check email uniqueness
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("Email address is already registered");
        }

        // Check mobile uniqueness
        if (userRepository.existsByMobileNumber(request.getMobileNumber())) {
            throw new BadRequestException("Mobile number is already registered");
        }

        // Build and save user
        User user = User.builder()
                .fullName(request.getFullName())
                .email(request.getEmail())
                .mobileNumber(request.getMobileNumber())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        user = userRepository.save(user);
        log.info("New user registered: {}", user.getEmail());

        // Generate token
        String token = jwtTokenProvider.generateToken(user.getEmail());

        return AuthResponse.builder()
                .success(true)
                .message("Registration successful! Welcome aboard.")
                .token(token)
                .user(mapToUserDto(user))
                .build();
    }

    // ─────────────────────────────── LOGIN ────────────────────────────────────

    public AuthResponse login(LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (BadCredentialsException e) {
            throw new UnauthorizedException("Invalid email or password");
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UnauthorizedException("Invalid email or password"));

        String token = jwtTokenProvider.generateToken(user.getEmail());
        log.info("User logged in: {}", user.getEmail());

        return AuthResponse.builder()
                .success(true)
                .message("Login successful! Welcome back, " + user.getFullName() + ".")
                .token(token)
                .user(mapToUserDto(user))
                .build();
    }

    // ─────────────────────────────── LOGOUT ───────────────────────────────────

    @Transactional
    public void logout(String token) {
        if (token == null || !jwtTokenProvider.validateToken(token)) {
            throw new BadRequestException("Invalid token");
        }

        if (revokedTokenRepository.existsByToken(token)) {
            throw new BadRequestException("Token is already revoked");
        }

        Date expiresAt = jwtTokenProvider.getExpirationFromToken(token);

        RevokedToken revokedToken = RevokedToken.builder()
                .token(token)
                .expiresAt(expiresAt.toInstant()
                        .atZone(java.time.ZoneId.systemDefault())
                        .toLocalDateTime())
                .build();

        revokedTokenRepository.save(revokedToken);
        log.info("Token revoked successfully");
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
        // Verify user exists
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No account found with that email address"));

        // Invalidate previous OTPs
        otpRepository.invalidateAllOtpForEmail(request.getEmail());

        // Generate 6-digit OTP
        String otp = generateOtp();

        // Save OTP (expires in 10 minutes)
        OtpRecord otpRecord = OtpRecord.builder()
                .email(request.getEmail())
                .otp(otp)
                .used(false)
                .expiresAt(LocalDateTime.now().plusMinutes(10))
                .build();

        otpRepository.save(otpRecord);

        // Send OTP via mock email service
        otpEmailService.sendOtp(request.getEmail(), user.getFullName(), otp);

        log.info("OTP generated for email: {}", request.getEmail());

        return ApiResponse.success(
                "OTP sent to your email address. Please check your inbox. (Check console for OTP in development mode)");
    }

    // ─────────────────────────────── VERIFY OTP ───────────────────────────────

    public ApiResponse verifyOtp(VerifyOtpRequest request) {
        OtpRecord otpRecord = otpRepository
                .findLatestValidOtp(request.getEmail(), LocalDateTime.now())
                .orElseThrow(() -> new BadRequestException(
                        "Invalid or expired OTP. Please request a new one."));

        if (!otpRecord.getOtp().equals(request.getOtp())) {
            throw new BadRequestException("Invalid OTP. Please try again.");
        }

        return ApiResponse.success("OTP verified successfully. You can now reset your password.");
    }

    // ──────────────────────────── RESET PASSWORD ──────────────────────────────

    @Transactional
    public ApiResponse resetPassword(ResetPasswordRequest request) {
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("Passwords do not match");
        }

        // Verify OTP again
        OtpRecord otpRecord = otpRepository
                .findLatestValidOtp(request.getEmail(), LocalDateTime.now())
                .orElseThrow(() -> new BadRequestException(
                        "Invalid or expired OTP. Please request a new one."));

        if (!otpRecord.getOtp().equals(request.getOtp())) {
            throw new BadRequestException("Invalid OTP. Please try again.");
        }

        // Update password
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Invalidate OTP
        otpRepository.invalidateAllOtpForEmail(request.getEmail());

        log.info("Password reset successfully for: {}", request.getEmail());

        return ApiResponse.success("Password reset successfully. Please login with your new password.");
    }

    // ─────────────────────────────── HELPERS ──────────────────────────────────

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
}
