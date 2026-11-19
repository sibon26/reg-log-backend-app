package com.auth.backend.controller;

import com.auth.backend.dto.ApiResponse;
import com.auth.backend.dto.UserDto;
import com.auth.backend.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * User profile endpoints – all require authentication.
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final AuthService authService;

    // GET /api/users/me – returns the authenticated user's profile
    @GetMapping("/me")
    public ResponseEntity<ApiResponse> getMe(
            @AuthenticationPrincipal UserDetails userDetails) {
        UserDto user = authService.getMe(userDetails.getUsername());
        return ResponseEntity.ok(ApiResponse.success("User details retrieved", user));
    }
}
