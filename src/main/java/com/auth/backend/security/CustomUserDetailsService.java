package com.auth.backend.security;

import com.auth.backend.entity.User;
import com.auth.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

/**
 * Loads a user by email OR mobile number.
 * The "username" field here is used as a login identifier that can be
 * either an email address or a 10-digit mobile number.
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String identifier) throws UsernameNotFoundException {
        // Detect whether the identifier looks like a mobile number (digits only)
        User user;
        if (identifier != null && identifier.matches("^[0-9]{10}$")) {
            user = userRepository.findByMobileNumber(identifier)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        } else {
            user = userRepository.findByEmail(identifier)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        }

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),   // principal is always the email
                user.getPassword(),
                new ArrayList<>()
        );
    }
}
