package com.auth.backend.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

/**
 * Utility for creating, reading, and clearing the JWT HttpOnly cookie.
 * Never expose this cookie value to JavaScript – SameSite + HttpOnly enforce this.
 */
@Component
public class CookieUtil {

    @Value("${jwt.cookie.name:access-token}")
    private String cookieName;

    @Value("${jwt.cookie.secure:false}")
    private boolean cookieSecure;

    @Value("${jwt.cookie.same-site:Lax}")
    private String cookieSameSite;

    @Value("${jwt.expiration:1800000}")
    private long jwtExpirationMs;

    /**
     * Set an HttpOnly JWT cookie on the response.
     */
    public void setJwtCookie(HttpServletResponse response, String token) {
        int maxAgeSeconds = (int) (jwtExpirationMs / 1000);

        ResponseCookie cookie = ResponseCookie.from(cookieName, token)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite(cookieSameSite)
                .path("/")
                .maxAge(maxAgeSeconds)
                .build();

        response.addHeader("Set-Cookie", cookie.toString());
    }

    /**
     * Clear the JWT cookie (sets Max-Age=0).
     */
    public void clearJwtCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(cookieName, "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite(cookieSameSite)
                .path("/")
                .maxAge(0)
                .build();

        response.addHeader("Set-Cookie", cookie.toString());
    }

    /**
     * Extract the JWT value from the incoming request cookie.
     * Returns null if not present.
     */
    public String getJwtFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if (cookieName.equals(cookie.getName())) {
                String value = cookie.getValue();
                return (value != null && !value.isBlank()) ? value : null;
            }
        }
        return null;
    }

    public String getCookieName() {
        return cookieName;
    }
}
