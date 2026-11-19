package com.auth.backend.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "auth_sessions", indexes = {
        @Index(name = "idx_session_jti",     columnList = "token_id", unique = true),
        @Index(name = "idx_session_user_id", columnList = "user_id"),
})
public class AuthSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "token_id", nullable = false, unique = true, length = 64)
    private String tokenId;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "revoked", nullable = false)
    private boolean revoked = false;

    public AuthSession() {}

    // Builder pattern
    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private User user;
        private String tokenId;
        private LocalDateTime expiresAt;
        private boolean revoked = false;

        public Builder user(User user) { this.user = user; return this; }
        public Builder tokenId(String tokenId) { this.tokenId = tokenId; return this; }
        public Builder expiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; return this; }
        public Builder revoked(boolean revoked) { this.revoked = revoked; return this; }

        public AuthSession build() {
            AuthSession s = new AuthSession();
            s.user = this.user;
            s.tokenId = this.tokenId;
            s.expiresAt = this.expiresAt;
            s.revoked = this.revoked;
            return s;
        }
    }

    // Getters
    public Long getId() { return id; }
    public User getUser() { return user; }
    public String getTokenId() { return tokenId; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }

    // Setters
    public void setId(Long id) { this.id = id; }
    public void setUser(User user) { this.user = user; }
    public void setTokenId(String tokenId) { this.tokenId = tokenId; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
}
