package com.auth.backend.repository;

import com.auth.backend.entity.AuthSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface AuthSessionRepository extends JpaRepository<AuthSession, Long> {

    Optional<AuthSession> findByTokenId(String tokenId);

    boolean existsByTokenIdAndRevokedFalse(String tokenId);

    /** Revoke all active sessions for a user (e.g. after password reset). */
    @Modifying
    @Transactional
    @Query("UPDATE AuthSession s SET s.revoked = true WHERE s.user.id = :userId AND s.revoked = false")
    int revokeAllByUserId(@Param("userId") Long userId);

    /** Revoke a single session by its token ID. */
    @Modifying
    @Transactional
    @Query("UPDATE AuthSession s SET s.revoked = true WHERE s.tokenId = :tokenId")
    int revokeByTokenId(@Param("tokenId") String tokenId);

    /** Cleanup expired sessions (maintenance query). */
    @Modifying
    @Transactional
    @Query("DELETE FROM AuthSession s WHERE s.expiresAt < :now")
    int deleteExpiredSessions(@Param("now") LocalDateTime now);
}
