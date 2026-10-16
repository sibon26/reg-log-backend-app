package com.auth.backend.repository;

import com.auth.backend.entity.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Repository
public interface RevokedTokenRepository extends JpaRepository<RevokedToken, Long> {

    boolean existsByToken(String token);

    @Modifying
    @Transactional
    @Query("DELETE FROM RevokedToken r WHERE r.expiresAt < :now")
    void deleteExpiredTokens(LocalDateTime now);
}
