package com.auth.backend.repository;

import com.auth.backend.entity.OtpRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface OtpRepository extends JpaRepository<OtpRecord, Long> {

    @Query("SELECT o FROM OtpRecord o WHERE o.email = :email AND o.used = false AND o.expiresAt > :now ORDER BY o.createdAt DESC")
    Optional<OtpRecord> findLatestValidOtp(String email, LocalDateTime now);

    @Modifying
    @Transactional
    @Query("UPDATE OtpRecord o SET o.used = true WHERE o.email = :email")
    void invalidateAllOtpForEmail(String email);
}
