package com.auth.backend.repository;

import com.auth.backend.entity.OtpRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface OtpRepository extends JpaRepository<OtpRecord, Long> {

    /** Find the most recent non-expired, non-used OTP for an email. */
    @Query("SELECT o FROM OtpRecord o WHERE o.email = :email AND o.used = false AND o.expiresAt > :now ORDER BY o.createdAt DESC")
    Optional<OtpRecord> findLatestValidOtp(@Param("email") String email, @Param("now") LocalDateTime now);

    /** Find by reset token hash (for the reset-password step). */
    @Query("SELECT o FROM OtpRecord o WHERE o.resetTokenHash = :hash AND o.used = false AND o.resetExpiresAt > :now")
    Optional<OtpRecord> findByResetTokenHash(@Param("hash") String hash, @Param("now") LocalDateTime now);

    /** Mark all OTP records for an email as used. */
    @Modifying
    @Transactional
    @Query("UPDATE OtpRecord o SET o.used = true WHERE o.email = :email")
    void invalidateAllOtpForEmail(@Param("email") String email);
}
