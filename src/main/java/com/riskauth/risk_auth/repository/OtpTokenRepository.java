package com.riskauth.risk_auth.repository;

import com.riskauth.risk_auth.entity.OtpToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface OtpTokenRepository extends JpaRepository<OtpToken, Long> {
    Optional<OtpToken> findFirstByUserIdAndUsedFalseOrderByIdDesc(Long userId);
    List<OtpToken> findByUserIdAndUsedFalse(Long userId);
}