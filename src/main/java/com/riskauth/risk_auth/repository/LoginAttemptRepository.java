
package com.riskauth.risk_auth.repository;

import com.riskauth.risk_auth.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    long countByEmailAndSuccessFalseAndAttemptTimeAfter(
            String email, LocalDateTime since);

    long countByIpAddressAndSuccessFalseAndAttemptTimeAfter(
            String ipAddress, LocalDateTime since);

    boolean existsByUserIdAndSuccessTrue(Long userId);

    boolean existsByUserIdAndCountryAndSuccessTrue(
            Long userId, String country);

    List<LoginAttempt> findTop50ByUserIdAndSuccessTrueOrderByAttemptTimeDesc(
            Long userId);
}
