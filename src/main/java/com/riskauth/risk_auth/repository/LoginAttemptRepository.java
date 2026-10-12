package com.riskauth.risk_auth.repository;



import com.riskauth.risk_auth.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {
}
