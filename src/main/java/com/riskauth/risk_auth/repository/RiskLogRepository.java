package com.riskauth.risk_auth.repository;

import com.riskauth.risk_auth.entity.RiskLog;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface RiskLogRepository extends JpaRepository<RiskLog, Long> {
    List<RiskLog> findByAttemptId(Long attemptId);
}