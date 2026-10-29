package com.riskauth.risk_auth.repository;

import com.riskauth.risk_auth.entity.ActionLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface ActionLogRepository extends JpaRepository<ActionLog, Long> {
    long countByUserIdAndCompletedTrueAndCreatedAtAfter(Long userId, LocalDateTime since);
    List<ActionLog> findTop50ByOrderByIdDesc();
}