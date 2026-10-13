package com.riskauth.risk_auth.controller;

import com.riskauth.risk_auth.entity.LoginAttempt;
import com.riskauth.risk_auth.entity.RiskLog;
import com.riskauth.risk_auth.repository.LoginAttemptRepository;
import com.riskauth.risk_auth.repository.RiskLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final LoginAttemptRepository loginAttemptRepository;
    private final RiskLogRepository riskLogRepository;

    @GetMapping("/attempts")
    public List<LoginAttempt> recentAttempts() {
        return loginAttemptRepository.findTop50ByOrderByIdDesc();
    }

    @GetMapping("/attempts/{id}/risk-factors")
    public List<RiskLog> riskFactors(@PathVariable Long id) {
        return riskLogRepository.findByAttemptId(id);
    }
}