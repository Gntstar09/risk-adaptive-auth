package com.riskauth.risk_auth.controller;

import com.riskauth.risk_auth.dto.DashboardResponse;
import com.riskauth.risk_auth.entity.ActionLog;
import com.riskauth.risk_auth.entity.LoginAttempt;
import com.riskauth.risk_auth.entity.RiskLog;
import com.riskauth.risk_auth.repository.ActionLogRepository;
import com.riskauth.risk_auth.repository.LoginAttemptRepository;
import com.riskauth.risk_auth.repository.RiskLogRepository;
import com.riskauth.risk_auth.service.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final LoginAttemptRepository loginAttemptRepository;
    private final RiskLogRepository riskLogRepository;
    private final ActionLogRepository actionLogRepository;
    private final DashboardService dashboardService;

    @GetMapping("/attempts")
    public List<LoginAttempt> recentAttempts() {
        return loginAttemptRepository.findTop50ByOrderByIdDesc();
    }

    @GetMapping("/attempts/{id}/risk-factors")
    public List<RiskLog> riskFactors(@PathVariable Long id) {
        return riskLogRepository.findByAttemptId(id);
    }

    @GetMapping("/actions")
    public List<ActionLog> recentActions() {
        return actionLogRepository.findTop50ByOrderByIdDesc();
    }

    @GetMapping("/dashboard")
    public DashboardResponse dashboard(@RequestParam(defaultValue = "7") int days) {
        return dashboardService.build(days);
    }
}