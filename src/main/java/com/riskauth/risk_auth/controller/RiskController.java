package com.riskauth.risk_auth.controller;

import com.riskauth.risk_auth.context.ContextCollector;
import com.riskauth.risk_auth.context.LoginContext;
import com.riskauth.risk_auth.dto.RiskEvaluationRequest;
import com.riskauth.risk_auth.dto.RiskEvaluationResponse;
import com.riskauth.risk_auth.entity.User;
import com.riskauth.risk_auth.repository.UserRepository;
import com.riskauth.risk_auth.risk.RiskAssessment;
import com.riskauth.risk_auth.risk.RiskAssessmentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/risk")
@RequiredArgsConstructor
public class RiskController {

    private final UserRepository userRepository;
    private final ContextCollector contextCollector;
    private final RiskAssessmentService riskAssessmentService;

    /** Read-only: scores a login context without recording an attempt or touching the baseline. */
    @PostMapping("/evaluate")
    public RiskEvaluationResponse evaluate(@Valid @RequestBody RiskEvaluationRequest req) {
        User user = userRepository.findByEmail(req.email())
                .orElseThrow(() -> new IllegalArgumentException("Unknown user"));

        LoginContext ctx = contextCollector.build(req.email(), req.ip(), req.userAgent(),
                req.screenResolution(), req.timezone(), req.language());

        RiskAssessment a = riskAssessmentService.assess(user.getId(), ctx);
        return new RiskEvaluationResponse(a.risk().score(), a.decision().name(),
                a.risk().factors(), a.signals());
    }
}