package com.riskauth.risk_auth.risk;

import com.riskauth.risk_auth.context.ContextSignals;
import com.riskauth.risk_auth.context.LoginContext;
import com.riskauth.risk_auth.service.ProfileService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/** Single place where signals become a score and a decision. Has no side effects. */
@Service
@RequiredArgsConstructor
public class RiskAssessmentService {

    private final ProfileService profileService;
    private final RiskEngine riskEngine;
    private final PolicyEngine policyEngine;

    public RiskAssessment assess(Long userId, LoginContext ctx) {
        ContextSignals signals = profileService.evaluate(userId, ctx);
        RiskResult risk = riskEngine.evaluate(signals);
        Decision decision = policyEngine.decide(risk.score());
        return new RiskAssessment(signals, risk, decision);
    }
}