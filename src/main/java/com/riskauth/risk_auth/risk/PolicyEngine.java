package com.riskauth.risk_auth.risk;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class PolicyEngine {

    @Value("${app.risk.threshold.low-max:30}")
    private int lowMax;

    @Value("${app.risk.threshold.medium-max:70}")
    private int mediumMax;

    public Decision decide(int score) {
        if (score <= lowMax) return Decision.ALLOW;
        if (score <= mediumMax) return Decision.STEP_UP;
        return Decision.DENY;
    }
}