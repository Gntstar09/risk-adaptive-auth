package com.riskauth.risk_auth.dto;

import com.riskauth.risk_auth.context.ContextSignals;
import com.riskauth.risk_auth.risk.RiskFactor;

import java.util.List;

public record RiskEvaluationResponse(
        int score,
        String decision,
        List<RiskFactor> factors,
        ContextSignals signals
) {}