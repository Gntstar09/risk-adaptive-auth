package com.riskauth.risk_auth.risk;

import com.riskauth.risk_auth.context.ContextSignals;

public record RiskAssessment(ContextSignals signals, RiskResult risk, Decision decision) {}