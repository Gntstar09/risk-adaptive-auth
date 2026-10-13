package com.riskauth.risk_auth.risk;

import java.util.List;

public record RiskResult(int score, List<RiskFactor> factors) {}