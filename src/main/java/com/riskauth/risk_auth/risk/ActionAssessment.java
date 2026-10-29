package com.riskauth.risk_auth.risk;

import java.util.List;

public record ActionAssessment(int score, String decision, List<RiskFactor> factors) {}