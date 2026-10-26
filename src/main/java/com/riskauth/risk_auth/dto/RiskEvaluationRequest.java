package com.riskauth.risk_auth.dto;

import jakarta.validation.constraints.NotBlank;

public record RiskEvaluationRequest(
        @NotBlank String email,
        @NotBlank String ip,
        String userAgent,
        String screenResolution,
        String timezone,
        String language
) {}