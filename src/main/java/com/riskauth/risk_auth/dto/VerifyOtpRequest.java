package com.riskauth.risk_auth.dto;

import jakarta.validation.constraints.NotBlank;

public record VerifyOtpRequest(
        @NotBlank String email,
        @NotBlank String code
) {}