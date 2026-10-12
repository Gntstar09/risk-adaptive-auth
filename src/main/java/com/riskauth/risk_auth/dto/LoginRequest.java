package com.riskauth.risk_auth.dto;



import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank String email,
        @NotBlank String password,
        String screenResolution,   // e.g. "1920x1080"
        String timezone,           // e.g. "Asia/Kolkata"
        String language            // e.g. "en-IN"
) {}
