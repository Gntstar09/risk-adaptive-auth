package com.riskauth.risk_auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.riskauth.risk_auth.context.ContextSignals;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthResponse(
        String token,
        String email,
        String role,
        String message,
        ContextSignals signals
) {}