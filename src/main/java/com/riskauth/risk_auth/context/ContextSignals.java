package com.riskauth.risk_auth.context;
import java.time.LocalDateTime;
public record ContextSignals(
        boolean firstLogin,
        boolean newDevice,
        boolean newCountry,
        boolean unusualHour,
        long failedAttemptsByEmail,
        long failedAttemptsByIp,
        String country,
        String deviceHash,
        LocalDateTime time
) {}