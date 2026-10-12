package com.riskauth.risk_auth.context;

import java.time.LocalDateTime;

public record LoginContext(
        String ip,
        String userAgent,
        String deviceHash,
        String country,
        LocalDateTime time,
        long failedByEmail,   // failed attempts for this email in the window
        long failedByIp       // failed attempts from this IP in the window
) {}