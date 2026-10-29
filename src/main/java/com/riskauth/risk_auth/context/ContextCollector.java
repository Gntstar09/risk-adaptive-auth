package com.riskauth.risk_auth.context;

import com.riskauth.risk_auth.dto.LoginRequest;
import com.riskauth.risk_auth.repository.LoginAttemptRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;

@Component
@RequiredArgsConstructor
public class ContextCollector {

    private final GeoIpService geoIpService;
    private final LoginAttemptRepository loginAttemptRepository;

    @Value("${app.risk.velocity-window-minutes:10}")
    private long windowMinutes;

    /** Used by the login flow: pulls values out of the HTTP request. */
    public LoginContext collect(LoginRequest req, HttpServletRequest http) {
        String language = (req.language() != null && !req.language().isBlank())
                ? req.language() : nz(http.getHeader("Accept-Language"));
        return build(req.email(), extractIp(http), http.getHeader("User-Agent"),
                req.screenResolution(), req.timezone(), language);
    }

    /** Used by both the login flow and POST /risk/evaluate. */
    public LoginContext build(String email, String ip, String userAgentRaw,
                              String screenResolution, String timezone, String language) {
        String userAgent = nz(userAgentRaw);
        if (userAgent.length() > 500) {
            userAgent = userAgent.substring(0, 500);
        }

        String deviceHash = sha256(userAgent + "|" + nz(language) + "|"
                + nz(screenResolution) + "|" + nz(timezone));

        String country = geoIpService.getCountry(ip);

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime since = now.minusMinutes(windowMinutes);
        long failedByEmail = loginAttemptRepository
                .countByEmailAndSuccessFalseAndDecisionIsNullAndAttemptTimeAfter(email, since);
        long failedByIp = loginAttemptRepository
                .countByIpAddressAndSuccessFalseAndDecisionIsNullAndAttemptTimeAfter(ip, since);

        return new LoginContext(ip, userAgent, deviceHash, country, now, failedByEmail, failedByIp);
    }

    public String extractIp(HttpServletRequest request) {
        // NOTE: X-Forwarded-For can be spoofed. Fine for a demo (lets us simulate
        // other countries in Postman); in production trust it only behind your own proxy.
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String sha256(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String nz(String s) {
        return s == null ? "" : s;
    }
}