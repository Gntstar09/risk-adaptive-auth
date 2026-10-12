
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

    public LoginContext collect(LoginRequest req, HttpServletRequest http) {
        String ip = extractIp(http);

        String userAgent = nz(http.getHeader("User-Agent"));
        if (userAgent.length() > 500) {
            userAgent = userAgent.substring(0, 500);
        }

        String language = (req.language() != null && !req.language().isBlank())
                ? req.language()
                : nz(http.getHeader("Accept-Language"));

        String deviceHash = sha256(
                userAgent + "|" + language + "|"
                        + nz(req.screenResolution()) + "|"
                        + nz(req.timezone())
        );

        String country = geoIpService.getCountry(ip);

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime since = now.minusMinutes(windowMinutes);

        long failedByEmail = loginAttemptRepository
                .countByEmailAndSuccessFalseAndAttemptTimeAfter(req.email(), since);

        long failedByIp = loginAttemptRepository
                .countByIpAddressAndSuccessFalseAndAttemptTimeAfter(ip, since);

        return new LoginContext(
                ip, userAgent, deviceHash, country,
                now, failedByEmail, failedByIp
        );
    }

    private String extractIp(HttpServletRequest request) {
        // Trust X-Forwarded-For only when configured behind a trusted proxy.
        String forwarded = request.getHeader("X-Forwarded-For");

        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }

    private String sha256(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(
                    md.digest(raw.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String nz(String s) {
        return s == null ? "" : s;
    }
}
