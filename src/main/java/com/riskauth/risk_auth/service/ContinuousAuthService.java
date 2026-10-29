package com.riskauth.risk_auth.service;

import com.riskauth.risk_auth.context.ContextCollector;
import com.riskauth.risk_auth.context.GeoIpService;
import com.riskauth.risk_auth.entity.ActionLog;
import com.riskauth.risk_auth.entity.User;
import com.riskauth.risk_auth.exception.ActionBlockedException;
import com.riskauth.risk_auth.repository.ActionLogRepository;
import com.riskauth.risk_auth.repository.UserRepository;
import com.riskauth.risk_auth.risk.ActionAssessment;
import com.riskauth.risk_auth.risk.Decision;
import com.riskauth.risk_auth.risk.PolicyEngine;
import com.riskauth.risk_auth.risk.RiskFactor;
import com.riskauth.risk_auth.security.JwtService;
import com.riskauth.risk_auth.security.SessionFingerprint;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/** Re-evaluates risk at the moment of a sensitive action, using the session the token was issued for. */
@Service
@RequiredArgsConstructor
public class ContinuousAuthService {

    private final UserRepository userRepository;
    private final ActionLogRepository actionLogRepository;
    private final JwtService jwtService;
    private final GeoIpService geoIpService;
    private final ContextCollector contextCollector;
    private final PolicyEngine policyEngine;
    private final OtpService otpService;

    @Value("${app.risk.action.client-change:40}")  private int clientChangePoints;
    @Value("${app.risk.action.country-change:40}") private int countryChangePoints;
    @Value("${app.risk.action.rapid-actions:20}")  private int rapidPoints;
    @Value("${app.risk.action.rapid-limit:3}")     private int rapidLimit;

    public ActionAssessment guard(HttpServletRequest http, String email, String action,
                                  List<RiskFactor> extraFactors) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user"));

        String ip = contextCollector.extractIp(http);
        String country = geoIpService.getCountry(ip);
        String uaHash = SessionFingerprint.hashUserAgent(http.getHeader("User-Agent"));

        String token = bearer(http);
        String boundUa = token == null ? null : jwtService.extractClaim(token, "ua");
        String boundCountry = token == null ? null : jwtService.extractClaim(token, "ctry");

        List<RiskFactor> factors = new ArrayList<>();
        if (boundUa != null && !boundUa.equals(uaHash)) {
            factors.add(new RiskFactor("SESSION_CLIENT_CHANGED", clientChangePoints,
                    "This session is now being used from a different browser or client"));
        }
        if (boundCountry != null && !boundCountry.equals(country)) {
            factors.add(new RiskFactor("SESSION_COUNTRY_CHANGED", countryChangePoints,
                    "This session is now being used from a different country (" + country + ")"));
        }
        long recent = actionLogRepository.countByUserIdAndCompletedTrueAndCreatedAtAfter(
                user.getId(), LocalDateTime.now().minusSeconds(60));
        if (recent >= rapidLimit) {
            factors.add(new RiskFactor("RAPID_ACTIONS", rapidPoints,
                    recent + " sensitive actions in the last minute"));
        }
        factors.addAll(extraFactors);

        int score = Math.min(100, factors.stream().mapToInt(RiskFactor::points).sum());
        Decision decision = policyEngine.decide(score);

        if (decision == Decision.DENY) {
            logAction(user, action, ip, country, score, "DENY", false, factors);
            throw new ActionBlockedException(HttpStatus.FORBIDDEN,
                    "Action blocked due to suspicious session activity.", "DENY", score, List.of());
        }

        if (decision == Decision.STEP_UP) {
            String code = http.getHeader("X-Action-Code");
            if (code == null || code.isBlank()) {
                logAction(user, action, ip, country, score, "STEP_UP", false, factors);
                otpService.generateAndSend(user, 0L);   // 0 = this OTP belongs to an action, not a login
                throw new ActionBlockedException(HttpStatus.PRECONDITION_REQUIRED,
                        "Additional verification required. A code was sent. Repeat the request with the header X-Action-Code.",
                        "STEP_UP", score, factors);
            }
            otpService.verify(user.getId(), code.trim());   // throws "Invalid OTP" etc. (400)
            logAction(user, action, ip, country, score, "STEP_UP_VERIFIED", true, factors);
            return new ActionAssessment(score, "STEP_UP_VERIFIED", factors);
        }

        logAction(user, action, ip, country, score, "ALLOW", true, factors);
        return new ActionAssessment(score, "ALLOW", factors);
    }

    private String bearer(HttpServletRequest http) {
        String header = http.getHeader("Authorization");
        return (header != null && header.startsWith("Bearer ")) ? header.substring(7) : null;
    }

    private void logAction(User user, String action, String ip, String country, int score,
                           String decision, boolean completed, List<RiskFactor> factors) {
        String summary = factors.stream().map(f -> f.name() + "+" + f.points())
                .collect(Collectors.joining(", "));
        if (summary.length() > 1000) {
            summary = summary.substring(0, 1000);
        }
        actionLogRepository.save(ActionLog.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .action(action)
                .ipAddress(ip)
                .country(country)
                .riskScore(score)
                .decision(decision)
                .completed(completed)
                .factors(summary)
                .createdAt(LocalDateTime.now())
                .build());
    }
}