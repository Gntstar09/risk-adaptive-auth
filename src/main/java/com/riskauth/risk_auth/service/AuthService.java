package com.riskauth.risk_auth.service;

import com.riskauth.risk_auth.context.ContextCollector;
import com.riskauth.risk_auth.context.ContextSignals;
import com.riskauth.risk_auth.context.LoginContext;
import com.riskauth.risk_auth.dto.AuthResponse;
import com.riskauth.risk_auth.dto.LoginRequest;
import com.riskauth.risk_auth.dto.RegisterRequest;
import com.riskauth.risk_auth.dto.VerifyOtpRequest;
import com.riskauth.risk_auth.entity.LoginAttempt;
import com.riskauth.risk_auth.entity.RiskLog;
import com.riskauth.risk_auth.entity.Role;
import com.riskauth.risk_auth.entity.User;
import com.riskauth.risk_auth.exception.LoginBlockedException;
import com.riskauth.risk_auth.repository.LoginAttemptRepository;
import com.riskauth.risk_auth.repository.RiskLogRepository;
import com.riskauth.risk_auth.repository.UserRepository;
import com.riskauth.risk_auth.risk.Decision;
import com.riskauth.risk_auth.risk.PolicyEngine;
import com.riskauth.risk_auth.risk.RiskEngine;
import com.riskauth.risk_auth.risk.RiskAssessment;
import com.riskauth.risk_auth.risk.RiskAssessmentService;
import com.riskauth.risk_auth.risk.RiskFactor;
import com.riskauth.risk_auth.risk.RiskResult;
import com.riskauth.risk_auth.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final RiskLogRepository riskLogRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final ContextCollector contextCollector;
    private final ProfileService profileService;
    private final RiskAssessmentService riskAssessmentService;
    private final OtpService otpService;

    @Value("${app.risk.brute-force-limit:5}")
    private long bruteForceLimit;

    public AuthResponse register(RegisterRequest req) {
        if (userRepository.existsByEmail(req.email())) {
            throw new IllegalArgumentException("Email already registered");
        }
        Role role = "ADMIN".equalsIgnoreCase(req.role()) ? Role.ADMIN : Role.USER;

        User user = User.builder()
                .email(req.email())
                .passwordHash(passwordEncoder.encode(req.password()))
                .role(role)
                .build();
        userRepository.save(user);

        return new AuthResponse(null, user.getEmail(), role.name(),
                "Registration successful", null, null, null, null);
    }

    public AuthResponse login(LoginRequest req, HttpServletRequest http) {
        // 1. Collect context
        LoginContext ctx = contextCollector.collect(req, http);
        Optional<User> userOpt = userRepository.findByEmail(req.email());
        Long userId = userOpt.map(User::getId).orElse(null);

        // 2. Hard rule: too many recent failures -> refuse before checking the password
        if (ctx.failedByEmail() >= bruteForceLimit) {
            LoginAttempt blocked = logAttempt(userId, req.email(), ctx, false, 100, Decision.DENY);
            saveFactors(blocked.getId(), List.of(new RiskFactor("BRUTE_FORCE_LOCKOUT", 100,
                    ctx.failedByEmail() + " failed attempts in the recent window")));
            throw new LoginBlockedException("Too many failed attempts. Try again later.",
                    HttpStatus.TOO_MANY_REQUESTS);
        }

        // 3. Verify credentials (decision stays null on failure = "wrong password")
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.email(), req.password()));
        } catch (AuthenticationException ex) {
            logAttempt(userId, req.email(), ctx, false, null, null);
            throw new BadCredentialsException("Invalid email or password");
        }
        User user = userOpt.get();

        // 4. Signals -> risk score -> decision
        RiskAssessment assessment = riskAssessmentService.assess(user.getId(), ctx);
        ContextSignals signals = assessment.signals();
        RiskResult risk = assessment.risk();
        Decision decision = assessment.decision();
        // 5. Record the attempt. success=true ONLY if the login is complete (ALLOW).
        boolean completed = decision == Decision.ALLOW;
        LoginAttempt attempt = logAttempt(user.getId(), user.getEmail(), ctx,
                completed, risk.score(), decision);
        saveFactors(attempt.getId(), risk.factors());

        // 6. Apply the policy
        if (decision == Decision.DENY) {
            throw new LoginBlockedException(
                    "Login blocked due to suspicious activity.", HttpStatus.FORBIDDEN);
        }

        if (decision == Decision.STEP_UP) {
            otpService.generateAndSend(user, attempt.getId());
            return new AuthResponse(null, user.getEmail(), user.getRole().name(),
                    "Additional verification required. An OTP has been sent.",
                    signals, risk.score(), decision.name(), risk.factors());
        }

        profileService.updateProfile(user.getId(), ctx.deviceHash(), ctx.time());
        String token = jwtService.generateToken(user.getEmail(), user.getRole().name());
        return new AuthResponse(token, user.getEmail(), user.getRole().name(),
                "Login successful", signals, risk.score(), decision.name(), risk.factors());
    }

    public AuthResponse verifyOtp(VerifyOtpRequest req) {
        User user = userRepository.findByEmail(req.email())
                .orElseThrow(() -> new IllegalArgumentException("Invalid OTP"));

        Long attemptId = otpService.verify(user.getId(), req.code());

        // Complete the pending login: now it counts toward the user's baseline
        LoginAttempt attempt = loginAttemptRepository.findById(attemptId)
                .orElseThrow(() -> new IllegalStateException("Pending attempt not found"));
        attempt.setSuccess(true);
        loginAttemptRepository.save(attempt);
        profileService.updateProfile(user.getId(), attempt.getDeviceHash(), attempt.getAttemptTime());

        String token = jwtService.generateToken(user.getEmail(), user.getRole().name());
        return new AuthResponse(token, user.getEmail(), user.getRole().name(),
                "Login successful after OTP verification", null,
                attempt.getRiskScore(), "STEP_UP_VERIFIED", null);
    }

    private LoginAttempt logAttempt(Long userId, String email, LoginContext ctx,
                                    boolean success, Integer riskScore, Decision decision) {
        return loginAttemptRepository.save(LoginAttempt.builder()
                .userId(userId)
                .email(email)
                .ipAddress(ctx.ip())
                .userAgent(ctx.userAgent())
                .deviceHash(ctx.deviceHash())
                .country(ctx.country())
                .success(success)
                .attemptTime(ctx.time())
                .riskScore(riskScore)
                .decision(decision == null ? null : decision.name())
                .build());
    }

    private void saveFactors(Long attemptId, List<RiskFactor> factors) {
        riskLogRepository.saveAll(factors.stream()
                .map(f -> RiskLog.builder()
                        .attemptId(attemptId)
                        .factorName(f.name())
                        .pointsAdded(f.points())
                        .reason(f.reason())
                        .build())
                .toList());
    }
}