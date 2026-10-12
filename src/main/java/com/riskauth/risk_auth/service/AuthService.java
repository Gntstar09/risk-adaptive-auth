
package com.riskauth.risk_auth.service;

import com.riskauth.risk_auth.context.ContextCollector;
import com.riskauth.risk_auth.context.ContextSignals;
import com.riskauth.risk_auth.context.LoginContext;
import com.riskauth.risk_auth.dto.AuthResponse;
import com.riskauth.risk_auth.dto.LoginRequest;
import com.riskauth.risk_auth.dto.RegisterRequest;
import com.riskauth.risk_auth.entity.LoginAttempt;
import com.riskauth.risk_auth.entity.Role;
import com.riskauth.risk_auth.entity.User;
import com.riskauth.risk_auth.repository.LoginAttemptRepository;
import com.riskauth.risk_auth.repository.UserRepository;
import com.riskauth.risk_auth.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final ContextCollector contextCollector;
    private final ProfileService profileService;

    public AuthResponse register(RegisterRequest req) {
        if (userRepository.existsByEmail(req.email())) {
            throw new IllegalArgumentException("Email already registered");
        }

        Role role = "ADMIN".equalsIgnoreCase(req.role())
                ? Role.ADMIN
                : Role.USER;

        User user = User.builder()
                .email(req.email())
                .passwordHash(passwordEncoder.encode(req.password()))
                .role(role)
                .build();

        userRepository.save(user);

        return new AuthResponse(
                null,
                user.getEmail(),
                role.name(),
                "Registration successful",
                null
        );
    }

    public AuthResponse login(LoginRequest req, HttpServletRequest http) {
        // 1. Collect login context
        LoginContext ctx = contextCollector.collect(req, http);
        Optional<User> userOpt = userRepository.findByEmail(req.email());

        // 2. Verify credentials
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            req.email(),
                            req.password()
                    )
            );
        } catch (AuthenticationException ex) {
            logAttempt(
                    userOpt.map(User::getId).orElse(null),
                    req.email(),
                    ctx,
                    false
            );

            throw new BadCredentialsException("Invalid email or password");
        }

        User user = userOpt.orElseThrow(
                () -> new BadCredentialsException("Invalid email or password")
        );

        // 3. Evaluate risk before recording the successful attempt
        ContextSignals signals = profileService.evaluate(user.getId(), ctx);

        // 4. Record the attempt and update the user's profile
        logAttempt(user.getId(), user.getEmail(), ctx, true);
        profileService.updateProfile(user.getId(), ctx);

        // 5. Generate JWT
        String token = jwtService.generateToken(
                user.getEmail(),
                user.getRole().name()
        );

        return new AuthResponse(
                token,
                user.getEmail(),
                user.getRole().name(),
                "Login successful",
                signals
        );
    }

    private void logAttempt(
            Long userId,
            String email,
            LoginContext ctx,
            boolean success
    ) {
        loginAttemptRepository.save(
                LoginAttempt.builder()
                        .userId(userId)
                        .email(email)
                        .ipAddress(ctx.ip())
                        .userAgent(ctx.userAgent())
                        .deviceHash(ctx.deviceHash())
                        .country(ctx.country())
                        .success(success)
                        .attemptTime(ctx.time())
                        .build()
        );
    }
}
