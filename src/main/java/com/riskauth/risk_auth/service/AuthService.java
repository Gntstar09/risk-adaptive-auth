package com.riskauth.risk_auth.service;



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

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

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

        return new AuthResponse(null, user.getEmail(), role.name(), "Registration successful");
    }

    public AuthResponse login(LoginRequest req, HttpServletRequest http) {
        String ip = extractIp(http);
        String userAgent = http.getHeader("User-Agent");
        Optional<User> userOpt = userRepository.findByEmail(req.email());

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.email(), req.password()));
        } catch (AuthenticationException ex) {
            logAttempt(userOpt.map(User::getId).orElse(null), req.email(), ip, userAgent, false);
            throw new BadCredentialsException("Invalid email or password");
        }

        User user = userOpt.get();
        logAttempt(user.getId(), user.getEmail(), ip, userAgent, true);

        String token = jwtService.generateToken(user.getEmail(), user.getRole().name());
        return new AuthResponse(token, user.getEmail(), user.getRole().name(), "Login successful");
    }

    private void logAttempt(Long userId, String email, String ip, String userAgent, boolean success) {
        loginAttemptRepository.save(LoginAttempt.builder()
                .userId(userId)
                .email(email)
                .ipAddress(ip)
                .userAgent(userAgent)
                .success(success)
                .attemptTime(LocalDateTime.now())
                .build());
    }

    private String extractIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
