package com.riskauth.risk_auth.controller;



import com.riskauth.risk_auth.dto.AuthResponse;
import com.riskauth.risk_auth.dto.LoginRequest;
import com.riskauth.risk_auth.dto.RegisterRequest;
import com.riskauth.risk_auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest req) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(req));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest req,
                                              HttpServletRequest http) {
        return ResponseEntity.ok(authService.login(req, http));
    }
}
