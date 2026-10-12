package com.riskauth.risk_auth.controller;



import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TestController {

    @GetMapping("/api/me")
    public Map<String, Object> me(Authentication auth) {
        return Map.of("email", auth.getName(), "authorities", auth.getAuthorities().toString());
    }

    @GetMapping("/admin/stats")
    public Map<String, String> adminStats() {
        return Map.of("message", "Welcome Admin - this is a protected admin area");
    }
}
