package com.riskauth.risk_auth.dto;



public record AuthResponse(String token, String email, String role, String message) {}