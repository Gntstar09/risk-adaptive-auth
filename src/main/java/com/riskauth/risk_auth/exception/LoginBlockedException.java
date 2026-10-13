package com.riskauth.risk_auth.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class LoginBlockedException extends RuntimeException {

    private final HttpStatus status;

    public LoginBlockedException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }
}