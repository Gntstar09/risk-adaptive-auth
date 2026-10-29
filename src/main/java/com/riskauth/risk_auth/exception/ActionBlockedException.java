package com.riskauth.risk_auth.exception;

import com.riskauth.risk_auth.risk.RiskFactor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.List;

@Getter
public class ActionBlockedException extends RuntimeException {

    private final HttpStatus status;
    private final String decision;
    private final int score;
    private final List<RiskFactor> factors;

    public ActionBlockedException(HttpStatus status, String message, String decision,
                                  int score, List<RiskFactor> factors) {
        super(message);
        this.status = status;
        this.decision = decision;
        this.score = score;
        this.factors = factors;
    }
}