package com.riskauth.risk_auth.controller;

import com.riskauth.risk_auth.dto.TransferRequest;
import com.riskauth.risk_auth.risk.ActionAssessment;
import com.riskauth.risk_auth.risk.RiskFactor;
import com.riskauth.risk_auth.service.ContinuousAuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class TransferController {

    private final ContinuousAuthService continuousAuthService;

    @Value("${app.risk.action.high-value:25}")
    private int highValuePoints;

    @Value("${app.risk.action.high-value-threshold:50000}")
    private BigDecimal highValueThreshold;

    /** Demo of a sensitive action: no money actually moves. */
    @PostMapping("/api/transfer")
    public Map<String, Object> transfer(@Valid @RequestBody TransferRequest req,
                                        HttpServletRequest http, Authentication auth) {
        List<RiskFactor> extra = new ArrayList<>();
        if (req.amount().compareTo(highValueThreshold) > 0) {
            extra.add(new RiskFactor("HIGH_VALUE_ACTION", highValuePoints,
                    "Transfer amount is above " + highValueThreshold));
        }

        ActionAssessment a = continuousAuthService.guard(http, auth.getName(), "TRANSFER", extra);

        return Map.of(
                "status", "Transfer accepted (demo: no money moves)",
                "toAccount", req.toAccount(),
                "amount", req.amount(),
                "riskScore", a.score(),
                "decision", a.decision(),
                "riskFactors", a.factors());
    }
}