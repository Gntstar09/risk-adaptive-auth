package com.riskauth.risk_auth.risk;

import com.riskauth.risk_auth.context.ContextSignals;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class RuleBasedRiskEngine implements RiskEngine {

    @Value("${app.risk.weights.new-device:35}")        private int newDevice;
    @Value("${app.risk.weights.new-country:40}")       private int newCountry;
    @Value("${app.risk.weights.unusual-hour:10}")      private int unusualHour;
    @Value("${app.risk.weights.failed-attempt:8}")     private int failedAttempt;
    @Value("${app.risk.weights.max-failed-counted:3}") private int maxFailedCounted;
    @Value("${app.risk.weights.ip-velocity:20}")       private int ipVelocity;
    @Value("${app.risk.ip-velocity-threshold:5}")      private int ipVelocityThreshold;

    @Override
    public RiskResult evaluate(ContextSignals s) {
        List<RiskFactor> factors = new ArrayList<>();

        if (s.newDevice()) {
            factors.add(new RiskFactor("NEW_DEVICE", newDevice,
                    "Login from a device not seen before"));
        }
        if (s.newCountry()) {
            factors.add(new RiskFactor("NEW_COUNTRY", newCountry,
                    "Login from a country not seen before (" + s.country() + ")"));
        }
        if (s.unusualHour()) {
            factors.add(new RiskFactor("UNUSUAL_HOUR", unusualHour,
                    "Login at a time of day outside the user's usual pattern"));
        }

        long failed = Math.min(s.failedAttemptsByEmail(), maxFailedCounted);
        if (failed > 0) {
            factors.add(new RiskFactor("FAILED_ATTEMPTS", (int) failed * failedAttempt,
                    s.failedAttemptsByEmail() + " recent failed attempt(s) on this account"));
        }
        if (s.failedAttemptsByIp() >= ipVelocityThreshold) {
            factors.add(new RiskFactor("IP_VELOCITY", ipVelocity,
                    s.failedAttemptsByIp() + " recent failed attempts from this IP address"));
        }

        int total = Math.min(100, factors.stream().mapToInt(RiskFactor::points).sum());
        return new RiskResult(total, factors);
    }
}