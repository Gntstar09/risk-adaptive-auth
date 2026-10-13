package com.riskauth.risk_auth.risk;

import com.riskauth.risk_auth.context.ContextSignals;

public interface RiskEngine {
    RiskResult evaluate(ContextSignals signals);
}