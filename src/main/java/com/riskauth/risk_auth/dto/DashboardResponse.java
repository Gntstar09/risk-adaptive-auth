package com.riskauth.risk_auth.dto;

import java.util.List;

public record DashboardResponse(
        int days,
        Summary summary,
        List<DayPoint> timeline,
        List<IpStat> topIps,
        List<FactorStat> topFactors,
        List<RecentEvent> recent
) {
    public record Summary(long total, long allowed, long stepUp, long denied,
                          long wrongPassword, double avgScore) {}

    public record DayPoint(String date, long allow, long stepUp, long deny, long wrongPassword) {}

    public record IpStat(String ip, String country, long events, int maxScore) {}

    public record FactorStat(String factor, long count) {}

    public record RecentEvent(Long id, String time, String email, String ip,
                              String country, Integer score, String decision) {}
}