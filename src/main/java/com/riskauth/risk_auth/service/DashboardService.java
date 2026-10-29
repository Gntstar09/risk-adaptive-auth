package com.riskauth.risk_auth.service;

import com.riskauth.risk_auth.dto.DashboardResponse;
import com.riskauth.risk_auth.entity.LoginAttempt;
import com.riskauth.risk_auth.entity.RiskLog;
import com.riskauth.risk_auth.repository.LoginAttemptRepository;
import com.riskauth.risk_auth.repository.RiskLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class DashboardService {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LoginAttemptRepository loginAttemptRepository;
    private final RiskLogRepository riskLogRepository;

    /** Categories: 0 = allowed, 1 = step-up, 2 = denied, 3 = wrong password. */
    private static int category(LoginAttempt a) {
        String dec = a.getDecision();
        if ("STEP_UP".equals(dec)) return 1;
        if ("DENY".equals(dec)) return 2;
        if (dec == null && !a.isSuccess()) return 3;
        return 0;   // ALLOW, or older successful logins that have no decision
    }

    public DashboardResponse build(int days) {
        int d = Math.max(1, Math.min(30, days));
        LocalDate today = LocalDate.now();
        LocalDateTime since = today.minusDays(d - 1L).atStartOfDay();
        List<LoginAttempt> attempts = loginAttemptRepository.findByAttemptTimeAfterOrderByIdDesc(since);

        long[] counts = new long[4];
        double scoreSum = 0;
        long scored = 0;
        Map<LocalDate, long[]> perDay = new TreeMap<>();
        for (int i = d - 1; i >= 0; i--) {
            perDay.put(today.minusDays(i), new long[4]);
        }

        for (LoginAttempt a : attempts) {
            int cat = category(a);
            counts[cat]++;
            if (a.getRiskScore() != null) {
                scoreSum += a.getRiskScore();
                scored++;
            }
            long[] row = perDay.get(a.getAttemptTime().toLocalDate());
            if (row != null) row[cat]++;
        }

        double avg = scored == 0 ? 0 : Math.round(scoreSum / scored * 10) / 10.0;
        DashboardResponse.Summary summary = new DashboardResponse.Summary(
                attempts.size(), counts[0], counts[1], counts[2], counts[3], avg);

        List<DashboardResponse.DayPoint> timeline = perDay.entrySet().stream()
                .map(e -> new DashboardResponse.DayPoint(e.getKey().toString(),
                        e.getValue()[0], e.getValue()[1], e.getValue()[2], e.getValue()[3]))
                .toList();

        // Top IPs: only attempts that were not a plain ALLOW
        Map<String, List<LoginAttempt>> byIp = attempts.stream()
                .filter(a -> category(a) != 0 && a.getIpAddress() != null)
                .collect(Collectors.groupingBy(LoginAttempt::getIpAddress));
        List<DashboardResponse.IpStat> topIps = byIp.entrySet().stream()
                .map(e -> {
                    List<LoginAttempt> list = e.getValue();
                    int max = list.stream().map(LoginAttempt::getRiskScore)
                            .filter(Objects::nonNull).max(Integer::compare).orElse(0);
                    String country = list.stream().map(LoginAttempt::getCountry)
                            .filter(Objects::nonNull).findFirst().orElse("UNKNOWN");
                    return new DashboardResponse.IpStat(e.getKey(), country, list.size(), max);
                })
                .sorted((a, b) -> a.events() != b.events()
                        ? Long.compare(b.events(), a.events())
                        : Integer.compare(b.maxScore(), a.maxScore()))
                .limit(8)
                .toList();

        // Top risk factors, from risk_logs
        List<Long> ids = attempts.stream().map(LoginAttempt::getId).toList();
        if (ids.size() > 20000) {
            ids = ids.subList(0, 20000);
        }
        List<DashboardResponse.FactorStat> topFactors = ids.isEmpty() ? List.of() :
                riskLogRepository.findByAttemptIdIn(ids).stream()
                        .collect(Collectors.groupingBy(RiskLog::getFactorName, Collectors.counting()))
                        .entrySet().stream()
                        .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                        .limit(8)
                        .map(e -> new DashboardResponse.FactorStat(e.getKey(), e.getValue()))
                        .toList();

        List<DashboardResponse.RecentEvent> recent = attempts.stream()
                .filter(a -> category(a) != 0)
                .limit(10)
                .map(a -> new DashboardResponse.RecentEvent(a.getId(), a.getAttemptTime().format(TIME),
                        a.getEmail(), a.getIpAddress(), a.getCountry(), a.getRiskScore(),
                        a.getDecision() != null ? a.getDecision() : "WRONG_PASSWORD"))
                .toList();

        return new DashboardResponse(d, summary, timeline, topIps, topFactors, recent);
    }
}