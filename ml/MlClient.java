package com.riskauth.risk_auth.ml;

import com.riskauth.risk_auth.context.ContextSignals;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
public class MlClient {

    private final RestClient client;

    public MlClient(@Value("${app.ml.url:http://127.0.0.1:8000}") String baseUrl) {
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(
                HttpClient.newBuilder().connectTimeout(Duration.ofMillis(500)).build());
        factory.setReadTimeout(Duration.ofMillis(800));
        this.client = RestClient.builder().baseUrl(baseUrl).requestFactory(factory).build();
    }

    /** Returns the ML score (0-100), or empty if the service is down, slow, or answers badly. */
    public Optional<Integer> score(ContextSignals s) {
        try {
            Map<String, Object> body = Map.of(
                    "first_login", s.firstLogin() ? 1 : 0,
                    "new_device", s.newDevice() ? 1 : 0,
                    "new_country", s.newCountry() ? 1 : 0,
                    "unusual_hour", s.unusualHour() ? 1 : 0,
                    "failed_by_email", (int) Math.min(s.failedAttemptsByEmail(), 1000),
                    "failed_by_ip", (int) Math.min(s.failedAttemptsByIp(), 100000),
                    "hour", s.time().getHour(),
                    "is_weekend", s.time().getDayOfWeek().getValue() >= 6 ? 1 : 0);

            Map<?, ?> res = client.post().uri("/predict")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(Map.class);

            if (res != null && res.get("ml_score") instanceof Number n) {
                return Optional.of(Math.max(0, Math.min(100, n.intValue())));
            }
            log.warn("ML service returned an unexpected response: {}", res);
        } catch (Exception e) {
            log.warn("ML service unavailable, using rules only: {}", e.getMessage());
        }
        return Optional.empty();
    }
}