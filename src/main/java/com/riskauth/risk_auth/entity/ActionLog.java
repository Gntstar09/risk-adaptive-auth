package com.riskauth.risk_auth.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "action_logs")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ActionLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id")
    private Long userId;

    private String email;

    private String action;

    @Column(name = "ip_address")
    private String ipAddress;

    private String country;

    @Column(name = "risk_score")
    private int riskScore;

    private String decision;           // ALLOW / STEP_UP / STEP_UP_VERIFIED / DENY

    private boolean completed;         // true if the action was actually performed

    @Column(length = 1000)
    private String factors;            // e.g. "SESSION_COUNTRY_CHANGED+40"

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}