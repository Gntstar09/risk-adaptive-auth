package com.riskauth.risk_auth.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "risk_logs")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class RiskLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "attempt_id", nullable = false)
    private Long attemptId;

    @Column(name = "factor_name", nullable = false)
    private String factorName;

    @Column(name = "points_added")
    private int pointsAdded;

    private String reason;
}