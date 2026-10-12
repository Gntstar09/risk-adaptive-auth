package com.riskauth.risk_auth.entity;



import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "login_attempts")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id")
    private Long userId;                 // null if the email doesn't exist

    private String email;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "device_hash")
    private String deviceHash;           // filled in on Day 3

    private String country;              // filled in on Day 3

    private boolean success;

    @Column(name = "attempt_time")
    private LocalDateTime attemptTime;

    @Column(name = "risk_score")
    private Integer riskScore;           // filled in when the risk engine exists

    private String decision;             // ALLOW / OTP / DENY, later
}
