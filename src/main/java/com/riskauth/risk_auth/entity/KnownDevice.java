package com.riskauth.risk_auth.entity;



import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "known_devices")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class KnownDevice {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "device_hash", nullable = false)
    private String deviceHash;

    @Column(name = "first_seen")
    private LocalDateTime firstSeen;

    @Column(name = "last_seen")
    private LocalDateTime lastSeen;

    private boolean trusted;
}
