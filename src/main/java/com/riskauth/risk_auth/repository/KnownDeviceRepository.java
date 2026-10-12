
package com.riskauth.risk_auth.repository;

import com.riskauth.risk_auth.entity.KnownDevice;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface KnownDeviceRepository extends JpaRepository<KnownDevice, Long> {

    boolean existsByUserIdAndDeviceHash(Long userId, String deviceHash);

    Optional<KnownDevice> findByUserIdAndDeviceHash(
            Long userId, String deviceHash);
}
