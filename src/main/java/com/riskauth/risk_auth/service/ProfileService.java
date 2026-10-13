
package com.riskauth.risk_auth.service;

import com.riskauth.risk_auth.context.ContextSignals;
import com.riskauth.risk_auth.context.LoginContext;
import com.riskauth.risk_auth.entity.KnownDevice;
import com.riskauth.risk_auth.entity.LoginAttempt;
import com.riskauth.risk_auth.repository.KnownDeviceRepository;
import com.riskauth.risk_auth.repository.LoginAttemptRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ProfileService {

    private final KnownDeviceRepository knownDeviceRepository;
    private final LoginAttemptRepository loginAttemptRepository;

    /** Compare the current context with the user's baseline. Call BEFORE updateProfile(). */
    public ContextSignals evaluate(Long userId, LoginContext ctx) {
        boolean hasHistory =
                loginAttemptRepository.existsByUserIdAndSuccessTrue(userId);

        boolean newDevice = hasHistory
                && !isKnownDevice(userId, ctx.deviceHash());

        boolean newCountry = hasHistory
                && !isUsualCountry(userId, ctx.country());

        boolean unusualHour = hasHistory
                && !isUsualHour(userId, ctx.time());

        return new ContextSignals(
                !hasHistory,
                newDevice,
                newCountry,
                unusualHour,
                ctx.failedByEmail(),
                ctx.failedByIp(),
                ctx.country(),
                ctx.deviceHash()
        );
    }

    public boolean isKnownDevice(Long userId, String deviceHash) {
        return knownDeviceRepository
                .existsByUserIdAndDeviceHash(userId, deviceHash);
    }

    public boolean isUsualCountry(Long userId, String country) {
        return loginAttemptRepository
                .existsByUserIdAndCountryAndSuccessTrue(userId, country);
    }

    /** Usual = the user has logged in successfully within +/- 2 hours of this time of day. */
    public boolean isUsualHour(Long userId, LocalDateTime time) {
        List<LoginAttempt> recent =
                loginAttemptRepository
                        .findTop50ByUserIdAndSuccessTrueOrderByAttemptTimeDesc(userId);

        int hour = time.getHour();

        return recent.stream()
                .anyMatch(a ->
                        hourDistance(a.getAttemptTime().getHour(), hour) <= 2);
    }

    /** Call after a successful login to add/refresh the device in the baseline. */

    @Transactional
    public void updateProfile(Long userId, String deviceHash, LocalDateTime time) {
        knownDeviceRepository.findByUserIdAndDeviceHash(userId, deviceHash)
                .ifPresentOrElse(
                        device -> {
                            device.setLastSeen(time);
                            knownDeviceRepository.save(device);
                        },
                        () -> knownDeviceRepository.save(KnownDevice.builder()
                                .userId(userId)
                                .deviceHash(deviceHash)
                                .firstSeen(time)
                                .lastSeen(time)
                                .trusted(true)
                                .build()));
    }

    private int hourDistance(int a, int b) {
        int d = Math.abs(a - b);
        return Math.min(d, 24 - d); // 23:00 and 01:00 are 2 hours apart
    }
}
