package com.riskauth.risk_auth.service;

import com.riskauth.risk_auth.entity.OtpToken;
import com.riskauth.risk_auth.entity.User;
import com.riskauth.risk_auth.repository.OtpTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpTokenRepository otpTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final ObjectProvider<JavaMailSender> mailSenderProvider;
    private final SecureRandom random = new SecureRandom();

    @Value("${app.otp.expiry-minutes:5}")
    private long expiryMinutes;

    @Value("${app.otp.max-attempts:3}")
    private int maxAttempts;

    @Value("${app.otp.email-enabled:false}")
    private boolean emailEnabled;

    @Value("${spring.mail.username:}")
    private String fromAddress;

    public void generateAndSend(User user, Long attemptId) {
        // Only the newest OTP may be valid
        otpTokenRepository.findByUserIdAndUsedFalse(user.getId()).forEach(t -> {
            t.setUsed(true);
            otpTokenRepository.save(t);
        });

        String code = String.format("%06d", random.nextInt(1_000_000));

        otpTokenRepository.save(OtpToken.builder()
                .userId(user.getId())
                .attemptId(attemptId)
                .codeHash(passwordEncoder.encode(code))   // never store the raw code
                .expiresAt(LocalDateTime.now().plusMinutes(expiryMinutes))
                .used(false)
                .attempts(0)
                .build());

        deliver(user, code);
    }

    private void deliver(User user, String code) {
        JavaMailSender sender = mailSenderProvider.getIfAvailable();

        // Demo mode: no email configured, print to the console instead
        if (!emailEnabled || sender == null || fromAddress.isBlank()) {
            log.info("[DEMO] OTP for {} = {}", user.getEmail(), code);
            return;
        }

        try {
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setFrom(fromAddress);
            msg.setTo(user.getEmail());
            msg.setSubject("Your verification code");
            msg.setText("Your verification code is " + code + ".\n\n"
                    + "It expires in " + expiryMinutes + " minutes and can be used once.\n"
                    + "If you did not try to sign in, please change your password.");
            sender.send(msg);
            log.info("OTP email sent to {}", user.getEmail());   // the code itself is never logged
        } catch (Exception e) {
            log.error("Could not send OTP email to {}: {}", user.getEmail(), e.getMessage());
        }
    }

    /**
     * Returns the id of the pending login attempt this OTP completes.
     * Deliberately NOT @Transactional: the wrong-guess counter must be saved
     * even though we throw right after, or OTP guessing would be unlimited.
     */
    public Long verify(Long userId, String code) {
        OtpToken token = otpTokenRepository.findFirstByUserIdAndUsedFalseOrderByIdDesc(userId)
                .orElseThrow(() -> new IllegalArgumentException("No pending verification. Please log in again."));

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            token.setUsed(true);
            otpTokenRepository.save(token);
            throw new IllegalArgumentException("OTP expired. Please log in again.");
        }
        if (token.getAttempts() >= maxAttempts) {
            token.setUsed(true);
            otpTokenRepository.save(token);
            throw new IllegalArgumentException("Too many wrong OTP attempts. Please log in again.");
        }
        if (!passwordEncoder.matches(code, token.getCodeHash())) {
            token.setAttempts(token.getAttempts() + 1);
            otpTokenRepository.save(token);
            throw new IllegalArgumentException("Invalid OTP");
        }

        token.setUsed(true);
        otpTokenRepository.save(token);
        return token.getAttemptId();
    }
}