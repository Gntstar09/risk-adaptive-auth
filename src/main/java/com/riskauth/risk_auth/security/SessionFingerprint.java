package com.riskauth.risk_auth.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Hashes the User-Agent the same way everywhere, so a token and a later request can be compared. */
public final class SessionFingerprint {

    private SessionFingerprint() {}

    public static String hashUserAgent(String userAgent) {
        String v = userAgent == null ? "" : userAgent;
        if (v.length() > 500) {
            v = v.substring(0, 500);
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(v.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}