package com.mobileamericas.authorization.adapter.token;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "authorization.jwt")
public record JwtProperties(String issuer, Duration accessTtl, Duration refreshTtl, List<String> keyLocations) {

    public JwtProperties {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("authorization.jwt.issuer es obligatorio.");
        }
        accessTtl = accessTtl == null ? Duration.ofMinutes(15) : accessTtl;
        refreshTtl = refreshTtl == null ? Duration.ofHours(12) : refreshTtl;
        if (keyLocations == null || keyLocations.isEmpty()) {
            throw new IllegalArgumentException("authorization.jwt.key-locations es obligatorio.");
        }
        keyLocations = List.copyOf(keyLocations);
    }
}
