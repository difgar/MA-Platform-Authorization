package com.mobileamericas.authorization.adapter.token;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Sin access-ttl ni refresh-ttl: la duración de los tokens deja de ser global
 * del servicio y pasa a declararse por aplicación en auth_app, que es donde
 * Spring Authorization Server la lee (por cliente OAuth).
 */
@ConfigurationProperties(prefix = "authorization.jwt")
public record JwtProperties(String issuer, List<String> keyLocations) {

    public JwtProperties {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("authorization.jwt.issuer es obligatorio.");
        }
        if (keyLocations == null || keyLocations.isEmpty()) {
            throw new IllegalArgumentException("authorization.jwt.key-locations es obligatorio.");
        }
        keyLocations = List.copyOf(keyLocations);
    }
}
