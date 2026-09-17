package com.mobileamericas.authorization.application.service;

import java.time.Duration;
import java.time.Instant;

public record AuthenticationResult(
        String accessToken,
        String refreshToken,
        Duration accessTtl,
        Instant refreshExpiresAt) {

    /**
     * Redactados los dos, no solo uno: RefreshTokenStore.IssuedRefreshToken ya
     * redacta su valor en claro, pero se lo pasa en claro a este record, que es
     * el que de verdad cruza a web/ y por tanto el que más cerca está de acabar
     * en una línea de log o en el volcado de una excepción.
     */
    @Override
    public String toString() {
        return "AuthenticationResult[accessToken=REDACTED, refreshToken=REDACTED, accessTtl=%s, refreshExpiresAt=%s]"
                .formatted(accessTtl, refreshExpiresAt);
    }
}
