package com.mobileamericas.authorization.application.port;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Refresh tokens opacos, rotativos y revocables.
 *
 * Opacos y no JWT a propósito: un JWT no se puede revocar antes de que expire
 * sin una lista de rechazados, que es exactamente la tabla que esto ya es.
 */
public interface RefreshTokenStore {

    record IssuedRefreshToken(String value, UUID familyId, Instant expiresAt) {

        /** Redactado a propósito: esto es lo que un log.debug o un volcado de excepción imprimiría. */
        @Override
        public String toString() {
            return "IssuedRefreshToken[value=REDACTED, familyId=%s, expiresAt=%s]".formatted(familyId, expiresAt);
        }
    }

    record RefreshSubject(UUID userId, UUID appId, UUID familyId) {}

    IssuedRefreshToken issue(UUID userId, UUID appId);

    IssuedRefreshToken rotate(UUID familyId);

    /**
     * Marca el token como usado y devuelve su sujeto.
     *
     * Si el token ya estaba usado, revoca TODA la familia y devuelve vacío: que
     * un token rotado vuelva a aparecer significa que alguien tiene una copia.
     */
    Optional<RefreshSubject> consume(String rawToken);

    void revokeFamily(UUID familyId);
}
