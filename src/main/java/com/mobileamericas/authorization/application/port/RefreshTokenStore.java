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

    /**
     * La familia existe pero ya está revocada: resultado rutinario, no un
     * error. Ocurre cada vez que la detección de reutilización o un logout
     * revocaron la familia y alguien vuelve a pedir una rotación con ella.
     * Quien llame debe tratarlo como "la sesión terminó, vuelve a autenticarte".
     */
    class RevokedFamilyException extends RuntimeException {
        private final UUID familyId;

        public RevokedFamilyException(UUID familyId) {
            super("Familia revocada: " + familyId);
            this.familyId = familyId;
        }

        public UUID familyId() {
            return familyId;
        }
    }

    /**
     * No existe ningún registro para ese familyId: violación de precondición,
     * indicio de un error interno (un familyId que no salió de este store).
     * No es un resultado rutinario.
     */
    class UnknownFamilyException extends RuntimeException {
        private final UUID familyId;

        public UnknownFamilyException(UUID familyId) {
            super("Familia desconocida: " + familyId);
            this.familyId = familyId;
        }

        public UUID familyId() {
            return familyId;
        }
    }

    IssuedRefreshToken issue(UUID userId, UUID appId);

    /**
     * @throws UnknownFamilyException si no existe ningún token con ese familyId;
     *         indica un error interno, no un resultado esperable en operación normal.
     * @throws RevokedFamilyException si la familia existe pero ya fue revocada;
     *         resultado rutinario tras una detección de reutilización o un logout.
     */
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
