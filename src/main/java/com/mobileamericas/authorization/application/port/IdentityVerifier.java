package com.mobileamericas.authorization.application.port;

import com.mobileamericas.authorization.domain.App;

public interface IdentityVerifier {

    record VerifiedIdentity(String email, String fullName, App app) {}

    /** @throws IdentityRejectedException si el token no vale o su 'aud' no es de ninguna app. */
    VerifiedIdentity verify(String idToken);

    class IdentityRejectedException extends RuntimeException {
        public IdentityRejectedException(String mensaje) {
            super(mensaje);
        }
        public IdentityRejectedException(String mensaje, Throwable causa) {
            super(mensaje, causa);
        }
    }
}
