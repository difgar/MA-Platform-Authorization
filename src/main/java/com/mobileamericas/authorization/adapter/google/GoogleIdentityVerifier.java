package com.mobileamericas.authorization.adapter.google;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.IdentityVerifier;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Verifica el ID token de Google y resuelve a qué app pertenece.
 *
 * El JwtDecoder es un singleton con caché de claves. El código anterior creaba
 * un GoogleIdTokenVerifier y un NetHttpTransport nuevos en CADA petición, lo que
 * anulaba la caché y añadía una ida y vuelta a Google por llamada.
 *
 * La app se deduce del 'aud' del token, es decir, del client ID de OAuth con el
 * que el usuario entró. Ese mapeo vive en auth_app.google_client_id.
 */
@Component
public class GoogleIdentityVerifier implements IdentityVerifier {

    private final JwtDecoder decoder;
    private final AppRepository apps;

    public GoogleIdentityVerifier(
            @Qualifier("googleJwtDecoder") JwtDecoder googleJwtDecoder, AppRepository apps) {
        this.decoder = googleJwtDecoder;
        this.apps = apps;
    }

    @Override
    public VerifiedIdentity verify(String idToken) {
        Jwt jwt;
        try {
            jwt = decoder.decode(idToken);
        } catch (JwtException e) {
            throw new IdentityRejectedException("El token de Google no es válido.", e);
        }

        var audiencias = jwt.getAudience();
        if (audiencias == null || audiencias.isEmpty()) {
            throw new IdentityRejectedException("El token de Google no declara audiencia.");
        }

        var app = audiencias.stream()
                .map(apps::findByGoogleClientId)
                .flatMap(Optional::stream)
                .findFirst()
                .orElseThrow(() -> new IdentityRejectedException(
                        "El token no corresponde a ninguna aplicación registrada."));

        if (!app.active()) {
            throw new IdentityRejectedException(
                    "La aplicación '%s' está desactivada.".formatted(app.name()));
        }

        var email = jwt.getClaimAsString("email");
        if (email == null || email.isBlank()) {
            throw new IdentityRejectedException("El token de Google no trae email.");
        }

        return new VerifiedIdentity(email, jwt.getClaimAsString("name"), app);
    }
}
