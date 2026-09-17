package com.mobileamericas.authorization.adapter.google;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "authorization.google")
public record GoogleProperties(String jwkSetUri, List<String> acceptedIssuers) {

    public GoogleProperties {
        jwkSetUri = jwkSetUri == null ? "https://www.googleapis.com/oauth2/v3/certs" : jwkSetUri;
        // Según la documentación de verificación de ID token de Google y su
        // documento de descubrimiento OpenID, el 'iss' de un ID token de Google
        // viene indistintamente como 'accounts.google.com' o como
        // 'https://accounts.google.com'; ambas formas son legítimas. NO reducir
        // esta lista a un solo valor: un validador de un único issuer rechazaría
        // inicios de sesión reales que traigan la forma que falte.
        acceptedIssuers = (acceptedIssuers == null || acceptedIssuers.isEmpty())
                ? List.of("https://accounts.google.com", "accounts.google.com")
                : List.copyOf(acceptedIssuers);
    }
}
