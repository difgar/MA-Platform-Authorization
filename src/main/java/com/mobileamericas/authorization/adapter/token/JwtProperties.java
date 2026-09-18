package com.mobileamericas.authorization.adapter.token;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Sin access-ttl ni refresh-ttl: la duración de los tokens deja de ser global
 * del servicio y pasa a declararse por aplicación en auth_app, que es donde
 * Spring Authorization Server la lee (por cliente OAuth).
 *
 * Sin 'issuer' tampoco, desde la tarea 9: era un componente huérfano. Nadie
 * leía JwtProperties.issuer, y el 'iss' que sale en los tokens lo decide
 * spring.security.oauth2.authorizationserver.issuer (application.yml), que es
 * lo que lee el framework. Mantener aquí un emisor que no emite nada invita a
 * cambiarlo para mover el emisor y a concluir, al ver que los tokens no
 * cambian, que el problema está en otra parte.
 */
@ConfigurationProperties(prefix = "authorization.jwt")
public record JwtProperties(List<String> keyLocations) {

    public JwtProperties {
        if (keyLocations == null || keyLocations.isEmpty()) {
            throw new IllegalArgumentException("authorization.jwt.key-locations es obligatorio.");
        }
        keyLocations = List.copyOf(keyLocations);
    }
}
