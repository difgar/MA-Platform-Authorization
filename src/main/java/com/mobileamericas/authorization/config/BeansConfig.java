package com.mobileamericas.authorization.config;

import com.mobileamericas.authorization.adapter.google.GoogleProperties;
import com.mobileamericas.authorization.adapter.token.JwtKeys;
import com.mobileamericas.authorization.adapter.token.JwtProperties;
import com.mobileamericas.authorization.adapter.token.RsaTokenIssuer;
import com.mobileamericas.authorization.application.port.TokenIssuer;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Cableado de beans de la aplicación. El decodificador propio (tarea 9) se
 * añade más adelante a esta misma clase.
 */
@Configuration
@EnableConfigurationProperties({JwtProperties.class, GoogleProperties.class})
public class BeansConfig {

    @Bean
    JwtKeys jwtKeys(ResourceLoader loader, JwtProperties props) {
        var jwks = props.keyLocations().stream()
                .map(location -> leer(loader, location))
                .toList();
        return JwtKeys.fromJson(jwks);
    }

    @Bean
    TokenIssuer tokenIssuer(JwtKeys keys, JwtProperties props) {
        return new RsaTokenIssuer(keys, props);
    }

    /**
     * Decodificador singleton para los ID token de Google: cachea las claves
     * públicas de Google internamente. El código anterior construía un
     * GoogleIdTokenVerifier nuevo en cada petición, lo que anulaba esa caché.
     *
     * withJwkSetUri(...) resuelve el JWKS de forma perezosa, en el primer
     * decode(), no al construir el bean: así el contexto de Spring arranca sin
     * red, lo que necesitan las pruebas de integración (sandbox sin internet).
     */
    @Bean
    JwtDecoder googleJwtDecoder(GoogleProperties props) {
        return NimbusJwtDecoder.withJwkSetUri(props.jwkSetUri()).build();
    }

    private String leer(ResourceLoader loader, String location) {
        try {
            return loader.getResource(location).getContentAsString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("No se pudo leer la clave JWT en " + location, e);
        }
    }
}
