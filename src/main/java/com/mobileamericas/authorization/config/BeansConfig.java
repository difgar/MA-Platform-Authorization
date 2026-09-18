package com.mobileamericas.authorization.config;

import com.mobileamericas.authorization.adapter.token.JwtKeys;
import com.mobileamericas.authorization.adapter.token.JwtProperties;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Cableado de beans de la aplicación.
 */
@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class BeansConfig {

    @Bean
    JwtKeys jwtKeys(ResourceLoader loader, JwtProperties props) {
        var jwks = props.keyLocations().stream()
                .map(location -> leer(loader, location))
                .toList();
        return JwtKeys.fromJson(jwks);
    }

    /** Lo consume el authorization server para firmar. */
    @Bean
    JWKSource<SecurityContext> jwkSource(JwtKeys keys) {
        return keys.jwkSource();
    }

    private String leer(ResourceLoader loader, String location) {
        try {
            return loader.getResource(location).getContentAsString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("No se pudo leer la clave JWT en " + location, e);
        }
    }
}
