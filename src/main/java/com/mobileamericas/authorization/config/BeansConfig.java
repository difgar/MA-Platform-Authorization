package com.mobileamericas.authorization.config;

import com.mobileamericas.authorization.adapter.token.JwtKeys;
import com.mobileamericas.authorization.adapter.token.JwtProperties;
import com.mobileamericas.authorization.adapter.token.RsaTokenIssuer;
import com.mobileamericas.authorization.application.port.TokenIssuer;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Cableado de beans de la aplicación. Solo lo que necesita la emisión de tokens
 * por ahora; el decodificador de Google y el propio (tareas 7 y 9) se añaden
 * más adelante a esta misma clase.
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

    @Bean
    TokenIssuer tokenIssuer(JwtKeys keys, JwtProperties props) {
        return new RsaTokenIssuer(keys, props);
    }

    private String leer(ResourceLoader loader, String location) {
        try {
            return loader.getResource(location).getContentAsString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("No se pudo leer la clave JWT en " + location, e);
        }
    }
}
