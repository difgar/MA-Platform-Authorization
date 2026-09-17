package com.mobileamericas.authorization.web.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Igual que JwtProperties (adapter/token): @ConfigurationProperties admite
 * tanto una secuencia YAML como una variable de entorno separada por comas,
 * así que no hace falta la solución de compromiso de un {@code @Value} sobre
 * un {@code List<String>} (que solo resuelve un escalar, nunca una secuencia
 * YAML — esa es la evidencia que estaba cuatro líneas más arriba, en el mismo
 * fichero de configuración, antes de esta clase).
 */
@ConfigurationProperties(prefix = "authorization.cors")
public record CorsProperties(List<String> allowedOrigins) {

    public CorsProperties {
        if (allowedOrigins == null || allowedOrigins.isEmpty()) {
            throw new IllegalArgumentException("authorization.cors.allowed-origins es obligatorio.");
        }
        allowedOrigins = List.copyOf(allowedOrigins);
    }
}
