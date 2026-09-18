package com.mobileamericas.authorization.adapter.persistence;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DomainMapper es package-private, igual que AppEntity: esta prueba vive en su
 * mismo paquete a propósito, para poder construir la entidad directamente sin
 * levantar base de datos ni contexto de Spring.
 */
class DomainMapperTest {

    /**
     * Sólo los casos vacío y en blanco de separarUris tenían prueba. El caso
     * normal -dos URIs, con espacios tras la coma y una coma final- es
     * justo el que produce en cuanto alguien registre una app con dos
     * entornos (p. ej. un panel con staging y producción), y no lo ejercitaba
     * nada.
     */
    @Test
    void separa_varias_uris_por_comas_limpiando_espacios_y_la_coma_final() {
        var e = new AppEntity();
        e.id = UUID.randomUUID().toString();
        e.name = "multi-entorno";
        e.url = "https://multi.example";
        e.active = true;
        e.redirectUris = "https://a.example/callback, https://b.example/callback ,";
        e.postLogoutRedirectUris = "https://a.example/, https://b.example/,";
        e.accessTtlSeconds = 7200L;
        e.createdAt = Instant.now();
        e.updatedAt = Instant.now();

        var app = DomainMapper.toDomain(e);

        assertThat(app.redirectUris())
                .containsExactly("https://a.example/callback", "https://b.example/callback");
        assertThat(app.postLogoutRedirectUris())
                .containsExactly("https://a.example/", "https://b.example/");
    }
}
