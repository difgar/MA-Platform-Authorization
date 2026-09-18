package com.mobileamericas.authorization.adapter.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "auth_app")
class AppEntity {

    @Id
    @Column(length = 36)
    String id;

    @Column(nullable = false, length = 100)
    String name;

    String url;

    @Column(nullable = false)
    boolean active;

    // Varias URI separadas por comas en una sola columna TEXT (ver DomainMapper,
    // que las separa al convertir a dominio). Nullable: una app puede darse de
    // alta sin ellas todavía, y RegisteredClientRepositoryAdapter decide qué
    // hacer con eso (ver su javadoc).
    @Column(name = "redirect_uris")
    String redirectUris;

    @Column(name = "post_logout_redirect_uris")
    String postLogoutRedirectUris;

    @Column(name = "access_ttl_seconds")
    Long accessTtlSeconds;

    @Column(name = "created_at", nullable = false)
    Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    Instant updatedAt;

    protected AppEntity() {}
}
