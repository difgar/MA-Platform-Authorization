package com.mobileamericas.authorization.adapter.token;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "auth_refresh_token")
class RefreshTokenEntity {

    @Id
    @Column(length = 36)
    String id;

    @Column(name = "user_id", nullable = false, length = 36)
    String userId;

    @Column(name = "app_id", nullable = false, length = 36)
    String appId;

    /** SHA-256 en hexadecimal. Nunca el valor en claro. */
    @Column(name = "token_hash", nullable = false, length = 64)
    String tokenHash;

    @Column(name = "family_id", nullable = false, length = 36)
    String familyId;

    @Column(name = "expires_at", nullable = false)
    Instant expiresAt;

    @Column(name = "used_at")
    Instant usedAt;

    @Column(name = "revoked_at")
    Instant revokedAt;

    @Column(name = "created_at", nullable = false)
    Instant createdAt;

    protected RefreshTokenEntity() {}
}
