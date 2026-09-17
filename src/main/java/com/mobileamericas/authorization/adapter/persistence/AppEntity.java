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

    @Column(name = "google_client_id", nullable = false)
    String googleClientId;

    String url;

    @Column(nullable = false)
    boolean active;

    @Column(name = "created_at", nullable = false)
    Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    Instant updatedAt;

    protected AppEntity() {}
}
