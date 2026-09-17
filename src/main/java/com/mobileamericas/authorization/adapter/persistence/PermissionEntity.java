package com.mobileamericas.authorization.adapter.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "auth_permission")
class PermissionEntity {

    @Id
    @Column(length = 36)
    String id;

    @Column(name = "app_id", nullable = false, length = 36)
    String appId;

    @Column(nullable = false, length = 100)
    String resource;

    @Column(nullable = false, length = 20)
    String verb;

    String description;

    @Column(name = "created_at", nullable = false)
    Instant createdAt;

    protected PermissionEntity() {}
}
