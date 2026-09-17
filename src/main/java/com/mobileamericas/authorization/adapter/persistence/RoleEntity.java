package com.mobileamericas.authorization.adapter.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "auth_role")
class RoleEntity {

    @Id
    @Column(length = 36)
    String id;

    @Column(nullable = false, length = 100)
    String name;

    @Column(name = "app_id", nullable = false, length = 36)
    String appId;

    String description;

    // EAGER aquí es deliberado y acotado: un rol tiene unos pocos permisos y
    // siempre se necesitan juntos. No es el EAGER global del código anterior,
    // que existía sólo para que el grafo sobreviviera fuera de la transacción.
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "auth_role_permission",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    Set<PermissionEntity> permissions;

    @Column(name = "created_at", nullable = false)
    Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    Instant updatedAt;

    protected RoleEntity() {}
}
