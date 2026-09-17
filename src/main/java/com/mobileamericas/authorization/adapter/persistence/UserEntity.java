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
@Table(name = "auth_user")
class UserEntity {

    @Id
    @Column(length = 36)
    String id;

    @Column(nullable = false, length = 320)
    String email;

    @Column(name = "full_name")
    String fullName;

    @Column(nullable = false)
    boolean active;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "auth_user_role",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    Set<RoleEntity> roles;

    @Column(name = "created_at", nullable = false)
    Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    Instant updatedAt;

    protected UserEntity() {}
}
