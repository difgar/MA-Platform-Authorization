package com.mobileamericas.authorization.adapter.persistence;

import com.mobileamericas.authorization.domain.App;
import com.mobileamericas.authorization.domain.Permission;
import com.mobileamericas.authorization.domain.Role;
import com.mobileamericas.authorization.domain.User;

import java.util.UUID;
import java.util.stream.Collectors;

/** El único punto donde una entidad JPA se convierte en dominio. */
final class DomainMapper {

    private DomainMapper() {}

    static App toDomain(AppEntity e) {
        return new App(UUID.fromString(e.id), e.name, e.googleClientId, e.url, e.active);
    }

    static User toDomain(UserEntity e) {
        var roles = e.roles.stream().map(DomainMapper::toDomain).collect(Collectors.toSet());
        return new User(UUID.fromString(e.id), e.email, e.fullName, e.active, roles);
    }

    static Role toDomain(RoleEntity e) {
        var permisos = e.permissions.stream()
                .map(p -> new Permission(p.resource, p.verb))
                .collect(Collectors.toSet());
        return new Role(UUID.fromString(e.id), e.name, UUID.fromString(e.appId), permisos);
    }
}
