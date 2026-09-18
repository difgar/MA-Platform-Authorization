package com.mobileamericas.authorization.adapter.persistence;

import com.mobileamericas.authorization.domain.App;
import com.mobileamericas.authorization.domain.Permission;
import com.mobileamericas.authorization.domain.Role;
import com.mobileamericas.authorization.domain.User;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/** El único punto donde una entidad JPA se convierte en dominio. */
final class DomainMapper {

    private DomainMapper() {}

    static App toDomain(AppEntity e) {
        return new App(UUID.fromString(e.id), e.name, e.url, e.active,
                separarUris(e.redirectUris), separarUris(e.postLogoutRedirectUris), e.accessTtlSeconds);
    }

    /** auth_app guarda varias URI separadas por comas en una sola columna TEXT. */
    private static List<String> separarUris(String csv) {
        if (csv == null || csv.isBlank()) {
            return List.of();
        }
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(uri -> !uri.isEmpty())
                .toList();
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
