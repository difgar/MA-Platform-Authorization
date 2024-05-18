package com.mobileamericas.authorization.services.impl;

import com.mobileamericas.authorization.infrastructure.persistence.entities.PermissionEntity;
import com.mobileamericas.authorization.infrastructure.persistence.entities.RoleEntity;
import com.mobileamericas.authorization.model.Role;
import com.mobileamericas.authorization.services.AuthorizationService;
import com.mobileamericas.authorization.services.UserService;
import com.mobileamericas.authorization.utils.AuthenticationUtil;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class AuthorizationServiceImpl implements AuthorizationService {

    private UserService userService;
    private AuthenticationUtil authenticationUtil;

    @Override
    public Optional<Set<Role>> getRoles() {
        return userService.findByEmail(authenticationUtil.getEmail())
                .map(user -> user.getRoles())
                .map(this::roleMapper);
    }

    private Set<Role> roleMapper(Set<RoleEntity> roles) {
        return roles.stream()
                .filter(rol -> rol.getApp().getName().equals(authenticationUtil.getApp()))
                .map(roleEntity -> Role.builder()
                .name(roleEntity.getName())
                .permissions(permissionMapper(roleEntity.getPermissions()))
                .build())
                .collect(Collectors.toSet());
    }

    private Set<String> permissionMapper(Set<PermissionEntity> permissions) {
        return permissions.stream().map(PermissionEntity::getName).collect(Collectors.toSet());
    }
}
