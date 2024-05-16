package com.mobileamericas.authorization.services.impl;

import com.mobileamericas.authorization.infrastructure.persistence.entities.PermissionEntity;
import com.mobileamericas.authorization.infrastructure.persistence.entities.RoleEntity;
import com.mobileamericas.authorization.model.Role;
import com.mobileamericas.authorization.services.AuthorizationService;
import com.mobileamericas.authorization.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class AuthorizationServiceImpl implements AuthorizationService {

    private UserService userService;

    @Override
    public Optional<Set<Role>> getRoles() {
        return userService.findByEmail(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString())
                .map(user -> user.getRoles())
                .map(this::roleMapper);
    }

    private Set<Role> roleMapper(Set<RoleEntity> roles) {
        return roles.stream().map(roleEntity -> Role.builder()
                .name(roleEntity.getName())
                .permissions(permissionMapper(roleEntity.getPermissions()))
                .build())
                .collect(Collectors.toSet());
    }

    private Set<String> permissionMapper(Set<PermissionEntity> permissions) {
        return permissions.stream().map(PermissionEntity::getName).collect(Collectors.toSet());
    }
}
