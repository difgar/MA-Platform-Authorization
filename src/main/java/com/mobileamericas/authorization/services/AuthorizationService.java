package com.mobileamericas.authorization.services;

import com.mobileamericas.authorization.infrastructure.persistence.entities.RoleEntity;
import com.mobileamericas.authorization.model.Role;

import java.util.Optional;
import java.util.Set;

public interface AuthorizationService {

    Optional<Set<Role>> getRoles();
    Set<Role> roleMapper(Set<RoleEntity> roles, String app);
}
