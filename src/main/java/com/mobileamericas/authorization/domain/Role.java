package com.mobileamericas.authorization.domain;

import java.util.Set;
import java.util.UUID;

public record Role(UUID id, String name, UUID appId, Set<Permission> permissions) {

    public Role {
        permissions = Set.copyOf(permissions);
    }
}
