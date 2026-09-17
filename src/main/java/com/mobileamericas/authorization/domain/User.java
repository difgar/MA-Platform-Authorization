package com.mobileamericas.authorization.domain;

import java.util.Set;
import java.util.UUID;

public record User(UUID id, String email, String fullName, boolean active, Set<Role> roles) {

    public User {
        roles = Set.copyOf(roles);
    }
}
