package com.mobileamericas.authorization.services;

import com.mobileamericas.authorization.infrastructure.persistence.entities.UserEntity;

import java.util.Optional;

public interface UserService {
    Optional<UserEntity> findByEmail(String email);
}
