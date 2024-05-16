package com.mobileamericas.authorization.repositories;

import com.mobileamericas.authorization.infrastructure.persistence.entities.UserEntity;

import java.util.Optional;

public interface UserRepository {
    Optional<UserEntity> findByEmail(String email);
}
