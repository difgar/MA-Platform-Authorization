package com.mobileamericas.authorization.infrastructure.persistence.repositories;

import com.mobileamericas.authorization.infrastructure.persistence.entities.UserEntity;
import com.mobileamericas.authorization.repositories.UserRepository;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaUserRepository extends JpaRepository<UserEntity, Long>, UserRepository {
    Optional<UserEntity> findByEmail(String email);
}
