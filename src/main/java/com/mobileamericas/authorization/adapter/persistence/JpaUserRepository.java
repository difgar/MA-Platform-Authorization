package com.mobileamericas.authorization.adapter.persistence;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

interface JpaUserRepository extends JpaRepository<UserEntity, String> {

    Optional<UserEntity> findByEmail(String email);
}
