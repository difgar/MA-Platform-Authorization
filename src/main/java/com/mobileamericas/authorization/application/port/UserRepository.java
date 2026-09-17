package com.mobileamericas.authorization.application.port;

import com.mobileamericas.authorization.domain.User;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository {

    Optional<User> findByEmail(String email);

    Optional<User> findById(UUID id);
}
