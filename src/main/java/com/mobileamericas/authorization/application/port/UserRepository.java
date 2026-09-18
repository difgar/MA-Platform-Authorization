package com.mobileamericas.authorization.application.port;

import com.mobileamericas.authorization.domain.User;

import java.util.Optional;

public interface UserRepository {

    Optional<User> findByEmail(String email);
}
