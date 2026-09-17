package com.mobileamericas.authorization.adapter.persistence;

import com.mobileamericas.authorization.application.port.UserRepository;
import com.mobileamericas.authorization.domain.User;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Repository
@Transactional(readOnly = true)
class UserRepositoryAdapter implements UserRepository {

    private final JpaUserRepository jpa;

    UserRepositoryAdapter(JpaUserRepository jpa) {
        this.jpa = jpa;
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return jpa.findByEmail(email).map(DomainMapper::toDomain);
    }

    @Override
    public Optional<User> findById(UUID id) {
        return jpa.findById(id.toString()).map(DomainMapper::toDomain);
    }
}
