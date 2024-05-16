package com.mobileamericas.authorization.services.impl;

import com.mobileamericas.authorization.infrastructure.persistence.entities.UserEntity;
import com.mobileamericas.authorization.repositories.UserRepository;
import com.mobileamericas.authorization.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@AllArgsConstructor
public class UserServiceImpl implements UserService {

    private UserRepository userRepository;

    @Override
    public Optional<UserEntity> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}
