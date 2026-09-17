package com.mobileamericas.authorization.adapter.token;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
class RefreshTokenStoreMySqlIT extends RefreshTokenStoreIT {

    @Container
    @ServiceConnection
    static MySQLContainer<?> db = new MySQLContainer<>("mysql:8.4");
}
