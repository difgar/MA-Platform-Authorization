package com.mobileamericas.authorization.oauth;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
class RegistroDeClientesMySqlIT extends RegistroDeClientesIT {

    @Container
    @ServiceConnection
    static MySQLContainer<?> db = new MySQLContainer<>("mysql:8.4");
}
