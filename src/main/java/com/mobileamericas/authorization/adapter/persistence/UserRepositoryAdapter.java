package com.mobileamericas.authorization.adapter.persistence;

import com.mobileamericas.authorization.application.port.UserRepository;
import com.mobileamericas.authorization.domain.User;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Optional;

@Repository
@Transactional(readOnly = true)
class UserRepositoryAdapter implements UserRepository {

    private final JpaUserRepository jpa;

    UserRepositoryAdapter(JpaUserRepository jpa) {
        this.jpa = jpa;
    }

    @Override
    public Optional<User> findByEmail(String email) {
        // MySQL (utf8mb4_0900_ai_ci) compara 'email' sin distinguir mayúsculas;
        // PostgreSQL sí distingue. Sin normalizar aquí, la misma consulta
        // devuelve resultados distintos según el motor -y, en un login real,
        // según cómo Google capitalice el email frente a cómo quedó guardado.
        // Locale.ROOT y no el locale por defecto: con locale turco, toLowerCase()
        // convierte 'I' en 'ı' (i sin punto) en vez de 'i', lo que rompería la
        // igualdad justo en un campo de identidad.
        return jpa.findByEmail(email.toLowerCase(Locale.ROOT)).map(DomainMapper::toDomain);
    }
}
