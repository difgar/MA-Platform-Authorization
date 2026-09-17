package com.mobileamericas.authorization.adapter.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

interface JpaRefreshTokenRepository extends JpaRepository<RefreshTokenEntity, String> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    /** El sujeto de rotate() sale del registro más reciente de la familia. */
    Optional<RefreshTokenEntity> findFirstByFamilyIdOrderByCreatedAtDesc(String familyId);

    // flushAutomatically: por si el llamador cambió alguna entidad de esta
    // familia antes de invocar esto en la misma transacción, esos cambios se
    // vuelcan primero. clearAutomatically: para que cualquier entidad de esta
    // familia que se lea DESPUÉS, en la misma transacción, se recargue desde
    // la base de datos en vez de devolver la copia en caché de primer nivel,
    // que este UPDATE masivo no actualiza.
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            UPDATE RefreshTokenEntity t SET t.revokedAt = :ahora
             WHERE t.familyId = :familyId AND t.revokedAt IS NULL
            """)
    void revokeFamily(@Param("familyId") String familyId, @Param("ahora") Instant ahora);
}
