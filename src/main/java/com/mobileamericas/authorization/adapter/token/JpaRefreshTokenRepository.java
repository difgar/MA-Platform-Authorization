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

    /**
     * Transición de estado condicionada, no una lectura previa: si el UPDATE
     * afecta cero filas, es que otra llamada concurrente ya marcó el token
     * como usado entre nuestra lectura y este UPDATE. Perder esa carrera es
     * indistinguible de la reutilización y {@code consume()} lo trata igual.
     */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("UPDATE RefreshTokenEntity t SET t.usedAt = :ahora WHERE t.id = :id AND t.usedAt IS NULL")
    int marcarUsado(@Param("id") String id, @Param("ahora") Instant ahora);

    // flushAutomatically: RefreshTokenEntity usa un @Id asignado, no generado,
    // así que un save() reciente en esta misma transacción (por ejemplo el
    // INSERT de un rotate() previo) puede seguir sin volcarse a la base de
    // datos; sin este flag, esa fila recién creada escaparía a este UPDATE
    // masivo, dejando un token vivo en una familia que se acaba de revocar.
    // clearAutomatically: desasocia TODO el contexto de persistencia de esta
    // transacción, no solo las filas de esta familia, así que cualquier otra
    // entidad gestionada que estuviera en vuelo queda desasociada y sus
    // cambios posteriores se pierden al hacer commit. Se acepta ese coste
    // porque revokeFamily() se usa cerca del final de la transacción.
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            UPDATE RefreshTokenEntity t SET t.revokedAt = :ahora
             WHERE t.familyId = :familyId AND t.revokedAt IS NULL
            """)
    void revokeFamily(@Param("familyId") String familyId, @Param("ahora") Instant ahora);
}
