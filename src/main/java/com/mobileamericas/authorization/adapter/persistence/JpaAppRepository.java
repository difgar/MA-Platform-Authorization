package com.mobileamericas.authorization.adapter.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

interface JpaAppRepository extends JpaRepository<AppEntity, String> {

    Optional<AppEntity> findByGoogleClientId(String googleClientId);

    Optional<AppEntity> findByName(String name);

    @Query("""
            SELECT DISTINCT p.resource FROM PermissionEntity p
             WHERE p.appId = :appId AND p.resource <> '*'
            """)
    List<String> findResourcesByAppId(@Param("appId") String appId);
}
