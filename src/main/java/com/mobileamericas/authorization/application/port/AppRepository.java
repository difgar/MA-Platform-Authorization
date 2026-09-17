package com.mobileamericas.authorization.application.port;

import com.mobileamericas.authorization.domain.App;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface AppRepository {

    Optional<App> findByGoogleClientId(String googleClientId);

    Optional<App> findByName(String name);

    /** Lo usa refresh(): la familia del refresh token guarda el id, no el nombre. */
    Optional<App> findById(UUID id);

    /** Recursos concretos declarados por la app. Nunca incluye el comodín '*'. */
    Set<String> resourceCatalogue(UUID appId);
}
