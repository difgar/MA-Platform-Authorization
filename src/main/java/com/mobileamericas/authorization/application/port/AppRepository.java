package com.mobileamericas.authorization.application.port;

import com.mobileamericas.authorization.domain.App;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface AppRepository {

    Optional<App> findByName(String name);

    /**
     * Lo consume ClaimsCustomizer para resolver el claim 'apps': los roles de
     * un usuario guardan el id de la aplicación, no su nombre.
     */
    Optional<App> findById(UUID id);

    /** Recursos concretos declarados por la app. Nunca incluye el comodín '*'. */
    Set<String> resourceCatalogue(UUID appId);
}
