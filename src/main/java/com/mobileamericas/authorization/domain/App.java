package com.mobileamericas.authorization.domain;

import java.util.List;
import java.util.UUID;

/**
 * Una app registrada. Desde la fase 2, auth_app ES el registro de clientes
 * OAuth (ver RegisteredClientRepositoryAdapter): redirectUris,
 * postLogoutRedirectUris y accessTtlSeconds son exactamente los datos que ese
 * adaptador traduce a un RegisteredClient, en vez de mantener una segunda
 * tabla que tendría que concordar con esta a mano.
 *
 * accessTtlSeconds puede ser null (la columna lo permite); el valor por
 * defecto del spec cuando falta lo decide el adaptador, no el dominio.
 */
public record App(
        UUID id,
        String name,
        String url,
        boolean active,
        List<String> redirectUris,
        List<String> postLogoutRedirectUris,
        Long accessTtlSeconds) {

    public App {
        redirectUris = List.copyOf(redirectUris);
        postLogoutRedirectUris = List.copyOf(postLogoutRedirectUris);
    }
}
