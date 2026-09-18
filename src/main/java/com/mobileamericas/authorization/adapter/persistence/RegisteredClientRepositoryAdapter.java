package com.mobileamericas.authorization.adapter.persistence;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.domain.App;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;

/**
 * auth_app ES el registro de clientes OAuth: este adaptador traduce cada fila
 * a un RegisteredClient en vez de mantener la tabla propia del framework como
 * un segundo registro aparte. Dos registros que deben concordar sin que nada
 * los compare es la forma exacta del bug que mantuvo este servicio caído en
 * producción.
 *
 * Todos los clientes son públicos (SPAs servidas desde un bucket, sin secreto
 * que guardar) con PKCE obligatorio y sin pantalla de consentimiento -son
 * aplicaciones de primera parte, y el consentimiento ahí es teatro-. No
 * declaran el grant de refresh: un cliente público no lo recibe aunque se
 * declare (verificado en la prueba de concepto de la fase 2), así que
 * declararlo solo confundiría a quien lea el registro.
 */
@Repository
@Transactional(readOnly = true)
class RegisteredClientRepositoryAdapter implements RegisteredClientRepository {

    /**
     * Ruling 7 de la tarea 4: access_ttl_seconds es nullable en la fila, y
     * Duration.ofSeconds(null) revienta con un NullPointerException que no
     * explica nada -una app dada de alta sin TTL dejaría de emitir tokens sin
     * decir por qué-. 7200 segundos (2h) es el valor por defecto que fija el
     * spec para cuando la fila no lo trae.
     */
    private static final Duration ACCESS_TOKEN_TTL_POR_DEFECTO = Duration.ofSeconds(7200);

    private final AppRepository apps;
    private final JpaAppRepository jpa;

    RegisteredClientRepositoryAdapter(AppRepository apps, JpaAppRepository jpa) {
        this.apps = apps;
        this.jpa = jpa;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return apps.findByName(clientId).map(this::toRegisteredClient).orElse(null);
    }

    /**
     * El id es el mismo UUID de auth_app (ver toRegisteredClient).
     *
     * Quién lo llama HOY, comprobado sobre las clases de
     * spring-security-oauth2-authorization-server 7.1.1 y no deducido:
     * OidcLogoutAuthenticationProvider (el end_session_endpoint resuelve el
     * cliente del id_token_hint por su id interno), más los proveedores de
     * introspección y de device verification. Sin este método implementado de
     * verdad, el logout falla con un UnsupportedOperationException que no dice
     * nada de su causa; lo cubre FlujoCompletoIT.
     *
     * Una versión anterior de este comentario lo justificaba con
     * JdbcOAuth2AuthorizationService y con la tabla oauth2_authorization. Las
     * dos cosas eran falsas: esa tabla la crea V3 (no V2) y NO hay hoy ningún
     * bean OAuth2AuthorizationService, así que el almacén es el de memoria y
     * nadie relee nada de esa tabla. Ver README, sección «Réplicas».
     */
    @Override
    public RegisteredClient findById(String id) {
        return jpa.findById(id)
                .map(DomainMapper::toDomain)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException(
                "El registro de clientes se gestiona por migración sobre auth_app hasta que la "
                        + "fase 3 añada el CRUD de apps; RegisteredClientRepositoryAdapter no escribe.");
    }

    /**
     * null cuando la app está desactivada o no tiene redirect_uris utilizable:
     * el contrato de RegisteredClientRepository entiende null como "cliente
     * desconocido", y así el framework responde con un error de OAuth en vez
     * de propagar una excepción como 500. Un RegisteredClient de
     * Authorization Code sin redirect_uri es inservible -y RegisteredClient.build()
     * no lo impide por sí solo en esta versión-, así que se trata igual que
     * una app desactivada (ruling 7 de la tarea 4).
     */
    private RegisteredClient toRegisteredClient(App app) {
        if (!app.active() || app.redirectUris().isEmpty()) {
            return null;
        }

        var ttl = app.accessTtlSeconds() != null
                ? Duration.ofSeconds(app.accessTtlSeconds())
                : ACCESS_TOKEN_TTL_POR_DEFECTO;

        var builder = RegisteredClient.withId(app.id().toString())
                .clientId(app.name())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope("openid")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(ttl)
                        .build());

        app.redirectUris().forEach(builder::redirectUri);
        app.postLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);

        return builder.build();
    }
}
