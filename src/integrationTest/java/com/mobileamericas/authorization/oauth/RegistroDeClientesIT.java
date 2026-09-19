package com.mobileamericas.authorization.oauth;

import com.mobileamericas.authorization.BaseIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * auth_app ES el registro de clientes OAuth: RegisteredClientRepositoryAdapter
 * traduce cada fila, no una segunda tabla que tendría que concordar con ella a
 * mano. Dos registros que deben concordar sin que nada los compare es la forma
 * exacta del bug que mantuvo este servicio caído en producción.
 */
public abstract class RegistroDeClientesIT extends BaseIT {

    @Autowired RegisteredClientRepository clientes;

    @Test
    void una_fila_de_auth_app_se_convierte_en_cliente_oauth() {
        var c = clientes.findByClientId("admin");

        assertThat(c).isNotNull();
        assertThat(c.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        // containsExactly, no contains: el diseño prohíbe declarar REFRESH_TOKEN
        // (un cliente público no lo recibe aunque se declare) y 'contains' pasaría
        // igual si alguien lo añadiera por error.
        assertThat(c.getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(c.getRedirectUris()).containsExactly("https://admin.mobile-americas.com/callback");
        assertThat(c.getPostLogoutRedirectUris()).containsExactly("https://admin.mobile-americas.com/");
        // Sin este scope, Spring Authorization Server rechaza con invalid_scope
        // cualquier /oauth2/authorize que pida openid, y no se emite id_token.
        assertThat(c.getScopes()).containsExactly("openid");
        assertThat(c.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(c.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofHours(2));
    }

    @Test
    void trafficflow_se_registra_como_cliente_publico_con_pkce() {
        var c = clientes.findByClientId("trafficflow");

        assertThat(c).isNotNull();
        assertThat(c.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(c.getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(c.getRedirectUris()).containsExactlyInAnyOrder(
                "https://tf.mobile-americas.com/callback", "http://localhost:5174/callback");
        assertThat(c.getPostLogoutRedirectUris()).containsExactlyInAnyOrder(
                "https://tf.mobile-americas.com/", "http://localhost:5174/");
        assertThat(c.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(c.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofHours(2));
    }

    @Test
    void un_cliente_desconocido_no_existe() {
        assertThat(clientes.findByClientId("no-registrado")).isNull();
    }

    @Test
    void una_app_desactivada_no_se_ofrece_como_cliente() {
        jdbc.sql("UPDATE auth_app SET active = FALSE WHERE name = 'fgf'").update();
        assertThat(clientes.findByClientId("fgf")).isNull();
    }

    /**
     * Ruling 7: un access_ttl_seconds nulo no debe reventar con un NPE que no
     * explica nada (Duration.ofSeconds(null)); se trata como 7200 segundos, el
     * valor por defecto del spec. Fila propia (no admin/fgf) para no depender
     * del orden de ejecución frente a las otras pruebas de esta clase.
     */
    @Test
    void un_ttl_nulo_usa_el_valor_por_defecto_de_dos_horas() {
        insertarApp("temporal-ttl-nulo", "https://temporal.mobile-americas.com/callback", null);

        var c = clientes.findByClientId("temporal-ttl-nulo");

        assertThat(c).isNotNull();
        assertThat(c.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofSeconds(7200));
    }

    /**
     * Ruling 7: un RegisteredClient de Authorization Code sin redirect_uri es
     * inservible. Se decide tratarlo igual que una app desactivada -devolver
     * null, "cliente desconocido" para el framework- en vez de dejar que
     * RegisteredClient.build() explote con un IllegalArgumentException que
     * llegaría como 500 al usuario.
     */
    @Test
    void redirect_uris_nulo_no_ofrece_cliente() {
        insertarApp("temporal-sin-redirect", null, 7200L);

        assertThat(clientes.findByClientId("temporal-sin-redirect")).isNull();
    }

    @Test
    void redirect_uris_en_blanco_no_ofrece_cliente() {
        insertarApp("temporal-redirect-en-blanco", "   ", 7200L);

        assertThat(clientes.findByClientId("temporal-redirect-en-blanco")).isNull();
    }

    @Test
    void guardar_un_cliente_no_esta_soportado() {
        var cliente = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("cualquiera")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://cualquiera.mobile-americas.com/callback")
                .build();

        assertThatThrownBy(() -> clientes.save(cliente))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessageContaining("migración");
    }

    /**
     * findById no es un método de adorno: el end_session_endpoint resuelve el
     * cliente del id_token_hint por su id interno
     * (OidcLogoutAuthenticationProvider), y sin esto implementado de verdad el
     * logout falla con un UnsupportedOperationException que no diría nada
     * sobre su causa.
     *
     * Esto decía antes que quien lo llamaba era JdbcOAuth2AuthorizationService,
     * al releer de oauth2_authorization. Era falso por partida doble: esa tabla
     * la crea V3, no V2, y no hay ningún bean OAuth2AuthorizationService, así
     * que el almacén de autorizaciones es el de memoria. Ver README, «Réplicas».
     */
    @Test
    void un_cliente_tambien_se_encuentra_por_su_id_interno() {
        var id = insertarApp("temporal-por-id", "https://temporal.mobile-americas.com/callback", 7200L);

        var c = clientes.findById(id);

        assertThat(c).isNotNull();
        assertThat(c.getClientId()).isEqualTo("temporal-por-id");
        // Y que el id del RegisteredClient sea el de auth_app, no uno
        // inventado por el adaptador: es el identificador con el que el
        // end_session_endpoint vuelve a buscar el cliente, así que un id que
        // no case rompe el logout aunque la búsqueda de arriba funcione.
        assertThat(c.getId()).isEqualTo(id);
    }

    /** Fila de auth_app aislada por prueba: no depende del orden de ejecución ni pisa admin/fgf. */
    private String insertarApp(String name, String redirectUris, Long accessTtlSeconds) {
        var id = UUID.randomUUID().toString();
        var redirectUrisSql = redirectUris == null ? "NULL" : "'" + redirectUris + "'";
        var ttlSql = accessTtlSeconds == null ? "NULL" : accessTtlSeconds.toString();

        jdbc.sql("""
                INSERT INTO auth_app (id, name, url, active, redirect_uris, access_ttl_seconds, created_at, updated_at)
                VALUES ('%s', '%s', 'https://temporal.mobile-americas.com', TRUE, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """.formatted(id, name, redirectUrisSql, ttlSql))
                .update();

        return id;
    }
}
