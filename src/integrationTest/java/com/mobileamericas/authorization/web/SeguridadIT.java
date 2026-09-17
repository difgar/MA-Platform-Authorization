package com.mobileamericas.authorization.web;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.TokenIssuer;
import com.mobileamericas.authorization.application.port.UserRepository;
import com.mobileamericas.authorization.domain.AccessGrant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Base abstracta y SIN anotar con {@code @SpringBootTest} ni
 * {@code @Testcontainers}, y no extiende {@link com.mobileamericas.authorization.BaseIT}
 * porque estas pruebas no tocan la base de datos directamente, solo HTTP.
 *
 * Las clases concretas ({@code SeguridadMySqlIT}, {@code SeguridadPostgresIT})
 * llevan cada una su propio contenedor y su propio {@code @SpringBootTest}, igual
 * que en {@code MigracionIT} y {@code RepositoriosIT}.
 *
 * {@code TestRestTemplate} también se movió de paquete en Boot 4: vive ahora en
 * org.springframework.boot.resttestclient (artefacto spring-boot-resttestclient),
 * no en org.springframework.boot.test.web.client como en Boot 3. Y, a diferencia
 * de Boot 3, ya no se autoconfigura solo por usar
 * webEnvironment = RANDOM_PORT: hace falta pedirlo explícitamente con
 * @AutoConfigureTestRestTemplate, o el @Autowired de más abajo falla con
 * NoSuchBeanDefinitionException.
 */
@AutoConfigureTestRestTemplate
public abstract class SeguridadIT {

    @Autowired TestRestTemplate http;
    @Autowired TokenIssuer emisor;
    @Autowired AppRepository apps;
    @Autowired UserRepository usuarios;

    @Test
    void el_endpoint_env_ya_no_existe() {
        // Era público y volcaba System.getenv(), que incluye la contraseña de la
        // base de datos y el secreto de firma.
        var r = http.getForEntity("/v1/authorization/env", String.class);

        assertThat(r.getStatusCode()).isIn(HttpStatus.NOT_FOUND, HttpStatus.UNAUTHORIZED);
        assertThat(r.getBody() == null ? "" : r.getBody())
                .doesNotContain("DB_MA_PLATFORM_PASSWORD")
                .doesNotContain("JWT_PRIVATE_KEY");
    }

    @Test
    void una_ruta_no_declarada_exige_autenticacion() {
        // Antes: .anyRequest().permitAll()
        assertThat(http.getForEntity("/v1/lo-que-sea", String.class).getStatusCode())
                .isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN, HttpStatus.NOT_FOUND);
    }

    @Test
    void el_jwks_es_publico_y_solo_trae_claves_publicas() {
        var r = http.getForEntity("/.well-known/jwks.json", String.class);

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r.getBody()).contains("\"keys\"").contains("\"n\"").contains("\"e\"");
        assertThat(r.getBody()).doesNotContain("\"d\"").doesNotContain("\"p\"");
    }

    @Test
    void me_sin_token_responde_401() {
        assertThat(http.getForEntity("/v1/auth/me", String.class).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    /**
     * El resto de las pruebas de esta clase comprueban el lado "cierra el
     * paso"; esta comprueba el lado contrario: que un token propio, válido,
     * de verdad autentica. Es la única forma de detectar una mala combinación
     * entre selfJwtDecoder (@Primary), el conversor de autoridades y el
     * validador de emisor: cualquiera de los tres, mal cableado, podría
     * rechazar en silencio un token legítimo y las otras pruebas no lo
     * notarían, porque todas esperan un rechazo.
     *
     * Usa al usuario sembrado tal cual, SIN sustituir nada: su full_name es
     * NULL en V2 (a propósito, para no meter datos personales en git), que es
     * exactamente el caso real de todo usuario hoy en la base de datos. Antes
     * de la corrección de RsaTokenIssuer, emitir este token lanzaba
     * IllegalArgumentException y el login real fallaba para cualquier
     * usuario; esta es la prueba que lo habría detectado.
     */
    @Test
    void un_usuario_con_full_name_nulo_autentica_en_me_sin_fallar() {
        var app = apps.findByName("admin").orElseThrow();
        var usuario = usuarios.findByEmail("usuario1@pendiente.local").orElseThrow();
        assertThat(usuario.fullName()).as("precondición: así están sembrados los usuarios hoy").isNull();

        var grant = AccessGrant.of(usuario, app, apps.resourceCatalogue(app.id()));
        var token = emisor.issueAccessToken(grant);

        var headers = new HttpHeaders();
        headers.setBearerAuth(token);

        var r = http.exchange("/v1/auth/me", HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r.getBody())
                .contains("usuario1@pendiente.local")
                .contains("\"app\":\"admin\"")
                // Ausente, no fabricado: ni el claim 'name' del token ni el
                // campo "name" de la respuesta deben inventar un valor.
                .contains("\"name\":null");
    }
}
