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
import tools.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.Map;
import java.util.Set;

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

    /**
     * OJO: no basta con pegarle a una ruta que no existe. Bajo el viejo
     * .anyRequest().permitAll(), GET /v1/lo-que-sea también daba 404 —el
     * despachador nunca encuentra un handler—, así que esa prueba pasaba
     * igual con o sin la denegación por defecto y no demostraba nada.
     *
     * GET /v1/auth/logout SÍ está mapeado (el controlador lo declara), pero
     * solo para POST, y la lista permitAll de SecurityConfig también dice
     * POST. Con permitAll a secas, esta petición pasaría la seguridad y
     * llegaría al despachador, que respondería 405 (método no soportado). Con
     * denegación por defecto, .anyRequest().authenticated() la intercepta ANTES
     * de que el despachador llegue a enterarse de que el método está mal: 401.
     * Es la única combinación de esta clase que distingue de verdad un
     * resultado del otro.
     */
    @Test
    void una_ruta_mapeada_pero_no_declarada_exige_autenticacion() {
        assertThat(http.getForEntity("/v1/auth/logout", String.class).getStatusCode())
                .isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
    }

    @Test
    void el_jwks_es_publico_y_solo_trae_claves_publicas() {
        var r = http.getForEntity("/.well-known/jwks.json", String.class);

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);

        // Se parsea el JSON real de la respuesta -no una subcadena, que ni
        // distingue una clave de un valor ni cubre 'dp'/'dq'/'qi' (los otros
        // tres componentes privados del formato CRT de una clave RSA que
        // 'd'/'p'/'q' por sí solos no cubren)- y se comprueba el objeto que
        // reconstruiría un consumidor real.
        @SuppressWarnings("unchecked")
        var jwks = (Map<String, Object>) new ObjectMapper().readValue(r.getBody(), Map.class);
        @SuppressWarnings("unchecked")
        var claves = (List<Map<String, Object>>) jwks.get("keys");

        assertThat(claves).as("el JWKS debe traer al menos una clave").isNotEmpty();
        for (var clave : claves) {
            assertThat(clave).containsKeys("n", "e");
            assertThat(clave.keySet())
                    .as("ningún componente privado de la clave RSA debe salir por el JWKS público")
                    .doesNotContainAnyElementsOf(Set.of("d", "p", "q", "dp", "dq", "qi"));
        }
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
        var headers = new HttpHeaders();
        headers.setBearerAuth(tokenDelUsuarioSembrado());

        var r = http.exchange("/v1/auth/me", HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r.getBody())
                .contains("usuario1@pendiente.local")
                .contains("\"app\":\"admin\"")
                // Ausente, no fabricado: ni el claim 'name' del token ni el
                // campo "name" de la respuesta deben inventar un valor.
                .contains("\"name\":null");
    }

    /**
     * El único camino que un navegador puede tomar de verdad.
     *
     * SecurityConfig configura oauth2ResourceServer().jwt() sin
     * bearerTokenResolver propio, así que por defecto Spring Security solo
     * mira la cabecera Authorization: Bearer (DefaultBearerTokenResolver). El
     * access token, sin embargo, viaja EXCLUSIVAMENTE en la cookie HttpOnly
     * ma_access, con el cuerpo vacío a propósito para que JavaScript no pueda
     * leerlo. Sin CookieBearerTokenResolver, un navegador podía iniciar sesión
     * y no tenía ninguna forma de llegar después a /v1/auth/me: JavaScript no
     * puede poner en una cabecera un valor que tiene prohibido leer.
     *
     * La otra prueba de esta clase que autentica con éxito
     * (un_usuario_con_full_name_nulo_autentica_en_me_sin_fallar) usa
     * headers.setBearerAuth(...), que es precisamente el camino que un
     * navegador NO puede tomar; sin esta prueba, ese agujero quedaba tapado
     * por su único camino de éxito.
     */
    @Test
    void un_token_propio_en_la_cookie_ma_access_autentica_en_me() {
        var headers = new HttpHeaders();
        headers.add(HttpHeaders.COOKIE, CookieFactory.ACCESS + "=" + tokenDelUsuarioSembrado());

        var r = http.exchange("/v1/auth/me", HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r.getBody()).contains("usuario1@pendiente.local");
    }

    private String tokenDelUsuarioSembrado() {
        var app = apps.findByName("admin").orElseThrow();
        var usuario = usuarios.findByEmail("usuario1@pendiente.local").orElseThrow();
        assertThat(usuario.fullName()).as("precondición: así están sembrados los usuarios hoy").isNull();

        var grant = AccessGrant.of(usuario, app, apps.resourceCatalogue(app.id()));
        return emisor.issueAccessToken(grant);
    }
}
