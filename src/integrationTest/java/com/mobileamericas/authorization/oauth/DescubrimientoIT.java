package com.mobileamericas.authorization.oauth;

import com.mobileamericas.authorization.BaseIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * El authorization server publica su documento de descubrimiento sin
 * autenticación. Es la prueba mínima de que el framework está activo.
 *
 * {@code @AutoConfigureTestRestTemplate} por el mismo motivo que en el resto
 * de la suite: en Boot 4, TestRestTemplate ya no se autoconfigura solo por
 * usar webEnvironment = RANDOM_PORT y vive en otro paquete
 * (org.springframework.boot.resttestclient).
 */
@AutoConfigureTestRestTemplate
public abstract class DescubrimientoIT extends BaseIT {

    @Autowired TestRestTemplate http;

    @Value("${local.server.port}") int puerto;

    @Test
    void publica_el_documento_de_descubrimiento() {
        var r = http.getForObject("/.well-known/openid-configuration", String.class);

        assertThat(r)
                .contains("\"authorization_endpoint\"")
                .contains("\"token_endpoint\"")
                .contains("\"jwks_uri\"")
                .contains("\"end_session_endpoint\"");
    }

    /**
     * Hereda el cuerpo del test que la fase 1 tenía sobre /.well-known/jwks.json
     * (SeguridadIT.el_jwks_es_publico_y_solo_trae_claves_publicas), portado a la
     * ruta que sirve ahora el framework. Se parsea el JSON real de la respuesta
     * -no una subcadena, que ni distingue una clave de un valor ni cubre
     * 'dp'/'dq'/'qi' (los otros tres componentes privados del formato CRT de una
     * clave RSA que 'd'/'p'/'q' por sí solos no cubren)- y se comprueba el objeto
     * que reconstruiría un consumidor real.
     *
     * Este es el único endpoint del servicio que publica material de clave, y
     * JwtKeys.jwkSource() acaba de reabrirse a público para dárselo al framework:
     * es exactamente el sitio donde una regresión sacaría la clave privada.
     */
    @Test
    void el_jwks_sigue_sirviendo_solo_material_publico() {
        var r = http.getForEntity("/oauth2/jwks", String.class);

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);

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

    /**
     * /oauth2/authorize está dentro del matcher del authorization server, pero
     * exige un usuario autenticado: sin sesión no se emite ningún código, y al
     * usuario se le manda a autenticarse.
     *
     * No prueba el framework, prueba dos líneas NUESTRAS, y por eso lo que se
     * afirma es el Location y no sólo el código de estado (los dos resultados
     * posibles son 302):
     *
     * - init() del configurer no llama a authorizeHttpRequests, así que sin el
     *   anyRequest().authenticated() de esa cadena nadie deniega esta
     *   petición: comprobado quitando la línea, la respuesta es
     *   302 https://admin.mobile-americas.com/callback?error=invalid_request&
     *   error_description=OAuth%202.0%20Parameter%3A%20principal. Es decir, al
     *   usuario sin sesión lo devuelven a su aplicación con un error que
     *   parece culpa suya.
     * - Y sin el exceptionHandling con LoginUrlAuthenticationEntryPoint que
     *   añadió la tarea 5, la respuesta es 401 con WWW-Authenticate: Bearer
     *   -como si faltara un token-, porque el entry point que registra el
     *   propio configurer es un HttpStatusEntryPoint(UNAUTHORIZED).
     *
     * Esta prueba distingue esos tres resultados.
     *
     * La petición lleva code_challenge porque el cliente exige PKCE: sin él el
     * endpoint rechaza por 'code_challenge' ANTES de mirar quién pide, y la
     * prueba pasaría por el motivo equivocado (verificado también).
     *
     * client_id=admin, no un cliente de andamiaje: desde la tarea 4,
     * RegisteredClientRepositoryAdapter (sobre auth_app) es el único registro
     * de clientes, así que 'admin' es el cliente real y activo que la app del
     * mismo nombre representa. redirect_uri es la que esa fila trae en
     * auth_app.redirect_uris (ver V3__oauth.sql, que es la migración que
     * añade y siembra esas columnas, no V2).
     *
     * Cliente HTTP propio, no TestRestTemplate, por lo mismo que en
     * ActuatorSecurityIT: TestRestTemplate sigue los redirects, así que una
     * regresión aquí intentaría conectarse de verdad a
     * https://admin.mobile-americas.com y fallaría con un error de E/S en vez
     * de con una aserción legible.
     */
    @Test
    void authorize_sin_sesion_no_emite_nada() throws Exception {
        var r = get("/oauth2/authorize?response_type=code&client_id=admin"
                + "&redirect_uri=https%3A%2F%2Fadmin.mobile-americas.com%2Fcallback&scope=openid"
                + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                + "&code_challenge_method=S256");

        assertThat(r.statusCode())
                .as("sin el entry point del login esto sería un 401 con WWW-Authenticate: Bearer")
                .isEqualTo(302);
        assertThat(r.headers().firstValue("Location").orElseThrow())
                .as("al usuario sin sesión se le manda a autenticarse, no de vuelta a su aplicación")
                .endsWith("/oauth2/authorization/google")
                .doesNotContain("admin.mobile-americas.com");
    }

    /**
     * La cadena de cierre (@Order(2)) deniega por defecto todo lo que no sea
     * actuator ni authorization server. Sustituye a
     * SeguridadIT.una_ruta_mapeada_pero_no_declarada_exige_autenticacion, que se
     * fue con la emisión de la fase 1.
     *
     * Vale el mismo razonamiento que allí: pegarle a una ruta inexistente no
     * demuestra nada por sí solo, porque un .anyRequest().permitAll() daría
     * 404 igualmente -el despachador no encuentra handler- y la prueba pasaría
     * con y sin la denegación. Lo que discrimina es EXIGIR un rechazo de
     * seguridad: con permitAll saldría 404 y esta aserción fallaría.
     *
     * Desde la tarea 5 ese rechazo es la redirección al login (302), no un 401
     * ni un 403: esta cadena ya tiene un mecanismo de autenticación
     * (oauth2Login) y, con un solo proveedor registrado, su entry point manda
     * directo a Google sin pantalla de selección.
     *
     * Cliente propio y no TestRestTemplate, a diferencia de la versión
     * anterior de esta prueba: TestRestTemplate sigue las redirecciones, y
     * seguirlas desde aquí acaba llamando de verdad a accounts.google.com
     * -este contexto no registra el proveedor simulado- y devolviendo 200,
     * con lo que la prueba fallaba por una razón que no tiene nada que ver con
     * lo que comprueba.
     */
    @Test
    void una_ruta_fuera_del_authorization_server_exige_autenticacion() throws Exception {
        var r = get("/v1/lo-que-sea");

        assertThat(r.statusCode())
                .as("un 404 sería lo que devolvería un permitAll: no distingue")
                .isEqualTo(302);
        assertThat(r.headers().firstValue("Location").orElseThrow())
                .endsWith("/oauth2/authorization/google");
    }

    private HttpResponse<String> get(String path) throws Exception {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build()
                .send(HttpRequest.newBuilder(URI.create("http://localhost:" + puerto + path)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
    }
}
