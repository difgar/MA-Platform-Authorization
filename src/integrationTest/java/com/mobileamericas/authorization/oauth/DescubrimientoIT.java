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
     * exige un usuario autenticado: sin sesión no se emite ningún código.
     *
     * No prueba el framework, prueba una línea NUESTRA. init() del configurer
     * no llama a authorizeHttpRequests, así que si SecurityConfig no declara
     * anyRequest().authenticated() en esa cadena nadie deniega esta petición:
     * comprobado quitando la línea, la respuesta pasa de 401 a
     * 302 https://admin.mobile-americas.com/callback?error=invalid_request&
     * error_description=OAuth%202.0%20Parameter%3A%20principal. Es decir, al
     * usuario sin sesión lo devuelven a su aplicación con un error en vez de
     * mandarlo a un login. Esta prueba distingue exactamente esos dos
     * resultados.
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
                .as("sin anyRequest().authenticated() esto sería un 302 de vuelta a la aplicación")
                .isEqualTo(401);
        assertThat(r.headers().firstValue("Location"))
                .as("nada debe volver a la aplicación mientras no haya sesión")
                .isEmpty();
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
     * 401 o 403, no un código fijo: cuál de los dos sale lo decide el
     * AuthenticationEntryPoint de esa cadena, que hoy no tiene ningún mecanismo
     * configurado (403) y en la tarea 5 pasará a redirigir al login con Google.
     * Lo que esta prueba vigila es que no se cuele nada sin autenticar, no cuál
     * de los rechazos toca en cada momento del rediseño.
     */
    @Test
    void una_ruta_fuera_del_authorization_server_exige_autenticacion() {
        var r = http.getForEntity("/v1/lo-que-sea", String.class);

        assertThat(r.getStatusCode())
                .as("un 404 sería lo que devolvería un permitAll: no distingue")
                .isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
    }

    private HttpResponse<String> get(String path) throws Exception {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build()
                .send(HttpRequest.newBuilder(URI.create("http://localhost:" + puerto + path)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
    }
}
