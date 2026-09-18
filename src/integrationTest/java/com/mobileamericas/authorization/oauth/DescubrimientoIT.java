package com.mobileamericas.authorization.oauth;

import com.mobileamericas.authorization.BaseIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
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
@TestPropertySource(properties =
        "spring.security.oauth2.authorizationserver.issuer=https://emisor.fijado.example/authorization-api")
public abstract class DescubrimientoIT extends BaseIT {

    /**
     * Un emisor que NO es el del servidor de la prueba, y ahí está la gracia.
     *
     * El emisor de producción se fija con esta misma propiedad en
     * application.yml, y hasta la ronda 1 de revisión no lo cubría nada: el
     * fichero de configuración de esta suite REEMPLAZA al principal, así que
     * el valor real nunca se carga aquí. De ahí se concluyó -mal, y estaba
     * escrito como si fuera imposible- que no se podía cubrir. Lo que no se
     * puede cubrir aquí es el VALOR de producción; el MECANISMO sí: si se
     * declara un emisor cualquiera y el documento de descubrimiento sale con
     * él en vez de con http://localhost:{puerto}, Spring Authorization Server
     * está respetando la propiedad, que es lo que hay que saber. El valor lo
     * cubre EmisorDeProduccionTest (src/test, sin Spring ni Docker).
     *
     * El dominio es de los reservados por el RFC 2606 para ejemplos: no
     * resuelve y ninguna prueba lo llama.
     *
     * Se inyecta en vez de repetirse como constante para que no haya dos
     * copias del mismo literal que nada compare -el patrón que esta fase
     * entera existe para quitar-; una anotación de clase no puede referirse a
     * un campo de su propia clase.
     */
    @Value("${spring.security.oauth2.authorizationserver.issuer}")
    String emisorDeclarado;

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
     * El emisor declarado manda sobre el host de la petición.
     *
     * Sin la propiedad, Spring Authorization Server deriva el emisor de cada
     * petición entrante (AuthorizationServerContextFilter). En producción eso
     * es el host del pod detrás del ingress: los tokens saldrían con un 'iss'
     * que rechaza todo consumidor que valide el emisor, y este documento
     * anunciaría endpoints inalcanzables desde fuera del clúster.
     *
     * Se afirma sobre CADA endpoint y no sólo sobre 'issuer': quien configura
     * su resource server con issuer-uri descubre por aquí dónde está el JWKS,
     * así que un 'issuer' correcto con un 'jwks_uri' apuntando al pod sería
     * igual de inútil. Y se afirma que el documento entero no menciona
     * localhost:{puerto}, que es exactamente lo que volvería a salir si
     * alguien retirara la propiedad, Boot la renombrara, o un
     * AuthorizationServerSettings propio la dejara sin efecto.
     */
    @Test
    void el_emisor_declarado_manda_sobre_el_host_de_la_peticion() {
        var r = http.getForObject("/.well-known/openid-configuration", String.class);

        @SuppressWarnings("unchecked")
        var metadatos = (Map<String, Object>) new ObjectMapper().readValue(r, Map.class);

        assertThat(metadatos).containsEntry("issuer", emisorDeclarado);
        assertThat(List.of("authorization_endpoint", "token_endpoint", "jwks_uri",
                        "userinfo_endpoint", "end_session_endpoint"))
                .allSatisfy(endpoint -> assertThat((String) metadatos.get(endpoint))
                        .as("%s tiene que colgar del emisor declarado, no del host de la petición",
                                endpoint)
                        .startsWith(emisorDeclarado + "/"));
        assertThat(r)
                .as("nada del documento puede salir con el host del servidor de la prueba: "
                        + "es justo lo que se anunciaría si la propiedad dejara de leerse")
                .doesNotContain("localhost:" + puerto);
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
     *
     * Ésta es la rama de NAVEGADOR (Accept: text/html, ver el helper get). La
     * de cliente de máquina es la prueba de más abajo, y responde otra cosa a
     * propósito.
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
     * La otra rama del entry point, y la que motivó setIgnoredMediaTypes:
     * quien no pide HTML no acaba en el login.
     *
     * Un cliente de máquina -sin cabecera Accept, que es lo que manda curl y
     * lo que se resuelve como el comodín- debe recibir el 401 del
     * HttpStatusEntryPoint que registra el configurer. Sin ese
     * setIgnoredMediaTypes(ALL), el comodín se considera compatible con
     * text/html y esta misma petición recibía 302 hacia Google y una cookie de
     * sesión: un cliente de token no sabe qué hacer con eso, y el diagnóstico
     * apunta al sitio equivocado. Comprobado quitando la línea: 302 + cookie.
     *
     * La aserción sobre Set-Cookie es la mitad que importa tanto como el
     * código: lo que se estaba regalando era una sesión, no sólo un status
     * equivocado.
     */
    @Test
    void authorize_sin_sesion_y_sin_pedir_html_no_va_al_login() throws Exception {
        var r = get("/oauth2/authorize?response_type=code&client_id=admin"
                + "&redirect_uri=https%3A%2F%2Fadmin.mobile-americas.com%2Fcallback&scope=openid"
                + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                + "&code_challenge_method=S256", null);

        assertThat(r.statusCode()).isEqualTo(401);
        assertThat(r.headers().firstValue("Location"))
                .as("a un cliente que no pide HTML no se le manda a ninguna pantalla")
                .isEmpty();
        assertThat(r.headers().allValues("set-cookie"))
                .as("y tampoco se le estrena una sesión que nadie le ha pedido")
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

    /**
     * Como un navegador: Accept: text/html. La cabecera NO es decorativa
     * -antes esta prueba no la mandaba y recorría la rama comodín del matcher
     * en vez de la de navegador, así que no verificaba el caso que el entry
     * point pretende cubrir-.
     */
    private HttpResponse<String> get(String path) throws Exception {
        return get(path, "text/html");
    }

    /** Sin cabecera Accept si 'accept' es null: es lo que manda un cliente de máquina. */
    private HttpResponse<String> get(String path, String accept) throws Exception {
        var peticion = HttpRequest.newBuilder(URI.create("http://localhost:" + puerto + path)).GET();
        if (accept != null) {
            peticion.header("Accept", accept);
        }
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build()
                .send(peticion.build(), HttpResponse.BodyHandlers.ofString());
    }
}
