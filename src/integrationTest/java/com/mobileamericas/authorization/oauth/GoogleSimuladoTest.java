package com.mobileamericas.authorization.oauth;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * El proveedor simulado es infraestructura de las cuatro tareas siguientes: si
 * su documento de descubrimiento o sus ID token traen un detalle mal, el fallo
 * aparece como un login roto en otra tarea, sin mensaje útil. Por eso estas
 * pruebas no comprueban "responde algo", sino las dos igualdades exactas que
 * Spring verifica y rechaza al menor desvío:
 *
 * <ul>
 *   <li>el {@code issuer} del descubrimiento y el {@code iss} de los ID token
 *       son la misma cadena que {@code issuerUri()}, puerto y barra final
 *       incluidos;</li>
 *   <li>el {@code nonce} del ID token es literalmente el que llegó en la
 *       peticion de autorización (Spring compara el hash que él mismo envió).</li>
 * </ul>
 *
 * No hay contexto de Spring aquí a propósito: el simulado tiene que poder
 * arrancar y consultarse antes de que exista uno.
 */
class GoogleSimuladoTest {

    private static final String CLIENTE = "cliente-google-de-pruebas";
    private static final String SECRETO = "secreto-de-pruebas";
    private static final String REDIRECT_URI = "http://localhost:34567/login/oauth2/code/google";

    private static GoogleSimulado google;

    private final HttpClient cliente = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();

    @BeforeAll
    static void arrancar() {
        google = GoogleSimulado.arrancarAislada();
    }

    @AfterAll
    static void parar() {
        google.parar();
    }

    @Test
    void sirve_descubrimiento_y_jwks_y_firma_tokens() throws Exception {
        var conf = cuerpo(get(google.issuerUri() + "/.well-known/openid-configuration"));
        assertThat(conf).contains("\"issuer\"").contains("\"jwks_uri\"");

        var metadatos = mapa(conf);
        assertThat(metadatos.get("issuer"))
                .as("Spring compara el issuer anunciado con el issuer-uri configurado y rechaza cualquier desvío")
                .isEqualTo(google.issuerUri());
        assertThat(metadatos)
                .containsEntry("authorization_endpoint", google.issuerUri() + "/oauth2/authorize")
                .containsEntry("token_endpoint", google.issuerUri() + "/oauth2/token")
                .containsEntry("userinfo_endpoint", google.issuerUri() + "/userinfo")
                .containsEntry("jwks_uri", google.issuerUri() + "/jwks");
        assertThat(metadatos)
                .as("nimbus exige estos tres campos para parsear los metadatos; sin ellos el contexto no arranca")
                .containsKeys("response_types_supported", "subject_types_supported",
                        "id_token_signing_alg_values_supported");

        var jwks = cuerpo(get(google.issuerUri() + "/jwks"));
        assertThat(jwks).contains("\"n\"").doesNotContain("\"d\"");

        @SuppressWarnings("unchecked")
        var claves = (List<Map<String, Object>>) mapa(jwks).get("keys");
        assertThat(claves).hasSize(1);
        assertThat(claves.getFirst())
                .as("sin kid ni alg, el verificador no sabe con qué clave comprobar la firma")
                .containsKeys("kid", "n", "e")
                .containsEntry("kty", "RSA")
                .containsEntry("alg", "RS256");
        assertThat(claves.getFirst().keySet())
                .as("ningún componente privado de la clave puede salir por el JWKS")
                .doesNotContainAnyElementsOf(Set.of("d", "p", "q", "dp", "dq", "qi"));

        var token = SignedJWT.parse(google.idTokenPara("alguien@ejemplo.com", true));
        var claims = token.getJWTClaimsSet();
        assertThat(claims.getStringClaim("email")).isEqualTo("alguien@ejemplo.com");
        assertThat(claims.getBooleanClaim("email_verified")).isTrue();
        assertThat(claims.getIssuer()).isEqualTo(google.issuerUri());
        assertThat(claims.getSubject()).isNotBlank();
        assertThat(claims.getAudience()).containsExactly(GoogleSimulado.AUDIENCIA_POR_DEFECTO);
        assertThat(claims.getIssueTime()).isNotNull();
        assertThat(claims.getExpirationTime().toInstant()).isAfter(Instant.now());
        assertThat(token.getHeader().getKeyID())
                .as("el kid de la firma tiene que ser el que publica el JWKS")
                .isEqualTo(claves.getFirst().get("kid"));
    }

    /**
     * El flujo que la tarea 5 necesita entero: nuestro servicio redirige al
     * simulado, el simulado devuelve un código al {@code redirect_uri}, y el
     * canje de ese código trae el ID token. Se comprueba aquí, sin Spring, para
     * que un fallo del simulado no aparezca disfrazado de fallo de SecurityConfig.
     */
    @Test
    void el_canje_del_codigo_devuelve_el_nonce_tal_cual_y_la_audiencia_del_cliente() throws Exception {
        var nonce = "nonce-" + UUID.randomUUID();
        var estado = "estado-" + UUID.randomUUID();

        var callback = google.callbackPara(urlDeAutorizacion(estado, nonce), "alguien@ejemplo.com", true);

        assertThat(callback).startsWith(REDIRECT_URI + "?");
        assertThat(parametro(callback, "state"))
                .as("sin el state de vuelta, Spring descarta la respuesta de autorización")
                .isEqualTo(estado);

        var respuesta = mapa(cuerpo(canjear(parametro(callback, "code"))));
        assertThat(respuesta).containsEntry("token_type", "Bearer");
        assertThat(respuesta.get("scope")).isEqualTo("openid email profile");

        var claims = SignedJWT.parse((String) respuesta.get("id_token")).getJWTClaimsSet();
        assertThat(claims.getStringClaim("nonce"))
                .as("Spring compara el nonce del ID token con el que envió: devolverlo tal cual no es opcional")
                .isEqualTo(nonce);
        assertThat(claims.getIssuer()).isEqualTo(google.issuerUri());
        assertThat(claims.getAudience())
                .as("la audiencia es el client-id de la petición de autorización, no un valor fijo")
                .containsExactly(CLIENTE);
        assertThat(claims.getStringClaim("email")).isEqualTo("alguien@ejemplo.com");
        assertThat(claims.getBooleanClaim("email_verified")).isTrue();

        // OidcUserService llama a userinfo cuando el scope trae 'email' o
        // 'profile', y rechaza el login si el 'sub' de userinfo no coincide con
        // el del ID token ("invalid_user_info_response").
        var usuario = mapa(cuerpo(get(google.issuerUri() + "/userinfo",
                "Authorization", "Bearer " + respuesta.get("access_token"))));
        assertThat(usuario.get("sub")).isEqualTo(claims.getSubject());
        assertThat(usuario)
                .containsEntry("email", "alguien@ejemplo.com")
                .containsEntry("email_verified", true);
    }

    @Test
    void un_email_sin_verificar_viaja_como_tal_en_el_id_token_y_en_userinfo() throws Exception {
        var callback = google.callbackPara(urlDeAutorizacion("estado", "nonce"), "sinverificar@ejemplo.com", false);

        var respuesta = mapa(cuerpo(canjear(parametro(callback, "code"))));
        var claims = SignedJWT.parse((String) respuesta.get("id_token")).getJWTClaimsSet();
        assertThat(claims.getBooleanClaim("email_verified")).isFalse();

        var usuario = mapa(cuerpo(get(google.issuerUri() + "/userinfo",
                "Authorization", "Bearer " + respuesta.get("access_token"))));
        assertThat(usuario).containsEntry("email_verified", false);
    }

    @Test
    void un_codigo_solo_se_canjea_una_vez() throws Exception {
        var codigo = parametro(google.callbackPara(urlDeAutorizacion("estado", "nonce"),
                "alguien@ejemplo.com", true), "code");

        assertThat(canjear(codigo).statusCode()).isEqualTo(200);

        var reintento = canjear(codigo);
        assertThat(reintento.statusCode()).isEqualTo(400);
        assertThat(reintento.body()).contains("invalid_grant");
    }

    @Test
    void un_access_token_desconocido_no_obtiene_userinfo() throws Exception {
        assertThat(get(google.issuerUri() + "/userinfo", "Authorization", "Bearer inventado").statusCode())
                .isEqualTo(401);
    }

    /**
     * Una URL de autorización que no apunte a este simulado es casi siempre la
     * Location equivocada (la del login propio, por ejemplo). Fallar aquí, con
     * mensaje, ahorra depurar un login que no llega a empezar.
     */
    @Test
    void una_url_de_autorizacion_ajena_se_rechaza_con_mensaje() {
        assertThatThrownBy(() -> google.callbackPara(
                "http://localhost:34567/oauth2/authorization/google", "alguien@ejemplo.com", true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(google.issuerUri());
    }

    /**
     * El puerto del simulado se inyecta con {@code @DynamicPropertySource} desde
     * una instancia compartida por toda la suite: dos llamadas no pueden dejar
     * dos servidores, ni dos issuer distintos, ni fallar.
     */
    @Test
    void arrancar_dos_veces_devuelve_el_mismo_servidor() {
        var primera = GoogleSimulado.arrancar();
        var segunda = GoogleSimulado.arrancar();

        assertThat(segunda).isSameAs(primera);
        assertThat(segunda.issuerUri()).isEqualTo(primera.issuerUri());
    }

    /**
     * Parar la instancia compartida dejaría a los contextos de Spring ya
     * cacheados apuntando a un puerto muerto, y el login fallaría en pruebas
     * que no han tocado nada. Mejor un error inmediato que ese.
     */
    @Test
    void la_instancia_compartida_no_se_puede_parar() {
        assertThatThrownBy(() -> GoogleSimulado.arrancar().parar())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("compartida");
    }

    @Test
    void parar_cierra_el_puerto() throws Exception {
        var propia = GoogleSimulado.arrancarAislada();
        var uri = propia.issuerUri();
        assertThat(get(uri + "/jwks").statusCode()).isEqualTo(200);

        propia.parar();

        assertThatThrownBy(() -> get(uri + "/jwks")).isInstanceOf(IOException.class);
    }

    /**
     * Ésta es la prueba que le ahorra horas a la tarea 5: es el propio Spring
     * -y el nimbus que lleva debajo- quien lee el documento de descubrimiento
     * al construir el contexto a partir de issuer-uri, y rechaza con un fallo
     * de arranque si falta cualquiera de los campos obligatorios. Se comprueba
     * aquí, sin contexto, para que el error salga en esta tarea y no disfrazado
     * de configuración mal puesta en otra.
     */
    @Test
    void spring_construye_el_registro_del_cliente_desde_el_descubrimiento() {
        var registro = ClientRegistrations.fromIssuerLocation(google.issuerUri())
                .registrationId("google")
                .clientId(CLIENTE)
                .clientSecret(SECRETO)
                .build();

        var proveedor = registro.getProviderDetails();
        assertThat(proveedor.getIssuerUri()).isEqualTo(google.issuerUri());
        assertThat(proveedor.getAuthorizationUri()).isEqualTo(google.issuerUri() + "/oauth2/authorize");
        assertThat(proveedor.getTokenUri()).isEqualTo(google.issuerUri() + "/oauth2/token");
        assertThat(proveedor.getJwkSetUri()).isEqualTo(google.issuerUri() + "/jwks");
        assertThat(proveedor.getUserInfoEndpoint().getUri()).isEqualTo(google.issuerUri() + "/userinfo");
        assertThat(registro.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(registro.getClientAuthenticationMethod())
                .as("el simulado anuncia client_secret_basic: es el método con el que hay que leer el client_id")
                .isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    private String urlDeAutorizacion(String estado, String nonce) {
        return google.issuerUri() + "/oauth2/authorize?response_type=code"
                + "&client_id=" + CLIENTE
                + "&scope=" + URLEncoder.encode("openid email profile", UTF_8)
                + "&state=" + estado
                + "&nonce=" + nonce
                + "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, UTF_8);
    }

    /**
     * Canjea como canjea el cliente de Spring para un proveedor con secreto:
     * client_secret_basic, con el client_id en la cabecera Authorization y NO en
     * el cuerpo. De ahí que la audiencia del ID token tenga que salir del
     * client_id de la petición de autorización.
     */
    private HttpResponse<String> canjear(String codigo) throws Exception {
        var basic = Base64.getEncoder().encodeToString((CLIENTE + ":" + SECRETO).getBytes(UTF_8));
        var cuerpo = "grant_type=authorization_code&code=" + codigo
                + "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, UTF_8);
        return cliente.send(HttpRequest.newBuilder(URI.create(google.issuerUri() + "/oauth2/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .header("Authorization", "Basic " + basic)
                        .POST(HttpRequest.BodyPublishers.ofString(cuerpo))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String uri, String... cabeceras) throws Exception {
        var peticion = HttpRequest.newBuilder(URI.create(uri));
        for (int i = 0; i < cabeceras.length; i += 2) {
            peticion.header(cabeceras[i], cabeceras[i + 1]);
        }
        return cliente.send(peticion.GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private String cuerpo(HttpResponse<String> respuesta) {
        assertThat(respuesta.statusCode()).isEqualTo(200);
        assertThat(respuesta.headers().firstValue("Content-Type")).hasValue("application/json");
        return respuesta.body();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mapa(String cuerpo) {
        return (Map<String, Object>) json.readValue(cuerpo, Map.class);
    }

    /** getRawQuery, no getQuery: sobre la cadena ya decodificada no se puede separar. */
    private String parametro(String url, String nombre) {
        return Arrays.stream(URI.create(url).getRawQuery().split("&"))
                .filter(p -> p.startsWith(nombre + "="))
                .map(p -> URLDecoder.decode(p.substring(nombre.length() + 1), UTF_8))
                .findFirst()
                .orElseThrow(() -> new AssertionError("falta el parámetro " + nombre + " en " + url));
    }
}
