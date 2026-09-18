package com.mobileamericas.authorization.oauth;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.LIST;

/**
 * El flujo entero de extremo a extremo -login federado, código con PKCE, canje
 * y token emitido de verdad- y la propiedad central del rediseño: un token de
 * una aplicación no vale en otra.
 *
 * Es la ÚNICA prueba de la fase que decodifica un JWT realmente emitido. El
 * customizador de claims (tarea 6) se prueba invocándolo a mano, y se cablea
 * por detección automática del framework: si ese bean dejara de cablearse, sus
 * pruebas unitarias seguirían todas en verde y el token real saldría sin
 * 'roles' ni 'permissions'. De ahí que aquí se afirmen los claims y no sólo
 * que el token existe.
 */
public abstract class FlujoCompletoIT extends BaseOauthIT {

    private static final SecureRandom ALEATORIO = new SecureRandom();
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void del_login_al_token_con_pkce() {
        var verifier = generarVerifier();
        var cookie = iniciarSesionCon("usuario1@pendiente.local");

        var code = extraerCodigo(pedirAutorizacion(cookie, "admin", retoDe(verifier)));
        var token = canjear(code, verifier, "admin");

        var claims = decodificar(token.get("access_token"));
        assertThat(claims.get("aud")).isEqualTo(List.of("admin"));
        assertThat(claims.get("permissions")).asInstanceOf(LIST).contains("usuarios:borrar");
        assertThat(token).containsKey("id_token");
        assertThat(token).doesNotContainKey("refresh_token");   // cliente público

        // El resto del contrato de claims, que ninguna otra prueba puede ver
        // porque ninguna otra llega a un token emitido por el framework.
        assertThat(claims).containsKeys("sub", "email", "roles", "permissions");
        // El 'sub' lo pone el framework con Authentication.getName(), que es el
        // email normalizado que fija UsuarioOidcService, NO el UUID de
        // auth_user. Se afirma aquí porque es el identificador con el que un
        // resource server va a auditar, y ninguna otra prueba lo ve.
        assertThat(claims.get("sub")).isEqualTo("usuario1@pendiente.local");
        assertThat(claims.get("email")).isEqualTo("usuario1@pendiente.local");
        assertThat(claims.get("roles")).asInstanceOf(LIST).containsExactly("admin");
        // admin@admin es el comodín '*:*'. Que aquí lleguen los 12 permisos
        // concretos de la app (3 recursos x 4 verbos) y NINGÚN comodín es lo
        // que demuestra que AccessGrant expandió antes de firmar: un resource
        // server estándar compara cadenas, no sabe interpretar '*'.
        assertThat(claims.get("permissions")).asInstanceOf(LIST)
                .hasSize(12)
                .doesNotContain("*:*", "*:borrar", "admin:usuarios:borrar");

        var identidad = decodificar(token.get("id_token"));
        assertThat(identidad.get("aud")).isEqualTo(List.of("admin"));
        assertThat(identidad.get("sub")).isEqualTo("usuario1@pendiente.local");
        assertThat(identidad.get("email")).isEqualTo("usuario1@pendiente.local");
        // Los permisos van SÓLO en el access token: un ID token es un documento
        // que el navegador puede guardar y que sobrevive horas a un cambio de rol.
        assertThat(identidad).doesNotContainKeys("roles", "permissions");
        // auth_user.full_name es NULL para usuario1 y el proveedor simulado no
        // manda avatar: un claim AUSENTE, no uno a null, que induciría a creer
        // que el dato se conoce y está vacío.
        assertThat(identidad).doesNotContainKeys("name", "picture");
    }

    @Test
    void el_canje_exige_el_verifier_correcto() {
        var cookie = iniciarSesionCon("usuario1@pendiente.local");
        var code = extraerCodigo(pedirAutorizacion(cookie, "admin", retoDe(generarVerifier())));

        assertThat(canjearEsperandoError(code, generarVerifier(), "admin"))
                .containsEntry("error", "invalid_grant");
    }

    /**
     * La propiedad central del rediseño: el token que emite auth para una
     * aplicación no sirve en otra, aunque quien lo lleva tenga cuenta en las
     * dos. usuario2 tiene admin@fgf y analyst@admin (ver V2__datos_iniciales.sql),
     * así que el token de fgf está firmado por el mismo emisor y con la misma
     * clave que uno de admin: lo único que lo distingue es el 'aud'.
     *
     * Por eso el decodificador se construye COMO LO HARÍA UN CONSUMIDOR REAL,
     * con el validador de audiencia que instala
     * spring.security.oauth2.resourceserver.jwt.audiences. Sin él, el token
     * de fgf se verifica sin problema -firma válida, emisor correcto, en
     * vigor- y esta prueba pasaría por el motivo equivocado, que es peor que
     * no tenerla.
     */
    @Test
    void un_token_de_una_app_no_vale_en_otra() {
        var token = tokenPara("usuario2@pendiente.local", "fgf");

        var decoderDeAdmin = decoderQueExige("admin");

        assertThatThrownBy(() -> decoderDeAdmin.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void el_logout_mata_la_sesion_sso_y_obliga_a_volver_a_autenticarse() {
        var cookie = iniciarSesionCon("usuario1@pendiente.local");
        // Con sesión viva, /authorize devuelve código sin preguntar nada.
        assertThat(pedirAutorizacion(cookie, "admin").getHeaders().getLocation().toString())
                .contains("code=");

        var salida = cerrarSesion(cookie, "admin");

        assertThat(salida.getHeaders().getLocation().toString())
                .startsWith("https://admin.mobile-americas.com/");
        // Y ahora la misma cookie ya no sirve: /authorize manda a Google.
        assertThat(pedirAutorizacion(cookie, "admin").getHeaders().getLocation().toString())
                .doesNotContain("code=")
                .contains("/oauth2/authorization/google");
    }

    /**
     * La otra mitad del logout, y pesa tanto como la primera: una lista de
     * redirecciones de salida sin validar es un redirect abierto, servido
     * desde la pantalla que el usuario acaba de reconocer como fiable.
     *
     * Y no basta por sí sola: si el mapeo de post_logout_redirect_uris se
     * rompiera y la lista del cliente quedara VACÍA, un dominio ajeno también
     * se rechazaría y esta prueba seguiría verde. Lo que cierra ese hueco es
     * la prueba de arriba, que exige que la redirección registrada SÍ funcione.
     */
    @Test
    void el_logout_no_acepta_una_redireccion_no_registrada() {
        var cookie = iniciarSesionCon("usuario1@pendiente.local");

        // post_logout_redirect_uri fuera de auth_app: no debe redirigir ahí.
        assertThat(cerrarSesionHacia(cookie, "admin", "https://evil.example/")
                .getHeaders().getLocation())
                .satisfiesAnyOf(
                        loc -> assertThat(loc).isNull(),
                        loc -> assertThat(loc.toString()).doesNotContain("evil.example"));
    }

    // --- PKCE ------------------------------------------------------------

    /**
     * 32 bytes de entropía en base64url sin relleno: el máximo que admite el
     * RFC 7636 para el verifier, y el mismo formato que usa el framework.
     * Uno por prueba, no una constante compartida: dos canjes con el mismo
     * verifier no distinguirían "el reto se comprobó" de "el reto da igual".
     */
    protected static String generarVerifier() {
        var bytes = new byte[32];
        ALEATORIO.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** El reto S256 del verifier, que es el único método que acepta el registro. */
    protected static String retoDe(String verifier) {
        try {
            var resumen = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(resumen);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("esta JVM no tiene SHA-256", e);
        }
    }

    // --- Código y canje --------------------------------------------------

    /**
     * El 'code' de la Location con la que /oauth2/authorize devuelve al
     * cliente. Falla con la Location entera dentro del mensaje si no lo trae:
     * ahí es donde viaja el 'error' de OAuth que explica por qué no hay código.
     */
    protected String extraerCodigo(ResponseEntity<String> autorizacion) {
        var location = autorizacion.getHeaders().getLocation();
        if (location == null) {
            throw new IllegalStateException("la autorización no redirigió a ningún sitio (HTTP "
                    + autorizacion.getStatusCode() + "): " + autorizacion.getBody());
        }
        var code = parametros(location.getRawQuery()).get("code");
        if (code == null) {
            throw new IllegalStateException("la autorización no emitió código: " + location);
        }
        return code;
    }

    /** Canjea el código y devuelve la respuesta del endpoint de token. */
    protected Map<String, String> canjear(String code, String verifier, String clientId) {
        var respuesta = pedirToken(code, verifier, clientId);
        if (respuesta.statusCode() != 200) {
            throw new IllegalStateException("el canje falló (HTTP " + respuesta.statusCode()
                    + "): " + respuesta.body());
        }
        return leerJson(respuesta.body());
    }

    /**
     * Igual, pero para el canje que NO debe emitir nada: devuelve el cuerpo
     * del error. Si el endpoint responde 200, revienta aquí en vez de dejar
     * que la aserción falle por "no contiene la clave error", que no diría que
     * lo que pasó es que se emitió un token.
     */
    protected Map<String, String> canjearEsperandoError(String code, String verifier, String clientId) {
        var respuesta = pedirToken(code, verifier, clientId);
        if (respuesta.statusCode() == 200) {
            throw new IllegalStateException("el canje SÍ emitió token cuando no debía: "
                    + respuesta.body());
        }
        return leerJson(respuesta.body());
    }

    /**
     * El access token de un usuario para una app, recorriendo el flujo entero
     * desde el login.
     */
    protected String tokenPara(String email, String clientId) {
        return tokensDe(iniciarSesionCon(email), clientId).get("access_token");
    }

    /** Los tokens que se lleva la sesión que trae la cookie, para esa app. */
    private Map<String, String> tokensDe(String cookie, String clientId) {
        var verifier = generarVerifier();
        var code = extraerCodigo(pedirAutorizacion(cookie, clientId, retoDe(verifier)));
        return canjear(code, verifier, clientId);
    }

    /**
     * POST /oauth2/token sin credenciales de cliente: todos los clientes de
     * auth_app son públicos (SPAs), y lo que prueba que quien canjea es quien
     * pidió el código es el code_verifier, no un secreto.
     */
    private HttpResponse<String> pedirToken(String code, String verifier, String clientId) {
        return postFormulario(urlBase() + "/oauth2/token", Map.of(
                "grant_type", "authorization_code",
                "code", code,
                "redirect_uri", redirectUriDe(clientId),
                "client_id", clientId,
                "code_verifier", verifier));
    }

    // --- Decodificación --------------------------------------------------

    /**
     * Los claims de un JWT emitido por el servicio, verificando firma, emisor
     * y vigencia pero SIN mirar la audiencia: quien decodifica aquí es la
     * prueba que quiere leer lo que hay dentro, no el resource server de una
     * aplicación concreta. Ese es {@link #decoderQueExige(String)}.
     */
    protected Map<String, Object> decodificar(String token) {
        return decoderQue(null).decode(token).getClaims();
    }

    /**
     * El decodificador de un resource server que sólo acepta tokens suyos,
     * construido como lo construye Spring Boot a partir de
     * {@code spring.security.oauth2.resourceserver.jwt.audiences}: los
     * validadores por defecto del emisor MÁS un JwtClaimValidator sobre 'aud'.
     *
     * Reconstruirlo aquí, y no dar por bueno un NimbusJwtDecoder pelado, es la
     * diferencia entre probar el aislamiento entre aplicaciones y probar que
     * la firma es válida: un decodificador sin el validador de audiencia
     * acepta el token de CUALQUIER app de este emisor.
     */
    protected JwtDecoder decoderQueExige(String clientId) {
        return decoderQue(new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD, audiencia -> audiencia != null && audiencia.contains(clientId)));
    }

    /**
     * Las dos claves que necesita un consumidor -jwks_uri e issuer- salen del
     * documento de descubrimiento, no de una constante: es de ahí de donde las
     * saca un consumidor real, y así la prueba no fija por su cuenta un emisor
     * que el framework deriva de la petición.
     */
    private JwtDecoder decoderQue(OAuth2TokenValidator<Jwt> ademasDeLoHabitual) {
        var metadatos = descubrimiento();
        var porDefecto = JwtValidators.createDefaultWithIssuer((String) metadatos.get("issuer"));

        var decoder = NimbusJwtDecoder.withJwkSetUri((String) metadatos.get("jwks_uri")).build();
        decoder.setJwtValidator(ademasDeLoHabitual == null
                ? porDefecto
                : new DelegatingOAuth2TokenValidator<>(porDefecto, ademasDeLoHabitual));
        return decoder;
    }

    // --- Logout ----------------------------------------------------------

    /**
     * Cierra la sesión SSO por el end_session_endpoint, hacia la redirección
     * que auth_app tiene registrada para esa app.
     */
    protected ResponseEntity<String> cerrarSesion(String cookie, String clientId) {
        return cerrarSesionHacia(cookie, clientId, postLogoutRegistradaDe(clientId));
    }

    /**
     * Igual, hacia donde diga quien llama: es lo que permite comprobar que una
     * redirección NO registrada no se sirve.
     *
     * El id_token_hint no es adorno: sin él el endpoint no sabe qué cliente
     * cierra sesión y no tiene contra qué lista validar la redirección. Se
     * obtiene recorriendo el flujo con la misma cookie, que es exactamente lo
     * que ha hecho la SPA antes de ofrecer el botón de salir.
     */
    protected ResponseEntity<String> cerrarSesionHacia(String cookie, String clientId, String destino) {
        var idToken = tokensDe(cookie, clientId).get("id_token");
        var url = (String) descubrimiento().get("end_session_endpoint")
                + "?id_token_hint=" + codificar(idToken)
                + "&client_id=" + codificar(clientId)
                + "&post_logout_redirect_uri=" + codificar(destino);
        return comoResponseEntity(get(url, cookie));
    }

    /**
     * La redirección de salida que auth_app tiene registrada para la app, leída
     * del mismo registro contra el que valida el framework.
     *
     * Falla con un mensaje propio si no hay ninguna: una lista vacía rechaza
     * cualquier destino, también uno legítimo, y sin este aviso el síntoma
     * sería un 400 de OAuth que no dice nada de la columna que lo causó.
     */
    private String postLogoutRegistradaDe(String clientId) {
        var registradas = clientes.findByClientId(clientId).getPostLogoutRedirectUris();
        if (registradas.isEmpty()) {
            throw new IllegalStateException("el cliente '" + clientId + "' no tiene ninguna "
                    + "post_logout_redirect_uri registrada en auth_app: nadie podría salir a su sitio");
        }
        return registradas.iterator().next();
    }

    // --- Auxiliares HTTP y JSON ------------------------------------------

    /** El documento de descubrimiento ya parseado. */
    private Map<String, Object> descubrimiento() {
        var respuesta = get(urlBase() + "/.well-known/openid-configuration", null);
        if (respuesta.statusCode() != 200) {
            throw new IllegalStateException("el documento de descubrimiento no se sirve (HTTP "
                    + respuesta.statusCode() + "): " + respuesta.body());
        }
        return JSON.readValue(respuesta.body(), new TypeReference<Map<String, Object>>() {});
    }

    /**
     * POST de formulario con el mismo cliente HTTP que el resto de la suite
     * (el que no sigue redirecciones), y Accept: application/json porque quien
     * canjea un código es código, no un navegador.
     */
    private HttpResponse<String> postFormulario(String url, Map<String, String> campos) {
        var cuerpo = campos.entrySet().stream()
                .map(campo -> codificar(campo.getKey()) + "=" + codificar(campo.getValue()))
                .collect(Collectors.joining("&"));
        var peticion = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(cuerpo, UTF_8))
                .build();
        try {
            return CLIENTE.send(peticion, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrumpido pidiendo " + url, e);
        }
    }

    /**
     * La respuesta del endpoint de token como mapa de cadenas: 'expires_in' es
     * un número en el JSON y Jackson lo convierte, lo que evita tener que
     * castear en cada aserción el único campo que no se mira.
     */
    private static Map<String, String> leerJson(String cuerpo) {
        return JSON.readValue(cuerpo, new TypeReference<Map<String, String>>() {});
    }

    /** Los parámetros de una query string, ya decodificados. */
    private static Map<String, String> parametros(String consulta) {
        var parametros = new LinkedHashMap<String, String>();
        if (consulta == null || consulta.isBlank()) {
            return parametros;
        }
        for (var par : consulta.split("&")) {
            var igual = par.indexOf('=');
            if (igual > 0) {
                parametros.put(URLDecoder.decode(par.substring(0, igual), UTF_8),
                        URLDecoder.decode(par.substring(igual + 1), UTF_8));
            }
        }
        return parametros;
    }
}
