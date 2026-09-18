package com.mobileamericas.authorization.oauth;

import com.mobileamericas.authorization.BaseIT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Base de las pruebas de integración del flujo OAuth: registra el proveedor
 * OIDC simulado y sabe recorrer el login sin navegador.
 *
 * Los helpers viven aquí, y no dentro de la prueba que los estrenó, porque el
 * validador de acceso y el flujo completo (tareas 7 y 8) los consumen tal
 * cual: duplicarlos sería mantener tres copias del mismo login.
 *
 * El proveedor se registra con {@code @DynamicPropertySource} y no en el yml:
 * {@code issuer-uri} se resuelve al CONSTRUIR el contexto -descargando el
 * documento de descubrimiento- y el puerto del simulado no se conoce hasta
 * arrancarlo. En el yml de integrationTest sólo está lo que no depende del
 * puerto (client-id, client-secret, scope).
 */
public abstract class BaseOauthIT extends BaseIT {

    /**
     * El reto PKCE que usa {@link #pedirAutorizacion(String, String)} cuando
     * quien llama no aporta uno: el par del apéndice B del RFC 7636 (verifier
     * {@code dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk}).
     *
     * No es decorativo: todo cliente de auth_app exige PKCE
     * (requireProofKey(true)), así que una petición a /oauth2/authorize sin
     * code_challenge se rechaza por 'invalid_request' ANTES de mirar si hay
     * sesión, y cualquier prueba sobre la autorización pasaría o fallaría por
     * el motivo equivocado.
     */
    protected static final String RETO_POR_DEFECTO = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    /**
     * Nunca sigue las redirecciones: todo lo que estas pruebas comprueban vive
     * en la cabecera Location, y seguirla la borraría (además de intentar
     * conectarse de verdad a https://admin.mobile-americas.com).
     */
    private static final HttpClient CLIENTE = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    @DynamicPropertySource
    static void proveedorSimulado(DynamicPropertyRegistry registro) {
        registro.add("spring.security.oauth2.client.provider.google.issuer-uri",
                () -> GoogleSimulado.arrancar().issuerUri());
    }

    /** El mismo registro (auth_app) contra el que /oauth2/authorize valida la redirección. */
    @Autowired
    protected RegisteredClientRepository clientes;

    @Value("${local.server.port}")
    protected int puerto;

    protected String urlBase() {
        return "http://localhost:" + puerto;
    }

    /** Recorre el login completo con Google y devuelve la cookie de la sesión establecida. */
    protected String iniciarSesionCon(String email) {
        return iniciarSesion(email, true);
    }

    /** Igual, pero el proveedor no da el email como verificado. */
    protected String iniciarSesionConEmailSinVerificar(String email) {
        return iniciarSesion(email, false);
    }

    /**
     * El login en los tres pasos que no necesitan HTML ni navegador, tal y como
     * los dejó preparados {@link GoogleSimulado}.
     *
     * @throws IllegalStateException si el login no llega a establecer sesión,
     *         con el cuerpo de la respuesta del servicio dentro del mensaje:
     *         es por ahí por donde las pruebas de rechazo leen el motivo, que
     *         sólo conoce el servidor.
     */
    private String iniciarSesion(String email, boolean emailVerificado) {
        // Paso 1: el servicio guarda la petición de autorización en una sesión
        // nueva y redirige al proveedor.
        var aGoogle = get(urlBase() + "/oauth2/authorization/google", null);
        var location = aGoogle.headers().firstValue("Location").orElseThrow(() -> new IllegalStateException(
                "GET /oauth2/authorization/google no redirigió a ningún proveedor (HTTP "
                        + aGoogle.statusCode() + "): sin oauth2Login no hay login que iniciar. "
                        + aGoogle.body()));
        var cookies = aplicarCookies(new LinkedHashMap<>(), aGoogle);

        // Paso 2: el simulado hace de Google y emite un código para esta identidad.
        var vuelta = GoogleSimulado.arrancar().callbackPara(location, email, emailVerificado);

        // Paso 3: con la cookie del paso 1 -sin ella Spring no encuentra la
        // petición guardada y no puede validar state ni nonce-, el servicio
        // canjea el código, pide userinfo y establece la sesión.
        var callback = get(vuelta, cabecera(cookies));
        if (callback.statusCode() != 302) {
            throw new IllegalStateException("el login no estableció sesión (HTTP "
                    + callback.statusCode() + "): " + callback.body());
        }
        // La protección contra fijación de sesión cambia el identificador al
        // autenticar, así que la cookie que vale es la del paso 3, no la del 1.
        return cabecera(aplicarCookies(cookies, callback));
    }

    /**
     * Pide un código de autorización con la sesión que trae la cookie.
     * Devuelve la respuesta SIN seguir la redirección: el Location intacto es
     * lo que afirman las pruebas del validador y del flujo completo.
     */
    protected ResponseEntity<String> pedirAutorizacion(String cookie, String clientId) {
        return pedirAutorizacion(cookie, clientId, RETO_POR_DEFECTO);
    }

    /** Igual, con un reto PKCE propio: quien vaya a canjear el código necesita su verifier. */
    protected ResponseEntity<String> pedirAutorizacion(String cookie, String clientId, String reto) {
        var url = urlBase() + "/oauth2/authorize?response_type=code"
                + "&client_id=" + codificar(clientId)
                + "&redirect_uri=" + codificar(redirectUriDe(clientId))
                + "&scope=openid"
                + "&code_challenge=" + codificar(reto)
                + "&code_challenge_method=S256";
        return comoResponseEntity(get(url, cookie));
    }

    /**
     * GET sin seguir redirecciones, con la cookie indicada si la hay.
     *
     * Accept: text/html porque quien recorre este flujo es un navegador, y el
     * entry point que manda al login está acotado a ese tipo: sin la cabecera,
     * el helper dependería de que un Accept ausente ('*&#47;*') siga contando
     * como compatible con text/html.
     */
    protected HttpResponse<String> get(String url, String cookie) {
        var peticion = HttpRequest.newBuilder(URI.create(url)).header("Accept", "text/html").GET();
        if (cookie != null) {
            peticion.header("Cookie", cookie);
        }
        try {
            return CLIENTE.send(peticion.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrumpido pidiendo " + url, e);
        }
    }

    protected static ResponseEntity<String> comoResponseEntity(HttpResponse<String> respuesta) {
        var builder = ResponseEntity.status(respuesta.statusCode());
        respuesta.headers().map().forEach((nombre, valores) -> {
            // Las pseudo-cabeceras de HTTP/2 (':status') no son cabeceras HTTP
            // válidas para HttpHeaders y harían fallar la conversión.
            if (!nombre.startsWith(":")) {
                builder.header(nombre, valores.toArray(String[]::new));
            }
        });
        return builder.body(respuesta.body());
    }

    /**
     * Aplica los Set-Cookie de una respuesta al tarro de cookies. Una cookie
     * con valor vacío es un borrado (así se cierra una sesión), no una cookie
     * más: guardarla dejaría viva la que el servidor acaba de invalidar.
     */
    private static Map<String, String> aplicarCookies(Map<String, String> cookies, HttpResponse<?> respuesta) {
        for (var setCookie : respuesta.headers().allValues("set-cookie")) {
            var par = setCookie.split(";", 2)[0];
            var igual = par.indexOf('=');
            if (igual <= 0) {
                continue;
            }
            var nombre = par.substring(0, igual).trim();
            var valor = par.substring(igual + 1).trim();
            if (valor.isEmpty() || "\"\"".equals(valor)) {
                cookies.remove(nombre);
            } else {
                cookies.put(nombre, valor);
            }
        }
        return cookies;
    }

    private static String cabecera(Map<String, String> cookies) {
        return cookies.entrySet().stream()
                .map(c -> c.getKey() + "=" + c.getValue())
                .collect(Collectors.joining("; "));
    }

    private String redirectUriDe(String clientId) {
        var cliente = clientes.findByClientId(clientId);
        if (cliente == null) {
            throw new IllegalArgumentException(
                    "auth_app no ofrece ningún cliente activo llamado '" + clientId + "'");
        }
        return cliente.getRedirectUris().iterator().next();
    }

    private static String codificar(String valor) {
        return URLEncoder.encode(valor, UTF_8);
    }
}
