package com.mobileamericas.authorization.oauth;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Proveedor OIDC falso con el que se prueba el login federado: los tests no
 * pueden llamar a Google. Sirve descubrimiento, JWKS, canje de código y
 * userinfo sobre el {@link HttpServer} del JDK -sin añadir WireMock- y firma
 * los ID token con una clave RSA generada en el arranque.
 *
 * <p>Ciclo de vida: {@link #arrancar()} devuelve una instancia compartida por
 * toda la suite, arrancada una sola vez. Tiene que ser así porque
 * {@code spring.security.oauth2.client.provider.google.issuer-uri} se resuelve
 * al CONSTRUIR el contexto de Spring -descargando el documento de
 * descubrimiento-, así que el servidor debe existir antes, y su puerto se
 * inyecta con {@code @DynamicPropertySource} desde {@link #issuerUri()}.
 *
 * <p>Uso previsto desde la clase base de integración:
 * <pre>{@code
 * @DynamicPropertySource
 * static void proveedorSimulado(DynamicPropertyRegistry registro) {
 *     registro.add("spring.security.oauth2.client.provider.google.issuer-uri",
 *             () -> GoogleSimulado.arrancar().issuerUri());
 * }
 * }</pre>
 *
 * <p>Y el login, sin navegador: pedir {@code /oauth2/authorization/google} sin
 * seguir la redirección, pasar la {@code Location} a
 * {@link #callbackPara(String, String, boolean)} y pedir la URL que devuelve.
 */
public final class GoogleSimulado {

    /**
     * Audiencia de los ID token firmados con {@link #idTokenPara(String, boolean)},
     * que se usa fuera del flujo y por tanto no tiene ninguna petición de
     * autorización que la fije. En el flujo completo la audiencia es el
     * {@code client_id} de esa petición.
     */
    public static final String AUDIENCIA_POR_DEFECTO = "cliente-google-simulado";

    private static final Duration VIGENCIA = Duration.ofMinutes(5);

    /** Guardada por el monitor de la clase; ver {@link #arrancar()}. */
    private static GoogleSimulado compartida;

    private final HttpServer servidor;
    private final String issuer;
    private final RSAKey clave;
    private final ObjectMapper json = new ObjectMapper();
    private final SecureRandom aleatorio = new SecureRandom();

    /** Códigos de autorización pendientes de canje, y access token ya emitidos. */
    private final Map<String, Sesion> porCodigo = new ConcurrentHashMap<>();
    private final Map<String, Sesion> porAccessToken = new ConcurrentHashMap<>();

    /**
     * Lo que el simulado recuerda de un login: la identidad, y lo que pidió la
     * petición de autorización. El {@code nonce} se guarda porque el ID token
     * debe devolverlo TAL CUAL llegó (Spring compara ese valor con el hash que
     * él mismo envió; cualquier otra cosa es un fallo de login sin mensaje
     * útil), y el {@code scope} porque de lo que devuelva el canje depende que
     * {@code OidcUserService} llegue a pedir userinfo.
     */
    private record Sesion(String sub, String email, boolean emailVerificado,
                          String nonce, String audiencia, String scope) {
    }

    /**
     * La instancia compartida por toda la suite. Idempotente: llamarla dos
     * veces no levanta dos servidores ni falla.
     */
    public static synchronized GoogleSimulado arrancar() {
        if (compartida == null) {
            compartida = arrancarAislada();
        }
        return compartida;
    }

    /**
     * Una instancia independiente, con su propio puerto y su propia clave, para
     * el test que necesita arrancarla y pararla. Todo lo demás usa
     * {@link #arrancar()}.
     */
    public static GoogleSimulado arrancarAislada() {
        try {
            return new GoogleSimulado();
        } catch (Exception e) {
            throw new IllegalStateException("no se pudo arrancar el proveedor OIDC simulado", e);
        }
    }

    private GoogleSimulado() throws Exception {
        this.clave = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .generate();

        // Puerto 0: lo elige el sistema. Uno fijo rompe la ejecución en
        // paralelo y en CI. Sólo loopback: ninguna prueba sale a la red.
        this.servidor = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        // Hilos virtuales (demonio): un manejador colgado no impide que la JVM
        // de los tests termine.
        this.servidor.setExecutor(Executors.newVirtualThreadPerTaskExecutor());

        // La IP literal, no el nombre 'localhost': el servidor está atado a la
        // dirección de loopback concreta, y 'localhost' puede resolverse a ::1
        // mientras el socket escucha en 127.0.0.1. Además garantiza que el
        // issuer anunciado sea alcanzable sin depender del DNS de la máquina.
        this.issuer = "http://" + InetAddress.getLoopbackAddress().getHostAddress()
                + ":" + servidor.getAddress().getPort();

        servidor.createContext("/.well-known/openid-configuration", this::descubrimiento);
        servidor.createContext("/jwks", this::jwks);
        servidor.createContext("/oauth2/authorize", this::autorizar);
        servidor.createContext("/oauth2/token", this::token);
        servidor.createContext("/userinfo", this::userinfo);
        servidor.start();
    }

    /**
     * El emisor que registrar como proveedor. Es consultable sin contexto de
     * Spring, y es la cadena EXACTA -puerto incluido, sin barra final- que
     * anuncia el descubrimiento y que llevan los ID token en {@code iss}:
     * Spring compara ambas con el {@code issuer-uri} configurado y rechaza
     * cualquier diferencia.
     */
    public String issuerUri() {
        return issuer;
    }

    /** Firma un ID token fuera del flujo, con {@link #AUDIENCIA_POR_DEFECTO}. */
    public String idTokenPara(String email, boolean emailVerificado) {
        return firmar(new Sesion(subDe(email), email, emailVerificado, null, AUDIENCIA_POR_DEFECTO, null));
    }

    /**
     * Hace de Google ante una petición de autorización: emite un código para la
     * identidad indicada y devuelve la URL de vuelta al cliente, con el
     * {@code code} y el {@code state} que éste envió.
     *
     * @param urlDeAutorizacion la {@code Location} con la que nuestro servicio
     *                          redirige al proveedor
     * @return la URL del callback del cliente, para pedirla tal cual
     */
    public String callbackPara(String urlDeAutorizacion, String email, boolean emailVerificado) {
        if (!urlDeAutorizacion.startsWith(issuer + "/oauth2/authorize")) {
            throw new IllegalArgumentException("esta URL no es una petición de autorización a "
                    + issuer + "/oauth2/authorize, así que no la emitió el cliente para este proveedor: "
                    + urlDeAutorizacion);
        }
        var parametros = parametros(URI.create(urlDeAutorizacion).getRawQuery());
        var redirectUri = parametros.get("redirect_uri");
        if (redirectUri == null) {
            throw new IllegalArgumentException("la petición de autorización no trae redirect_uri: "
                    + urlDeAutorizacion);
        }

        var codigo = valorOpaco();
        porCodigo.put(codigo, new Sesion(subDe(email), email, emailVerificado, parametros.get("nonce"),
                parametros.getOrDefault("client_id", AUDIENCIA_POR_DEFECTO), parametros.get("scope")));

        var vuelta = new StringBuilder(redirectUri)
                .append(redirectUri.contains("?") ? '&' : '?')
                .append("code=").append(URLEncoder.encode(codigo, UTF_8));
        if (parametros.get("state") != null) {
            vuelta.append("&state=").append(URLEncoder.encode(parametros.get("state"), UTF_8));
        }
        return vuelta.toString();
    }

    /**
     * Para este servidor y libera su puerto. La instancia compartida no se para:
     * los contextos de Spring ya cacheados guardan su puerto en el
     * {@code issuer-uri} con el que se construyeron, y pararlo haría fallar el
     * login en pruebas que no han tocado nada.
     */
    public void parar() {
        synchronized (GoogleSimulado.class) {
            if (this == compartida) {
                throw new IllegalStateException("la instancia compartida de GoogleSimulado no se para: "
                        + "los contextos de Spring cacheados siguen usando su puerto");
            }
        }
        servidor.stop(0);
    }

    // --- Endpoints -------------------------------------------------------

    /**
     * Los campos no son decorativos: nimbus exige {@code issuer},
     * {@code response_types_supported}, {@code subject_types_supported} y
     * {@code id_token_signing_alg_values_supported} para parsear los metadatos,
     * y Spring exige que {@code grant_types_supported} incluya
     * {@code authorization_code}. Sin uno de ellos el contexto no arranca.
     */
    private void descubrimiento(HttpExchange intercambio) throws IOException {
        var metadatos = new LinkedHashMap<String, Object>();
        metadatos.put("issuer", issuer);
        metadatos.put("authorization_endpoint", issuer + "/oauth2/authorize");
        metadatos.put("token_endpoint", issuer + "/oauth2/token");
        metadatos.put("userinfo_endpoint", issuer + "/userinfo");
        metadatos.put("jwks_uri", issuer + "/jwks");
        metadatos.put("response_types_supported", List.of("code"));
        metadatos.put("subject_types_supported", List.of("public"));
        metadatos.put("id_token_signing_alg_values_supported", List.of("RS256"));
        metadatos.put("grant_types_supported", List.of("authorization_code"));
        metadatos.put("scopes_supported", List.of("openid", "email", "profile"));
        metadatos.put("token_endpoint_auth_methods_supported",
                List.of("client_secret_basic", "client_secret_post"));
        metadatos.put("claims_supported", List.of("iss", "aud", "sub", "exp", "iat", "email", "email_verified"));
        responder(intercambio, 200, metadatos);
    }

    private void jwks(HttpExchange intercambio) throws IOException {
        // toPublicJWK, no la clave entera: por aquí no puede salir ni un
        // componente privado.
        responder(intercambio, 200, new JWKSet(clave.toPublicJWK()).toJSONObject());
    }

    /**
     * En el flujo de las pruebas nadie pide este endpoint: quien hace de Google
     * es {@link #callbackPara(String, String, boolean)}, porque el simulado no
     * tiene pantalla de login donde elegir identidad. Existe para que seguir la
     * redirección por error dé un mensaje en vez de un 404 inexplicable.
     */
    private void autorizar(HttpExchange intercambio) throws IOException {
        responder(intercambio, 400, Map.of(
                "error", "interaction_required",
                "error_description", "El proveedor simulado no tiene pantalla de login: "
                        + "el test decide la identidad llamando a GoogleSimulado.callbackPara(location, email, verificado) "
                        + "en vez de seguir esta redirección."));
    }

    /**
     * La audiencia del ID token sale del {@code client_id} que traía la petición
     * de autorización, no de la petición de canje: con client_secret_basic -que
     * es el método que Spring elige para un proveedor con secreto- el
     * {@code client_id} viaja en la cabecera Authorization y no en el cuerpo,
     * así que leerlo del formulario dejaría el {@code aud} vacío y Spring
     * rechazaría el login. En la autorización es un parámetro obligatorio y ya
     * se guardó al emitir el código.
     */
    private void token(HttpExchange intercambio) throws IOException {
        var formulario = parametros(new String(intercambio.getRequestBody().readAllBytes(), UTF_8));
        var codigo = formulario.get("code");
        // La guarda no es ceremonia: porCodigo es un ConcurrentHashMap y no
        // admite null como clave, así que sin ella una petición sin 'code'
        // revienta el manejador y el cliente ve una conexión cortada en vez del
        // 400 que daría Google.
        if (codigo == null) {
            responder(intercambio, 400, Map.of(
                    "error", "invalid_request",
                    "error_description", "la petición de canje no trae el parámetro code"));
            return;
        }

        var sesion = porCodigo.remove(codigo);   // de un solo uso
        if (sesion == null) {
            responder(intercambio, 400, Map.of(
                    "error", "invalid_grant",
                    "error_description", "código de autorización desconocido o ya canjeado"));
            return;
        }

        var accessToken = valorOpaco();
        porAccessToken.put(accessToken, sesion);

        var respuesta = new LinkedHashMap<String, Object>();
        respuesta.put("access_token", accessToken);
        respuesta.put("token_type", "Bearer");
        respuesta.put("expires_in", VIGENCIA.toSeconds());
        if (sesion.scope() != null) {
            // El que pidió el cliente, no uno inventado. Y ausente si no pidió
            // ninguno: Google omite el campo, no lo manda a null.
            respuesta.put("scope", sesion.scope());
        }
        respuesta.put("id_token", firmar(sesion));
        responder(intercambio, 200, respuesta);
    }

    /**
     * {@code OidcUserService} pide userinfo en cuanto el scope trae
     * {@code email} o {@code profile}, y aborta el login si el {@code sub} que
     * lee aquí no es el del ID token; por eso el access token va atado a la
     * misma sesión que se firmó.
     */
    private void userinfo(HttpExchange intercambio) throws IOException {
        var cabecera = intercambio.getRequestHeaders().getFirst("Authorization");
        var sesion = cabecera != null && cabecera.startsWith("Bearer ")
                ? porAccessToken.get(cabecera.substring("Bearer ".length()))
                : null;
        if (sesion == null) {
            responder(intercambio, 401, Map.of("error", "invalid_token"));
            return;
        }
        var usuario = new LinkedHashMap<String, Object>();
        usuario.put("sub", sesion.sub());
        usuario.put("email", sesion.email());
        usuario.put("email_verified", sesion.emailVerificado());
        usuario.put("name", sesion.email().split("@")[0]);
        responder(intercambio, 200, usuario);
    }

    // --- Auxiliares ------------------------------------------------------

    private String firmar(Sesion sesion) {
        var ahora = Instant.now();
        var claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(sesion.sub())
                .audience(sesion.audiencia())
                .issueTime(Date.from(ahora))
                .expirationTime(Date.from(ahora.plus(VIGENCIA)))
                .claim("email", sesion.email())
                .claim("email_verified", sesion.emailVerificado());
        if (sesion.nonce() != null) {
            claims.claim("nonce", sesion.nonce());
        }
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID(clave.getKeyID())
                .build(), claims.build());
        try {
            jwt.sign(new RSASSASigner(clave));
        } catch (Exception e) {
            throw new IllegalStateException("no se pudo firmar el ID token", e);
        }
        return jwt.serialize();
    }

    /** Estable por email: repetir el login del mismo usuario no cambia su sub. */
    private String subDe(String email) {
        return "sub-" + UUID.nameUUIDFromBytes(email.getBytes(UTF_8));
    }

    private Map<String, String> parametros(String consulta) {
        var parametros = new LinkedHashMap<String, String>();
        if (consulta == null || consulta.isBlank()) {
            return parametros;
        }
        for (var par : consulta.split("&")) {
            var separador = par.indexOf('=');
            if (separador > 0) {
                parametros.put(URLDecoder.decode(par.substring(0, separador), UTF_8),
                        URLDecoder.decode(par.substring(separador + 1), UTF_8));
            }
        }
        return parametros;
    }

    private String valorOpaco() {
        var bytes = new byte[32];
        aleatorio.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private void responder(HttpExchange intercambio, int estado, Map<String, ?> cuerpo) throws IOException {
        var bytes = json.writeValueAsString(cuerpo).getBytes(UTF_8);
        intercambio.getResponseHeaders().set("Content-Type", "application/json");
        intercambio.sendResponseHeaders(estado, bytes.length);
        try (var salida = intercambio.getResponseBody()) {
            salida.write(bytes);
        }
    }
}
