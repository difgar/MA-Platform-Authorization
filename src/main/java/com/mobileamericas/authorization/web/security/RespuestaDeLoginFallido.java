package com.mobileamericas.authorization.web.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Optional;

/**
 * Qué ve quien intenta entrar y no puede.
 *
 * Existe porque oauth2Login manda los fallos a /login?error, y el motivo del
 * rechazo -no está dado de alta, está dado de baja, o Google no da su email
 * como verificado- sólo lo conoce el servidor y NO viaja en ese 302. Quien
 * intenta entrar no puede saber por qué no puede, y una prueba tampoco puede
 * distinguir un rechazo de otro ni un rechazo de un éxito.
 *
 * <h2>Devuelve a la aplicación, y sólo responde JSON si no hay a dónde</h2>
 *
 * La primera versión respondía SIEMPRE un JSON con 401, razonando que es «el
 * único idioma que habla este servicio». Era verdad para una máquina y falso
 * para el caso real: en ese instante quien mira es una persona con un
 * navegador, y este servicio SÍ sabe de qué aplicación viene. Un JSON crudo en
 * una URL del servidor de autorización parece una avería, no una falta de
 * permiso.
 *
 * El contraste que lo delata estaba dentro de este mismo repositorio:
 * AccesoAlClienteValidator rechaza en /authorize y redirige a la aplicación
 * con error y state, y ese caso siempre se vio bien. El rechazo EN /authorize
 * estaba resuelto y el rechazo ANTES de /authorize no, y la diferencia no la
 * nota quien la programa: la nota quien se queda mirando el JSON.
 *
 * <h2>Dos códigos, en capas</h2>
 *
 * <ul>
 *   <li>{@code error} es SIEMPRE {@code access_denied}, que es estándar de
 *       OAuth 2.0: un cliente genérico que no conozca nada de esta plataforma
 *       se comporta bien.</li>
 *   <li>{@code error_reason} lleva el motivo concreto. Un consumidor traduce
 *       por él cuando lo reconoce y cae al mensaje de {@code access_denied}
 *       cuando no, así que un motivo nuevo NUNCA llega crudo a una pantalla y
 *       el contrato se puede ampliar sin coordinar con nadie.</li>
 * </ul>
 *
 * Distinguir «no estás dado de alta» de «estás dado de baja» sólo se lo cuenta
 * a quien YA ha completado el login en Google con esa identidad: para sondear
 * si un correo ajeno existe en la plataforma haría falta controlar esa cuenta
 * de Google. No es enumeración abierta, es preguntar por lo propio, y a cambio
 * la persona sabe si tiene que pedir acceso o reclamar una baja. Por eso el
 * detalle va en {@code error_reason} y el {@code error} estándar no distingue.
 *
 * <h2>El redirect_uri se valida contra el registro, siempre</h2>
 *
 * La URI a la que se devuelve NO se toma de la petición guardada tal cual: se
 * comprueba que esté registrada para ese client_id en auth_app. Sin esa
 * comprobación esto sería un redirect abierto servido por la pantalla que el
 * usuario acaba de reconocer como fiable, que es exactamente el agujero que
 * FlujoCompletoIT ya vigila para el logout.
 */
class RespuestaDeLoginFallido implements AuthenticationFailureHandler {

    private static final String MOTIVO_POR_DEFECTO = "login_fallido";

    /**
     * Instancia propia, no un bean: la fase 2 prohíbe declarar un bean
     * ObjectMapper (afectaría a la serialización de todo el servicio) y aquí
     * sólo se necesita para escribir dos campos. A mano habría que escapar la
     * descripción, que es texto libre.
     */
    private final ObjectMapper json = new ObjectMapper();

    private final RequestCache peticionesGuardadas;
    private final RegisteredClientRepository clientes;

    RespuestaDeLoginFallido(RequestCache peticionesGuardadas, RegisteredClientRepository clientes) {
        this.peticionesGuardadas = peticionesGuardadas;
        this.clientes = clientes;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest peticion, HttpServletResponse respuesta,
                                        AuthenticationException fallo) throws IOException {
        var motivo = motivoDe(fallo);
        var destino = destinoDeVuelta(peticion, motivo);

        if (destino.isPresent()) {
            respuesta.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            respuesta.sendRedirect(destino.get());
            return;
        }
        responderJson(respuesta, motivo, fallo);
    }

    /**
     * El motivo estable que viaja en {@code error_reason}: el código del
     * OAuth2Error que lanzó UsuarioOidcService, o uno genérico.
     *
     * Cualquier fallo que no sea de OAuth se resume sin detalle: el mensaje de
     * una excepción cualquiera puede describir el interior del servicio, y
     * quien lo lee aquí es cualquiera en internet.
     */
    private static String motivoDe(AuthenticationException fallo) {
        return fallo instanceof OAuth2AuthenticationException oauth
                ? oauth.getError().getErrorCode()
                : MOTIVO_POR_DEFECTO;
    }

    /**
     * La URI de la aplicación que arrancó el flujo, con el error y su state.
     *
     * Vacío -y entonces se responde JSON- cuando no hay a dónde volver: quien
     * llega al callback de Google directamente, o con la sesión caducada, o
     * pidiendo un client_id que ya no está registrado. Ahí no hay redirect_uri
     * que valga y adivinar una sería peor que el JSON.
     */
    private Optional<String> destinoDeVuelta(HttpServletRequest peticion, String motivo) {
        var guardada = peticionesGuardadas.getRequest(peticion, null);
        if (guardada == null) {
            return Optional.empty();
        }
        var clientId = parametro(guardada, "client_id");
        var redirectUri = parametro(guardada, "redirect_uri");
        if (clientId == null || redirectUri == null || !estaRegistrada(clientId, redirectUri)) {
            return Optional.empty();
        }

        var destino = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("error", "access_denied")
                .queryParam("error_reason", motivo);
        // El state vuelve tal cual vino: es del cliente y es lo que le permite
        // casar esta respuesta con la petición que hizo.
        Optional.ofNullable(parametro(guardada, "state"))
                .ifPresent(state -> destino.queryParam("state", state));
        // encode(): el state es texto libre elegido por el cliente y puede
        // traer cualquier cosa. Sin codificar, una URI ilegal.
        return Optional.of(destino.build().encode().toUriString());
    }

    /**
     * Se leen del SavedRequest y no de la query a mano: él ya los tiene
     * decodificados, y parsear una query string por nuestra cuenta sería una
     * segunda implementación de algo que el framework ya hizo bien.
     */
    private static String parametro(SavedRequest guardada, String nombre) {
        var valores = guardada.getParameterValues(nombre);
        return valores == null || valores.length == 0 ? null : valores[0];
    }

    private boolean estaRegistrada(String clientId, String redirectUri) {
        var cliente = clientes.findByClientId(clientId);
        return cliente != null && cliente.getRedirectUris().contains(redirectUri);
    }

    private void responderJson(HttpServletResponse respuesta, String motivo,
                               AuthenticationException fallo) throws IOException {
        var cuerpo = new LinkedHashMap<String, String>();
        cuerpo.put("error", "access_denied");
        cuerpo.put("error_reason", motivo);
        cuerpo.put("error_description", fallo instanceof OAuth2AuthenticationException oauth
                && oauth.getError().getDescription() != null
                ? oauth.getError().getDescription()
                : "No se pudo completar el inicio de sesión.");

        respuesta.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        respuesta.setContentType(MediaType.APPLICATION_JSON_VALUE);
        respuesta.setCharacterEncoding("UTF-8");
        // Un rechazo de login no se guarda en ninguna caché intermedia.
        respuesta.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        respuesta.getWriter().write(json.writeValueAsString(cuerpo));
    }
}
