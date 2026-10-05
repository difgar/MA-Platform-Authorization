package com.mobileamericas.authorization.web.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * Qué ve quien pide un código en /oauth2/authorize y no se lo damos.
 *
 * Existe por una sola razón: añadir {@code error_reason} al rechazo de
 * AccesoAlClienteValidator. Sin él, ese rechazo llega al cliente como un
 * {@code error=access_denied} PELADO, y el consumidor sólo puede reconocerlo
 * por la AUSENCIA de {@code error_reason} — o sea, un significado que viaja en
 * un hueco.
 *
 * Y un hueco lo produce cualquiera. Lo encontró la integración de TrafficFlow:
 * una caída de red o una respuesta a medias también llegan sin motivo, y la
 * pantalla común le decía «tu cuenta no tiene permiso en trafficflow» a alguien
 * cuyo problema era internet — mandando a pedir un permiso a quien ya lo tiene.
 * Con {@code error_reason=sin_rol} explícito, la ausencia deja de significar
 * nada y cae al mensaje genérico, que es lo correcto para «no sé qué pasó».
 *
 * <h2>Por qué access_denied se puede traducir a sin_rol sin adivinar</h2>
 *
 * En ESTA configuración, un {@code access_denied} del endpoint de autorización
 * sólo lo produce nuestro validador: el framework también lo emite cuando el
 * usuario deniega el consentimiento, y aquí no hay pantalla de consentimiento
 * —{@code requireAuthorizationConsent(false)} en todos los clientes, y no hay
 * ningún AuthorizationConsentService declarado—. Si algún día se activa el
 * consentimiento, esta traducción deja de ser cierta y hay que distinguir.
 *
 * <h2>Lo que NO cambia</h2>
 *
 * Cuando no hay una redirección válida a la que volver —cliente desconocido,
 * redirect_uri no registrada— el error se responde en el cuerpo y NO se
 * redirige. Es la regla que impide que este endpoint sea un redirect abierto, y
 * se conserva tal cual: la comprobación es la misma que hace el framework, que
 * el token traiga un redirectUri con contenido.
 *
 * <h2>Y la sesión de auth se cierra con el rechazo sin_rol</h2>
 *
 * Lo encontró producción (finanzas@ entrando por el admin, 2026-10-05): tras el
 * rechazo, la sesión de auth seguía autenticada con esa cuenta. Cada reintento
 * repetía el rechazo SIN pasar por Google —no había forma de elegir otra
 * cuenta— y el logout OIDC daba 400, porque nunca se emitió un id_token que
 * mandar como id_token_hint. La única salida era borrar cookies a mano.
 *
 * Una sesión que sólo sirve para ser rechazada no le sirve a nadie: se
 * invalida (y con ella la fila de SPRING_SESSION) y el siguiente
 * /oauth2/authorize vuelve a Google. Sólo en ESTE rechazo, el de access_denied:
 * un error de petición mal formada (scope, redirect_uri) no dice nada de la
 * cuenta y no debe echar a quien sí tiene roles en otras aplicaciones.
 */
class RespuestaDeAuthorizeFallido implements AuthenticationFailureHandler {

    static final String MOTIVO_SIN_ROL = "sin_rol";

    private final HttpMessageConverter<OAuth2Error> errores = new OAuth2ErrorHttpMessageConverter();

    @Override
    public void onAuthenticationFailure(HttpServletRequest peticion, HttpServletResponse respuesta,
                                        AuthenticationException fallo) throws IOException {
        if (!(fallo instanceof OAuth2AuthorizationCodeRequestAuthenticationException oauth)) {
            responderEnElCuerpo(respuesta, new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
            return;
        }

        var error = oauth.getError();
        var peticionDeCodigo = oauth.getAuthorizationCodeRequestAuthentication();
        if (OAuth2ErrorCodes.ACCESS_DENIED.equals(error.getErrorCode())) {
            cerrarSesion(peticion, respuesta, peticionDeCodigo);
        }
        if (peticionDeCodigo == null || !StringUtils.hasText(peticionDeCodigo.getRedirectUri())) {
            responderEnElCuerpo(respuesta, error);
            return;
        }
        respuesta.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        respuesta.sendRedirect(redireccion(error, peticionDeCodigo));
    }

    /**
     * SecurityContextLogoutHandler y no un session.invalidate() a mano: además
     * de invalidar limpia el SecurityContextHolder y guarda un contexto vacío en
     * el repositorio, así que nada de lo que quede de esta petición puede volver
     * a escribir la autenticación en una sesión nueva. Con Spring Session JDBC,
     * invalidar la HttpSession envuelta borra la fila y el filtro de sesión
     * manda la cookie caducada en esta misma respuesta.
     *
     * El principal de la petición de código es el usuario de la sesión (lo que
     * había en el SecurityContextHolder); el handler no lo necesita para invalidar.
     */
    private static void cerrarSesion(HttpServletRequest peticion, HttpServletResponse respuesta,
                                     OAuth2AuthorizationCodeRequestAuthenticationToken peticionDeCodigo) {
        var usuario = peticionDeCodigo != null && peticionDeCodigo.getPrincipal() instanceof Authentication a
                ? a : null;
        new SecurityContextLogoutHandler().logout(peticion, respuesta, usuario);
    }

    private static String redireccion(OAuth2Error error,
                                      OAuth2AuthorizationCodeRequestAuthenticationToken peticionDeCodigo) {
        var destino = UriComponentsBuilder.fromUriString(peticionDeCodigo.getRedirectUri())
                .queryParam("error", error.getErrorCode());

        if (OAuth2ErrorCodes.ACCESS_DENIED.equals(error.getErrorCode())) {
            destino.queryParam("error_reason", MOTIVO_SIN_ROL);
        }
        if (StringUtils.hasText(error.getDescription())) {
            destino.queryParam("error_description", error.getDescription());
        }
        if (StringUtils.hasText(peticionDeCodigo.getState())) {
            destino.queryParam("state", peticionDeCodigo.getState());
        }
        // encode() y no build().toUriString() a secas: la descripción es
        // texto libre con espacios y comillas, y sin codificar produce una URI
        // ilegal que revienta en el cliente en vez de llegar como error.
        return destino.build().encode().toUriString();
    }

    private void responderEnElCuerpo(HttpServletResponse respuesta, OAuth2Error error) throws IOException {
        respuesta.setStatus(HttpStatus.BAD_REQUEST.value());
        respuesta.setContentType(MediaType.APPLICATION_JSON_VALUE);
        respuesta.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        errores.write(error, null, new ServletServerHttpResponse(respuesta));
    }
}
