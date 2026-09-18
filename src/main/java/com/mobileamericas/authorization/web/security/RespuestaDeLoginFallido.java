package com.mobileamericas.authorization.web.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.LinkedHashMap;

/**
 * Qué ve quien intenta entrar y no puede.
 *
 * Existe porque oauth2Login manda los fallos a /login?error y auth NO sirve
 * HTML: /login cae en la cadena de cierre, que exige autenticación y -con un
 * solo proveedor registrado- vuelve a redirigir a Google, así que el usuario
 * rechazado entra en un bucle de redirecciones en lugar de leer por qué no
 * puede entrar. Y el motivo (no está dado de alta, o Google no da su email
 * como verificado) sólo lo conoce el servidor: por la redirección no viaja.
 *
 * Responde en el formato de error de OAuth 2.0, que es el único idioma que
 * este servicio habla, y con 401: la persona está autenticada ante Google
 * pero no ante la plataforma, y puede reintentar con otra identidad.
 */
class RespuestaDeLoginFallido implements AuthenticationFailureHandler {

    /**
     * Instancia propia, no un bean: la fase 2 prohíbe declarar un bean
     * ObjectMapper (afectaría a la serialización de todo el servicio) y aquí
     * sólo se necesita para escribir dos campos. A mano habría que escapar la
     * descripción, que es texto libre.
     */
    private final ObjectMapper json = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest peticion, HttpServletResponse respuesta,
                                        AuthenticationException fallo) throws IOException {
        var cuerpo = new LinkedHashMap<String, String>();
        if (fallo instanceof OAuth2AuthenticationException oauth) {
            cuerpo.put("error", oauth.getError().getErrorCode());
            cuerpo.put("error_description", oauth.getError().getDescription() != null
                    ? oauth.getError().getDescription()
                    : "El proveedor de identidad no completó el login.");
        } else {
            // Cualquier otro fallo se resume sin detalle: el mensaje de una
            // excepción que no es de OAuth puede describir el interior del
            // servicio, y quien la lee aquí es cualquiera en internet.
            cuerpo.put("error", "login_fallido");
            cuerpo.put("error_description", "No se pudo completar el inicio de sesión.");
        }

        respuesta.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        respuesta.setContentType(MediaType.APPLICATION_JSON_VALUE);
        respuesta.setCharacterEncoding("UTF-8");
        // Un rechazo de login no se guarda en ninguna caché intermedia.
        respuesta.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        respuesta.getWriter().write(json.writeValueAsString(cuerpo));
    }
}
