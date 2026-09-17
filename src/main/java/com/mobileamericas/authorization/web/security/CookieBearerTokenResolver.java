package com.mobileamericas.authorization.web.security;

import com.mobileamericas.authorization.web.CookieFactory;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

import java.util.Arrays;

/**
 * Cabecera {@code Authorization: Bearer} primero, para servicio a servicio;
 * si no hay, cae a la cookie {@code ma_access}.
 *
 * Sin este resolver, {@link DefaultBearerTokenResolver} —el único que Spring
 * instala si no se configura otro— solo mira esa cabecera. Pero el access
 * token viaja EXCLUSIVAMENTE en una cookie {@code HttpOnly} (CookieFactory),
 * precisamente para que JavaScript no pueda leerlo. Sin este resolver, un
 * navegador podía iniciar sesión y no tenía ninguna forma de llegar después a
 * /v1/auth/me: JavaScript no puede poner en una cabecera un valor que tiene
 * prohibido leer.
 *
 * Aceptar una cookie como credencial reabre la superficie CSRF: el comentario
 * de csrf().disable() en SecurityConfig explica por qué SameSite=Lax es,
 * desde este cambio, el control real que sostiene esa decisión, no un
 * detalle cosmético.
 */
class CookieBearerTokenResolver implements BearerTokenResolver {

    private final BearerTokenResolver cabecera = new DefaultBearerTokenResolver();

    @Override
    public String resolve(HttpServletRequest request) {
        var token = cabecera.resolve(request);
        if (token != null) {
            return token;
        }
        var cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        return Arrays.stream(cookies)
                .filter(c -> CookieFactory.ACCESS.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
