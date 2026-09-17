package com.mobileamericas.authorization.web;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * HttpOnly, Secure y SameSite=Lax, los tres.
 *
 * En develop estaban las tres líneas comentadas y el token viajaba además en el
 * cuerpo de la respuesta, de donde MA-Platform-UI lo copiaba a localStorage.
 * Cualquier XSS podía leerlo.
 */
@Component
public class CookieFactory {

    // Públicas: web.security.CookieBearerTokenResolver, en otro paquete, tiene
    // que saber el nombre de la cookie de acceso para poder leerla.
    public static final String ACCESS = "ma_access";
    public static final String REFRESH = "ma_refresh";

    ResponseCookie access(String valor, Duration ttl) {
        return base(ACCESS, valor).maxAge(ttl).build();
    }

    ResponseCookie refresh(String valor, Duration ttl) {
        return base(REFRESH, valor).maxAge(ttl).build();
    }

    ResponseCookie borrar(String nombre) {
        return base(nombre, "").maxAge(Duration.ZERO).build();
    }

    private ResponseCookie.ResponseCookieBuilder base(String nombre, String valor) {
        return ResponseCookie.from(nombre, valor)
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .path("/");
    }
}
