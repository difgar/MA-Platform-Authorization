package com.mobileamericas.authorization.web;

import com.mobileamericas.authorization.application.service.AuthenticationResult;
import com.mobileamericas.authorization.application.service.AuthenticationService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;

@RestController
@RequestMapping("/v1/auth")
class AuthController {

    private final AuthenticationService servicio;
    private final CookieFactory cookies;

    AuthController(AuthenticationService servicio, CookieFactory cookies) {
        this.servicio = servicio;
        this.cookies = cookies;
    }

    @PostMapping("/google")
    ResponseEntity<Void> google(@RequestBody String googleIdToken) {
        return conCookies(servicio.authenticate(googleIdToken.trim()));
    }

    @PostMapping("/refresh")
    ResponseEntity<Void> refresh(@CookieValue(CookieFactory.REFRESH) String refreshToken) {
        return conCookies(servicio.refresh(refreshToken));
    }

    @PostMapping("/logout")
    ResponseEntity<Void> logout(
            @CookieValue(value = CookieFactory.REFRESH, required = false) String refreshToken) {
        if (refreshToken != null) {
            servicio.logout(refreshToken);
        }
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cookies.borrar(CookieFactory.ACCESS).toString())
                .header(HttpHeaders.SET_COOKIE, cookies.borrar(CookieFactory.REFRESH).toString())
                .build();
    }

    /** El cuerpo va vacío a propósito: el token no debe ser legible por JavaScript. */
    private ResponseEntity<Void> conCookies(AuthenticationResult r) {
        var ttlRefresh = Duration.between(Instant.now(), r.refreshExpiresAt());
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE,
                        cookies.access(r.accessToken(), r.accessTtl()).toString())
                .header(HttpHeaders.SET_COOKIE,
                        cookies.refresh(r.refreshToken(), ttlRefresh).toString())
                .build();
    }
}
