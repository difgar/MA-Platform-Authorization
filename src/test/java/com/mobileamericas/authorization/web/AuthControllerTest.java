package com.mobileamericas.authorization.web;

import com.mobileamericas.authorization.application.service.AuthenticationResult;
import com.mobileamericas.authorization.application.service.AuthenticationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.time.Instant;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.springframework.http.HttpHeaders.SET_COOKIE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// @MockBean fue eliminado en Boot 4 (deprecado desde 3.4); su reemplazo es
// @MockitoBean, de org.springframework.test.context.bean.override.mockito.
//
// @WebMvcTest también se movió de paquete en Boot 4: la modularización llevó
// el soporte de MockMvc a un artefacto propio, spring-boot-webmvc-test, con
// paquete org.springframework.boot.webmvc.test.autoconfigure. No llega
// transitivamente con spring-boot-starter-test; se añadió a build.gradle.
//
// AuthController inyecta CookieFactory, que es un @Component: @WebMvcTest solo
// carga @Controller, @ControllerAdvice, filtros, Converter y similares, así que
// sin este @Import el contexto no arranca por falta de ese colaborador.
@WebMvcTest(AuthController.class)
@Import(CookieFactory.class)
class AuthControllerTest {

    @Autowired MockMvc mvc;
    @MockitoBean AuthenticationService servicio;

    @Test
    void el_login_devuelve_las_cookies_y_nada_en_el_cuerpo() throws Exception {
        given(servicio.authenticate(anyString())).willReturn(new AuthenticationResult(
                "el-access-token", "el-refresh-token",
                Duration.ofMinutes(15), Instant.now().plus(Duration.ofHours(12))));

        mvc.perform(post("/v1/auth/google")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("token-de-google"))
                .andExpect(status().isNoContent())
                // El token NO va en el cuerpo: antes iba, y la UI lo guardaba en
                // localStorage, que es legible por cualquier XSS.
                .andExpect(content().string(""))
                .andExpect(cookie().exists("ma_access"))
                .andExpect(cookie().httpOnly("ma_access", true))
                .andExpect(cookie().secure("ma_access", true))
                .andExpect(cookie().exists("ma_refresh"))
                .andExpect(cookie().httpOnly("ma_refresh", true))
                // MockMvc no tiene un matcher de sameSite; sin esto, borrar
                // .sameSite("Lax") de CookieFactory dejaría la suite entera en
                // verde. Se comprueba la cabecera Set-Cookie cruda, cookie por
                // cookie: hasItem exige que exista UNA línea que combine el
                // nombre con el atributo, no solo que "alguna" de las dos lo
                // tenga.
                .andExpect(header().stringValues(SET_COOKIE,
                        hasItem(allOf(containsString("ma_access="), containsString("SameSite=Lax")))))
                .andExpect(header().stringValues(SET_COOKIE,
                        hasItem(allOf(containsString("ma_refresh="), containsString("SameSite=Lax")))));
    }

    @Test
    void un_acceso_denegado_responde_403_en_problem_json() throws Exception {
        willThrow(new AuthenticationService.AccessDeniedException("Sin roles en la aplicación."))
                .given(servicio).authenticate(anyString());

        mvc.perform(post("/v1/auth/google")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("token-de-google"))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.detail").value("Sin roles en la aplicación."))
                // Nunca una traza: el ResponseDto anterior devolvía
                // e.getStackTrace()[0] al cliente.
                .andExpect(jsonPath("$.stackTrace").doesNotExist());
    }

    @Test
    void el_logout_borra_las_cookies() throws Exception {
        mvc.perform(post("/v1/auth/logout").cookie(
                        new jakarta.servlet.http.Cookie("ma_refresh", "el-refresh-token")))
                .andExpect(status().isNoContent())
                .andExpect(cookie().maxAge("ma_access", 0))
                .andExpect(cookie().maxAge("ma_refresh", 0))
                // Las cookies de borrado son las mismas que las de emisión (mismo
                // base() en CookieFactory), pero eso es exactamente lo que hay que
                // comprobar, no darlo por hecho.
                .andExpect(header().stringValues(SET_COOKIE,
                        hasItem(allOf(containsString("ma_access="), containsString("SameSite=Lax")))))
                .andExpect(header().stringValues(SET_COOKIE,
                        hasItem(allOf(containsString("ma_refresh="), containsString("SameSite=Lax")))));
    }

    @Test
    void el_refresh_devuelve_cookies_nuevas() throws Exception {
        given(servicio.refresh("el-refresh-token")).willReturn(new AuthenticationResult(
                "nuevo-access-token", "nuevo-refresh-token",
                Duration.ofMinutes(15), Instant.now().plus(Duration.ofHours(12))));

        mvc.perform(post("/v1/auth/refresh").cookie(
                        new jakarta.servlet.http.Cookie("ma_refresh", "el-refresh-token")))
                .andExpect(status().isNoContent())
                .andExpect(cookie().exists("ma_access"))
                .andExpect(cookie().exists("ma_refresh"));
    }

    /**
     * Sin el ResponseEntityExceptionHandler de ApiExceptionHandler, esto daba
     * 500: @ExceptionHandler(Exception.class) atrapaba el
     * MissingRequestCookieException de Spring MVC antes de que
     * ResponseEntityExceptionHandler pudiera traducirlo a su 400 real. Como
     * /v1/auth/refresh es permitAll, cualquier llamador anónimo podía forzar
     * esa traza ERROR en el log con solo omitir la cookie.
     */
    @Test
    void el_refresh_sin_cookie_responde_400_no_500() throws Exception {
        mvc.perform(post("/v1/auth/refresh"))
                .andExpect(status().isBadRequest());
    }
}
