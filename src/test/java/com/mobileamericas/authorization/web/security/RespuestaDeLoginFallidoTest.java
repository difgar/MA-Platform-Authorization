package com.mobileamericas.authorization.web.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Lo que ve quien no consigue entrar. Las pruebas de integración cubren el
 * camino con el error de OAuth dentro (LoginIT lee por ahí el motivo del
 * rechazo); esta cubre además la otra rama, la del fallo que NO es de OAuth,
 * que es la que podría filtrar el interior del servicio a cualquiera.
 */
class RespuestaDeLoginFallidoTest {

    private final RespuestaDeLoginFallido handler = new RespuestaDeLoginFallido();
    private final MockHttpServletRequest peticion = new MockHttpServletRequest();
    private final MockHttpServletResponse respuesta = new MockHttpServletResponse();

    @Test
    void un_error_de_oauth_viaja_con_su_codigo_y_su_descripcion() throws Exception {
        handler.onAuthenticationFailure(peticion, respuesta, new OAuth2AuthenticationException(
                new OAuth2Error("usuario_desconocido",
                        "El usuario no está dado de alta en la plataforma.", null)));

        assertThat(respuesta.getStatus()).isEqualTo(401);
        assertThat(respuesta.getContentType()).startsWith("application/json");
        assertThat(respuesta.getContentAsString())
                .contains("\"error\":\"usuario_desconocido\"")
                .contains("El usuario no está dado de alta en la plataforma.");
    }

    @Test
    void un_error_de_oauth_sin_descripcion_no_deja_el_campo_a_null() throws Exception {
        handler.onAuthenticationFailure(peticion, respuesta,
                new OAuth2AuthenticationException(new OAuth2Error("invalid_state_parameter")));

        assertThat(respuesta.getContentAsString())
                .contains("\"error\":\"invalid_state_parameter\"")
                .doesNotContain("null");
    }

    @Test
    void un_fallo_que_no_es_de_oauth_no_cuenta_nada_del_interior() throws Exception {
        handler.onAuthenticationFailure(peticion, respuesta, new InternalAuthenticationServiceException(
                "could not extract ResultSet; SQL [select u1_0.email from auth_user u1_0]"));

        assertThat(respuesta.getStatus()).isEqualTo(401);
        assertThat(respuesta.getContentAsString())
                .contains("\"error\":\"login_fallido\"")
                .doesNotContain("auth_user", "ResultSet", "SQL");
    }
}
