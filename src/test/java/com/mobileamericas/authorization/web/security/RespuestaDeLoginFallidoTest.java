package com.mobileamericas.authorization.web.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Lo que ve quien no consigue entrar.
 *
 * El caso normal es una persona con un navegador que venía de una aplicación,
 * y entonces vuelve a ella con el motivo. El JSON queda para cuando no hay a
 * dónde volver, que es también donde vive el riesgo de contar de más.
 */
class RespuestaDeLoginFallidoTest {

    private static final String DESTINO = "http://localhost:5173/callback";

    private final MockHttpServletRequest peticion = new MockHttpServletRequest();
    private final MockHttpServletResponse respuesta = new MockHttpServletResponse();

    private RespuestaDeLoginFallido conPeticionGuardada(String clientId, String redirectUri, String state) {
        var original = new MockHttpServletRequest("GET", "/oauth2/authorize");
        original.setParameter("client_id", clientId);
        original.setParameter("redirect_uri", redirectUri);
        if (state != null) {
            original.setParameter("state", state);
        }
        SavedRequest guardada = new DefaultSavedRequest(original);
        return new RespuestaDeLoginFallido(cacheCon(guardada), registro());
    }

    @Test
    void el_rechazo_vuelve_a_la_aplicacion_con_el_motivo_y_el_state() throws Exception {
        conPeticionGuardada("admin", DESTINO, "xyz-123").onAuthenticationFailure(
                peticion, respuesta, rechazo("usuario_no_registrado"));

        assertThat(respuesta.getStatus()).isEqualTo(302);
        assertThat(respuesta.getRedirectedUrl())
                .startsWith(DESTINO)
                // 'error' es el estándar de OAuth: un cliente genérico que no
                // conozca nada de esta plataforma sigue entendiéndolo.
                .contains("error=access_denied")
                // y el motivo concreto viaja aparte, para quien sepa leerlo.
                .contains("error_reason=usuario_no_registrado")
                .contains("state=xyz-123");
    }

    @Test
    void el_motivo_distingue_estar_de_baja_de_no_estar_dado_de_alta() throws Exception {
        conPeticionGuardada("admin", DESTINO, null).onAuthenticationFailure(
                peticion, respuesta, rechazo("usuario_inactivo"));

        // Son dos situaciones con acciones distintas -pedir acceso o reclamar
        // una baja- y por eso no se resumen en el mismo código.
        assertThat(respuesta.getRedirectedUrl()).contains("error_reason=usuario_inactivo");
    }

    /**
     * El caso que más veces va a ocurrir, y el único cuyo código NO lo pone
     * este servicio: cuando alguien cierra la ventana de Google, el proveedor
     * responde 'access_denied' y ese código llega tal cual a 'error_reason'.
     *
     * Se fija aquí, en el lado que lo emite, porque un consumidor puede
     * protegerse de un motivo que no conoce pero no puede notar si un día este
     * código cambia. Y hay una trampa detrás: 'error_reason=access_denied'
     * significa «canceló», mientras que un rechazo SIN error_reason -el de
     * AccesoAlClienteValidator en /authorize- significa «no tiene rol aquí».
     * Las dos llegan con error=access_denied y no son lo mismo: confundirlas
     * manda a pedir un permiso a quien ya lo tiene.
     */
    @Test
    void el_codigo_que_pone_google_al_cancelar_viaja_tal_cual() throws Exception {
        conPeticionGuardada("admin", DESTINO, "xyz").onAuthenticationFailure(
                peticion, respuesta, rechazo("access_denied"));

        assertThat(respuesta.getRedirectedUrl())
                .contains("error=access_denied")
                .contains("error_reason=access_denied");
    }

    @Test
    void una_redireccion_no_registrada_no_se_usa_jamas() throws Exception {
        // Sin esta comprobación esto sería un redirect abierto servido por la
        // pantalla que el usuario acaba de reconocer como fiable.
        conPeticionGuardada("admin", "https://evil.example/callback", "xyz")
                .onAuthenticationFailure(peticion, respuesta, rechazo("usuario_no_registrado"));

        assertThat(respuesta.getRedirectedUrl()).isNull();
        assertThat(respuesta.getStatus()).isEqualTo(401);
        assertThat(respuesta.getContentAsString()).doesNotContain("evil.example");
    }

    @Test
    void sin_peticion_guardada_no_hay_a_donde_volver_y_responde_json() throws Exception {
        new RespuestaDeLoginFallido(cacheCon(null), registro())
                .onAuthenticationFailure(peticion, respuesta, rechazo("usuario_no_registrado"));

        assertThat(respuesta.getStatus()).isEqualTo(401);
        assertThat(respuesta.getContentType()).startsWith("application/json");
        assertThat(respuesta.getContentAsString())
                .contains("\"error\":\"access_denied\"")
                .contains("\"error_reason\":\"usuario_no_registrado\"");
    }

    @Test
    void un_fallo_que_no_es_de_oauth_no_cuenta_nada_del_interior() throws Exception {
        new RespuestaDeLoginFallido(cacheCon(null), registro()).onAuthenticationFailure(
                peticion, respuesta, new InternalAuthenticationServiceException(
                        "could not extract ResultSet; SQL [select u1_0.email from auth_user u1_0]"));

        assertThat(respuesta.getStatus()).isEqualTo(401);
        assertThat(respuesta.getContentAsString())
                .contains("\"error_reason\":\"login_fallido\"")
                .doesNotContain("auth_user", "ResultSet", "SQL");
    }

    private static OAuth2AuthenticationException rechazo(String codigo) {
        return new OAuth2AuthenticationException(new OAuth2Error(codigo, "motivo legible", null));
    }

    private static RequestCache cacheCon(SavedRequest guardada) {
        return new RequestCache() {
            @Override
            public void saveRequest(jakarta.servlet.http.HttpServletRequest r,
                                    jakarta.servlet.http.HttpServletResponse s) {
            }

            @Override
            public SavedRequest getRequest(jakarta.servlet.http.HttpServletRequest r,
                                           jakarta.servlet.http.HttpServletResponse s) {
                return guardada;
            }

            @Override
            public jakarta.servlet.http.HttpServletRequest getMatchingRequest(
                    jakarta.servlet.http.HttpServletRequest r, jakarta.servlet.http.HttpServletResponse s) {
                return null;
            }

            @Override
            public void removeRequest(jakarta.servlet.http.HttpServletRequest r,
                                      jakarta.servlet.http.HttpServletResponse s) {
            }
        };
    }

    private static RegisteredClientRepository registro() {
        var admin = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("admin")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(DESTINO)
                .scope("openid")
                .build();
        return new RegisteredClientRepository() {
            @Override
            public void save(RegisteredClient registeredClient) {
            }

            @Override
            public RegisteredClient findById(String id) {
                return null;
            }

            @Override
            public RegisteredClient findByClientId(String clientId) {
                return "admin".equals(clientId) ? admin : null;
            }
        };
    }
}
