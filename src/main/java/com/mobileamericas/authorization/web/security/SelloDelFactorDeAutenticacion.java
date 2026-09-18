package com.mobileamericas.authorization.web.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Marca la sesión con el factor -y el instante- con que se autenticó.
 *
 * No es cosmético, y no lo descubrió el diseño sino la tarea 8 al pedir el
 * primer token de verdad: JwtGenerator pone 'auth_time' en todo ID token de
 * authorization_code que lleve 'sid' -que con OIDC habilitado son todos,
 * porque ambos claims salen de la misma rama, la que se ejecuta cuando hay
 * SessionInformation-, y lo saca de la FactorGrantedAuthority más reciente
 * del principal. Sin ninguna, la generación revienta con
 * "authenticationTime cannot be null" y POST /oauth2/token responde 500 -el
 * access token ya estaba firmado, el que no llega a existir es el ID token-,
 * así que la SPA se queda sin identidad y, sobre todo, sin el id_token_hint
 * que exige el logout OIDC: /connect/logout sin él no sabe qué cliente cierra
 * sesión ni contra qué lista validar la redirección de salida.
 *
 * Hay que ponerlo aquí porque el login federado NO lo pone:
 * OAuth2LoginAuthenticationProvider sí añade FACTOR_AUTHORIZATION_CODE, pero
 * OidcAuthorizationCodeAuthenticationProvider -el proveedor que atiende a un
 * registro con scope 'openid', que es el nuestro- no lo hace (verificado
 * sobre spring-security-oauth2-client 7.1.1). Es decir, la combinación
 * "authorization server + oauth2Login contra un proveedor OIDC" no emite
 * ningún ID token tal cual viene de fábrica. Y tampoco podría arreglarse
 * desde un OAuth2TokenCustomizer: el fallo ocurre ANTES de que el generador
 * llegue a aplicarlo.
 *
 * Se cablea a mano en SecurityConfig con .userAuthoritiesMapper(...), y no
 * como @Bean autodetectado a propósito: un cableado implícito que deje de
 * aplicarse no rompe nada visible, y el síntoma vuelve a aparecer lejos de su
 * causa, que es justo el modo de fallo que esta clase existe para cerrar.
 */
class SelloDelFactorDeAutenticacion implements GrantedAuthoritiesMapper {

    /**
     * AÑADE, no sustituye: las autoridades que trae el proveedor siguen ahí.
     * Y esto no toca lo que viaja en el token: las autoridades del access
     * token las pone ClaimsCustomizer desde AccessGrant, no la sesión.
     */
    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(
            Collection<? extends GrantedAuthority> autoridades) {
        var conFactor = new ArrayList<GrantedAuthority>(autoridades);
        conFactor.add(FactorGrantedAuthority.fromAuthority(
                FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY));
        return conFactor;
    }
}
