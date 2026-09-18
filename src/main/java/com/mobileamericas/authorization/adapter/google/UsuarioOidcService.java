package com.mobileamericas.authorization.adapter.google;

import com.mobileamericas.authorization.application.port.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.io.Serializable;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;

/**
 * Quién puede entrar. Envuelve el {@link OidcUserService} de serie -que es el
 * que habla con el endpoint userinfo del proveedor- y decide, con lo que Google
 * dice de la identidad, si esa persona es un usuario de la plataforma.
 *
 * Rechaza durante el propio login, no más tarde: así el desconocido no llega a
 * tener sesión SSO en este servicio. Si el rechazo esperara a
 * /oauth2/authorize, cualquiera con una cuenta de Google tendría sesión aquí y
 * el único filtro sería el de roles por aplicación.
 *
 * Vive en adapter/ y no en application/: la restricción de la fase 1 es que
 * domain/ y application/ no importen org.springframework.*, y este servicio ES
 * el adaptador hacia el proveedor de identidad.
 */
@Service
public class UsuarioOidcService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcUserService delegado = new OidcUserService();
    private final UserRepository usuarios;

    public UsuarioOidcService(UserRepository usuarios) {
        this.usuarios = usuarios;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest peticion) throws OAuth2AuthenticationException {
        var deGoogle = delegado.loadUser(peticion);
        var email = deGoogle.getEmail();

        // Un email_verified AUSENTE cuenta como no verificado (getEmailVerified()
        // devuelve null), y de ahí el Boolean.TRUE.equals en vez de un '!'
        // sobre un boolean desempaquetado. La comprobación no es opcional: el
        // email es la única clave hacia los roles, así que un proveedor que no
        // garantice que esa dirección es de quien se está autenticando
        // permitiría entrar como otra persona sólo declarando su email.
        if (email == null || email.isBlank() || !Boolean.TRUE.equals(deGoogle.getEmailVerified())) {
            throw new OAuth2AuthenticationException(new OAuth2Error("email_no_verificado",
                    "Google no da el email como verificado; no se puede usar como identidad.", null));
        }

        // La normalización viene de la fase 1, donde la identidad resultaba
        // dependiente de la colación del motor: el mismo email encontraba
        // usuario en MySQL (utf8mb4_0900_ai_ci, insensible a mayúsculas) y no
        // en PostgreSQL. UserRepositoryAdapter ya normaliza el argumento de la
        // consulta; lo que se decide AQUÍ es la forma canónica de la identidad
        // que entra en la sesión, y de la que dependen el PRINCIPAL_NAME de
        // SPRING_SESSION y la búsqueda de roles en /oauth2/authorize.
        var identidad = email.toLowerCase(Locale.ROOT);

        usuarios.findByEmail(identidad).orElseThrow(() -> new OAuth2AuthenticationException(
                new OAuth2Error("usuario_desconocido",
                        "El usuario no está dado de alta en la plataforma.", null)));

        return new UsuarioAutenticado(deGoogle, identidad);
    }

    /**
     * El usuario que entra en la sesión: el que devolvió el proveedor, pero
     * con el email normalizado como nombre del principal.
     *
     * Hace falta envolverlo porque el nombre de un OidcUser lo fija el
     * atributo que el registro del cliente declare (por defecto 'sub'), y el
     * 'sub' de Google no dice nada sobre a qué fila de auth_user corresponde.
     * Todo lo que va detrás -PRINCIPAL_NAME en SPRING_SESSION, y la búsqueda
     * de roles al autorizar- usa Authentication.getName().
     *
     * Serializable de forma explícita: OidcUser no lo es, y el contexto de
     * seguridad se serializa entero en SPRING_SESSION_ATTRIBUTES.
     */
    private record UsuarioAutenticado(OidcUser proveedor, String email) implements OidcUser, Serializable {

        @Override
        public String getName() {
            return email;
        }

        @Override
        public Map<String, Object> getAttributes() {
            return proveedor.getAttributes();
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return proveedor.getAuthorities();
        }

        @Override
        public Map<String, Object> getClaims() {
            return proveedor.getClaims();
        }

        @Override
        public OidcUserInfo getUserInfo() {
            return proveedor.getUserInfo();
        }

        @Override
        public OidcIdToken getIdToken() {
            return proveedor.getIdToken();
        }
    }
}
