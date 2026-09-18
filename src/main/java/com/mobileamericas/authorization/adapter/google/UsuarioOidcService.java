package com.mobileamericas.authorization.adapter.google;

import com.mobileamericas.authorization.application.port.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger log = LoggerFactory.getLogger(UsuarioOidcService.class);

    private final OidcUserService delegado = new OidcUserService();
    private final UserRepository usuarios;

    public UsuarioOidcService(UserRepository usuarios) {
        this.usuarios = usuarios;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest peticion) throws OAuth2AuthenticationException {
        var deGoogle = delegado.loadUser(peticion);
        var email = deGoogle.getEmail();

        // Sin email no hay identidad que buscar, y eso NO es lo mismo que un
        // email sin verificar: son causas distintas y el diagnóstico tiene que
        // distinguirlas.
        if (email == null || email.isBlank()) {
            throw rechazar("email_ausente", "(sin email)",
                    "El proveedor no devuelve ningún email para esta cuenta, y el email es la "
                            + "identidad en esta plataforma.");
        }

        // Un email_verified AUSENTE cuenta como no verificado (getEmailVerified()
        // devuelve null), y de ahí el Boolean.TRUE.equals en vez de un '!'
        // sobre un boolean desempaquetado. La comprobación no es opcional: el
        // email es la única clave hacia los roles, así que un proveedor que no
        // garantice que esa dirección es de quien se está autenticando
        // permitiría entrar como otra persona sólo declarando su email.
        if (!Boolean.TRUE.equals(deGoogle.getEmailVerified())) {
            throw rechazar("email_no_verificado", email,
                    "Google no da el email como verificado; no se puede usar como identidad.");
        }

        // La normalización viene de la fase 1, donde la identidad resultaba
        // dependiente de la colación del motor: el mismo email encontraba
        // usuario en MySQL (utf8mb4_0900_ai_ci, insensible a mayúsculas) y no
        // en PostgreSQL. UserRepositoryAdapter ya normaliza el argumento de la
        // consulta; lo que se decide AQUÍ es la forma canónica de la identidad
        // que entra en la sesión, y de la que dependen el PRINCIPAL_NAME de
        // SPRING_SESSION y la búsqueda de roles en /oauth2/authorize.
        var identidad = email.toLowerCase(Locale.ROOT);

        var usuario = usuarios.findByEmail(identidad)
                .orElseThrow(() -> rechazar("usuario_desconocido", identidad,
                        "El usuario no está dado de alta en la plataforma."));

        // Dado de baja se cierra en la puerta, no tres tareas más abajo.
        // Rechazarlo sólo al autorizar funcionaría -AccessGrant.of devuelve un
        // grant vacío si el usuario está inactivo, así que no se emite token-,
        // pero dejaría que desactivar a alguien no le revoque la sesión SSO (12
        // h deslizantes), admitiría al inactivo en cualquier endpoint que se
        // añada luego a la cadena de cierre con authenticated(), y abriría el
        // ciclo login OK -> access_denied -> la SPA reintenta login -> sesión
        // válida -> access_denied. Un rechazo aquí corta todo eso.
        //
        // Código propio y no el de 'usuario_desconocido': estar de baja y no
        // existir son cosas distintas para quien lea el log.
        if (!usuario.active()) {
            throw rechazar("usuario_inactivo", identidad,
                    "El usuario está dado de baja en la plataforma.");
        }

        return new UsuarioAutenticado(deGoogle, identidad);
    }

    /**
     * El rechazo, con su rastro. Un servicio de autenticación que rechaza
     * logins deja una línea: sin ella, un intento masivo de emails no aparece
     * en ningún sitio. A nivel WARN y con el email y el motivo, NADA más: ni
     * el ID token, ni el access token, ni los claims.
     *
     * (auth_audit existe desde la fase 1, pero su forma -entity, entity_id,
     * payload- es para auditar el CRUD de la fase 3 y nunca ha tenido escritor;
     * un evento de login no cabe ahí.)
     */
    private static OAuth2AuthenticationException rechazar(String codigo, String email, String descripcion) {
        log.warn("Login rechazado para '{}': {} [{}]", email, descripcion, codigo);
        return new OAuth2AuthenticationException(new OAuth2Error(codigo, descripcion, null));
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
