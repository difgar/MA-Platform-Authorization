package com.mobileamericas.authorization.adapter.token;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.UserRepository;
import com.mobileamericas.authorization.domain.AccessGrant;
import com.mobileamericas.authorization.domain.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/**
 * Dónde se enchufa el RBAC de la fase 1 a la emisión de Spring Authorization
 * Server. El modelo -{@link AccessGrant}, {@code Permission}, {@code Verb}-
 * ya existe y está probado desde esa fase; este adaptador sólo lo invoca en
 * el instante en que el framework construye cada JWT.
 *
 * Vive en adapter/ y no en application/ porque {@link JwtEncodingContext},
 * {@link OAuth2TokenCustomizer} y {@link OidcUser} son tipos de Spring
 * Security: la restricción de que domain/ y application/ no importen
 * org.springframework.* sigue siendo absoluta, y este es justo el punto
 * donde el framework tiene que entrar.
 *
 * El {@code aud} del token lo pone el framework a partir del client_id
 * (que ES el nombre de la app en auth_app); este customizador no lo toca.
 */
@Component
public class ClaimsCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final UserRepository usuarios;
    private final AppRepository apps;

    public ClaimsCustomizer(UserRepository usuarios, AppRepository apps) {
        this.usuarios = usuarios;
        this.apps = apps;
    }

    @Override
    public void customize(JwtEncodingContext ctx) {
        // El nombre del principal es el email normalizado: UsuarioOidcService
        // lo fija así al construir la sesión SSO, y es la misma clave que
        // AccessGrant necesita para resolver roles. Se resuelve aquí, en cada
        // emisión, y no se cachea nada: el mismo guardián que la fase 1, así
        // que degradar a un usuario se nota en el siguiente token que pida.
        var email = ctx.getPrincipal().getName();
        var usuario = usuarios.findByEmail(email).orElseThrow();

        if (!OAuth2TokenType.ACCESS_TOKEN.equals(ctx.getTokenType())) {
            personalizarIdToken(ctx, email, usuario);
            return;
        }

        personalizarAccessToken(ctx, email, usuario);
    }

    /**
     * Identidad para la SPA, nunca autorización: un ID token es un documento
     * que el navegador puede llegar a guardar y que no caduca hasta dentro de
     * horas, mucho después de que un cambio de rol debiera notarse. Por eso
     * 'roles' y 'permissions' no van aquí.
     *
     * 'uid' es auth_user.id, y es el ÚNICO identificador de esta plataforma
     * que no cambia nunca. Existe porque los otros dos sí cambian: 'sub' y
     * 'email' llevan hoy el correo, y a un correo se le cambia el dominio
     * cuando la empresa se renombra, o el nombre cuando alguien se casa. Un
     * consumidor que guarde 'sub' o 'email' como clave ajena se queda ese día
     * con una referencia que no apunta a nadie, sin que nada falle ni avise.
     * Para mostrar en pantalla, 'email'; para guardar, 'uid'.
     */
    private void personalizarIdToken(JwtEncodingContext ctx, String email, User usuario) {
        ctx.getClaims().claim("uid", usuario.id().toString());
        ctx.getClaims().claim("email", email);

        // full_name es NULLABLE en el esquema (mismo criterio que aplicaba
        // RsaTokenIssuer en la fase 1): un claim ausente es honesto, mandar
        // null o "" induciría a un consumidor a creer que el nombre se
        // conoce y está vacío.
        if (usuario.fullName() != null) {
            ctx.getClaims().claim("name", usuario.fullName());
        }

        avatarDe(ctx.getPrincipal()).ifPresent(url -> ctx.getClaims().claim("picture", url));
    }

    /**
     * Autorización para el resource server: roles y permisos ya expandidos
     * por AccessGrant.of -los comodines no viajan nunca en el token-, más el
     * email.
     *
     * 'email' y 'sub' llevan HOY el mismo valor, no dos distintos: el
     * framework pone en 'sub' el nombre del principal, que es el email
     * normalizado que fija UsuarioOidcService (comprobado sobre un token real
     * emitido, en FlujoCompletoIT; antes aquí decía que 'sub' era un UUID
     * opaco, y era falso).
     *
     * Aun coincidiendo, el claim no sobra, y la razón no es la comodidad:
     * 'sub' es por contrato un identificador OPACO de sujeto, y un consumidor
     * que lo lea como una dirección de correo se estaría apoyando en un
     * detalle de implementación de este emisor. 'email' es el claim que SÍ
     * promete ser una dirección, y es el que un resource server debe leer
     * para mostrar o registrar quién hizo algo.
     *
     * Y para REGISTRAR de forma duradera -una auditoría, una clave ajena- ni
     * uno ni otro: 'uid', que es auth_user.id y no cambia nunca. 'sub' y
     * 'email' llevan hoy el mismo correo, y un correo es mutable; quien los
     * guarde como identidad se rompe el día que alguien cambie de dirección,
     * en silencio, porque el token seguiría validando.
     */
    private void personalizarAccessToken(JwtEncodingContext ctx, String email, User usuario) {
        var app = apps.findByName(ctx.getRegisteredClient().getClientId()).orElseThrow();
        var grant = AccessGrant.of(usuario, app, apps.resourceCatalogue(app.id()));

        ctx.getClaims().claim("uid", usuario.id().toString());
        ctx.getClaims().claim("email", email);
        ctx.getClaims().claim("roles", List.copyOf(grant.roleNames()));
        ctx.getClaims().claim("permissions", List.copyOf(grant.authorities()));
    }

    /**
     * El avatar sale del {@link OidcUser} que sostiene la sesión SSO -lo que
     * devolvió Google-, no de auth_user, que no tiene columna para ello.
     * Ausente si el proveedor no lo manda, en vez de forzar un claim vacío.
     */
    private static Optional<String> avatarDe(Authentication principal) {
        if (principal.getPrincipal() instanceof OidcUser oidcUser) {
            return Optional.ofNullable(oidcUser.getAttribute("picture"));
        }
        return Optional.empty();
    }
}
