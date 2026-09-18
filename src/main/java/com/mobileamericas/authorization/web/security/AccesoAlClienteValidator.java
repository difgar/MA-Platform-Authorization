package com.mobileamericas.authorization.web.security;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.UserRepository;
import com.mobileamericas.authorization.domain.AccessGrant;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;

import java.util.function.Consumer;

/**
 * Cierra el agujero de un usuario sin ningún rol en la app que pide el token:
 * hoy AccessGrant.of devuelve un grant vacío y el framework, si nadie lo
 * impide, emite igualmente un código y luego un token con cero autoridades.
 * Eso es peor que un rechazo -la aplicación cree que el usuario ha entrado y
 * no puede hacer nada, sin que nadie sepa por qué-, el mismo fallo silencioso
 * que la fase 1 ya corrigió en grantDe.
 *
 * Sustituye al validador por defecto del framework en vez de sumarse a él: se
 * DELEGA en él primero (pordefecto.accept(ctx)), que es quien valida
 * redirect_uri y scope. Sin esa delegación, registrar esta clase en su lugar
 * (ver SecurityConfig) dejaría de comprobar eso. PKCE (code_challenge) y
 * grant_type NO pasan por aquí: los aplica el framework alrededor del hueco
 * que este validador sustituye, antes y después de invocarlo -delegar de más
 * no haría daño, pero no es lo que ocurre-.
 *
 * El segundo argumento de la excepción es ctx.getAuthentication() a
 * propósito, no null: sin él el usuario recibe un 400 crudo en la pantalla de
 * auth; con él, AuthenticationEntryPoint sabe a qué authorization request
 * responder y el usuario vuelve a su aplicación con
 * error=access_denied en la URL de redirección.
 *
 * Por eso un usuario o una app que ya no existen (auth_user borrado, auth_app
 * renombrada o eliminada mientras su registro de cliente sigue sirviéndose)
 * se tratan como el mismo rechazo, no como un 500: un Optional vacío aquí es
 * exactamente el escenario que esta clase existe para no dejar pasar, y un
 * .orElseThrow() sin más volvería a dar el 400/500 crudo que el resto de la
 * clase evita.
 */
class AccesoAlClienteValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

    private final OAuth2AuthorizationCodeRequestAuthenticationValidator pordefecto =
            new OAuth2AuthorizationCodeRequestAuthenticationValidator();

    private final UserRepository usuarios;
    private final AppRepository apps;

    AccesoAlClienteValidator(UserRepository usuarios, AppRepository apps) {
        this.usuarios = usuarios;
        this.apps = apps;
    }

    @Override
    public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext ctx) {
        pordefecto.accept(ctx);

        var autenticacion = ctx.getAuthentication();

        // El framework invoca este validador también en la fase temprana de
        // /oauth2/authorize (OAuth2AuthorizationEndpointFilter la ejecuta en
        // toda petición GET, autenticada o no, para poder responder un error
        // de OAuth sin forzar antes un login) -no sólo al final, ya con la
        // sesión resuelta y el anyRequest().authenticated() de SecurityConfig
        // aplicado-. ctx.getAuthentication() ahí es un
        // OAuth2AuthorizationCodeRequestAuthenticationToken cuyo PRINCIPAL
        // (no el token en sí) es lo que de verdad hay en el
        // SecurityContextHolder: para una petición anónima, un
        // AnonymousAuthenticationToken ("anonymousUser"), que no existe en
        // auth_user. Sin esta guarda, usuarios.findByEmail(...).orElseThrow()
        // revienta con un 500 en vez del 401/302 al login que esta misma
        // cadena ya sabe dar (comprobado: DescubrimientoIT y LoginIT lo
        // cubren). Sin sesión real no hay roles que comprobar todavía; ese
        // rechazo es cosa del exceptionHandling de la cadena, no de este
        // validador.
        if (autenticacion.getPrincipal() instanceof AnonymousAuthenticationToken) {
            return;
        }

        var clientId = ctx.getRegisteredClient().getClientId();
        var app = apps.findByName(clientId);
        var usuario = usuarios.findByEmail(autenticacion.getName());

        // .orElseThrow() aquí sería el mismo 400/500 crudo que esta clase
        // existe para evitar, sólo que por otra puerta: un usuario borrado de
        // auth_user (no sólo desactivado) con sesión todavía viva, o una app
        // renombrada o eliminada mientras su registro de cliente sigue
        // sirviéndose, son Optional vacíos alcanzables en producción, no
        // casos teóricos. Se tratan como el mismo access_denied que la falta
        // de roles, no como un error de servidor.
        if (app.isEmpty() || usuario.isEmpty()
                || AccessGrant.of(usuario.get(), app.get(), apps.resourceCatalogue(app.get().id())).isEmpty()) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED,
                            "El usuario no tiene roles ni permisos en '" + clientId + "'.", null),
                    // ctx.getAuthentication() de nuevo, no la variable de
                    // arriba: aquí ya se sabe que es un
                    // OAuth2AuthorizationCodeRequestAuthenticationToken real
                    // (se descartó el anónimo antes), y volver a pedirlo deja
                    // que el propio getAuthentication() -genérico- infiera ese
                    // tipo en el sitio, en vez de fijar antes un tipo más
                    // amplio (Authentication) que no encajaría aquí. Sin este
                    // segundo argumento el usuario recibe un 400 crudo en vez
                    // de volver a su aplicación con el error.
                    ctx.getAuthentication());
        }
    }
}
