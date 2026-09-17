package com.mobileamericas.authorization.application.service;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.IdentityVerifier;
import com.mobileamericas.authorization.application.port.RefreshTokenStore;
import com.mobileamericas.authorization.application.port.TokenIssuer;
import com.mobileamericas.authorization.application.port.UserRepository;
import com.mobileamericas.authorization.domain.AccessGrant;
import com.mobileamericas.authorization.domain.App;
import com.mobileamericas.authorization.domain.User;

/**
 * Caso de uso de autenticación. Sin anotación de Spring: application/ no
 * importa el framework. Se registra como @Bean en config/BeansConfig.java.
 */
public class AuthenticationService {

    private final IdentityVerifier identidades;
    private final UserRepository usuarios;
    private final AppRepository apps;
    private final TokenIssuer emisor;
    private final RefreshTokenStore refrescos;

    public AuthenticationService(IdentityVerifier identidades, UserRepository usuarios,
                                 AppRepository apps, TokenIssuer emisor,
                                 RefreshTokenStore refrescos) {
        this.identidades = identidades;
        this.usuarios = usuarios;
        this.apps = apps;
        this.emisor = emisor;
        this.refrescos = refrescos;
    }

    public AuthenticationResult authenticate(String googleIdToken) {
        var identidad = identidades.verify(googleIdToken);

        var usuario = usuarios.findByEmail(identidad.email())
                .orElseThrow(() -> new AccessDeniedException(
                        "El usuario no está dado de alta en la plataforma."));

        return emitir(usuario, identidad.app());
    }

    /**
     * Renueva la sesión.
     *
     * No recibe el access token. Los roles y permisos se resuelven consultando
     * el repositorio por el userId que guarda la familia del refresh, así que un
     * access token fabricado no aporta nada. Es lo que cierra la escalada de
     * privilegios que tenía JwtUtil.refreshAccessToken().
     *
     * Deliberadamente NO transaccional: application/ no puede usar
     * @Transactional (no importa Spring), así que consume() y rotate() corren
     * cada uno en su propia transacción dentro del store. Si rotate() falla
     * justo después de que consume() tuvo éxito, el token viejo queda
     * consumido y no se emite uno nuevo: el usuario tiene que volver a
     * autenticarse. Eso falla cerrado, que es la dirección correcta, pero es
     * una decisión y queda escrita aquí para que nadie la redescubra leyendo
     * un stack trace en producción.
     */
    public AuthenticationResult refresh(String rawRefreshToken) {
        var sujeto = refrescos.consume(rawRefreshToken)
                .orElseThrow(() -> new AccessDeniedException(
                        "El refresh token no es válido o ya se usó."));

        var usuario = usuarios.findById(sujeto.userId())
                .orElseThrow(() -> new AccessDeniedException("El usuario ya no existe."));

        var app = apps.findById(sujeto.appId())
                .orElseThrow(() -> new AccessDeniedException("La aplicación ya no existe."));

        var grant = grantDe(usuario, app);

        RefreshTokenStore.IssuedRefreshToken rotado;
        try {
            rotado = refrescos.rotate(sujeto.familyId());
        } catch (RefreshTokenStore.RevokedFamilyException e) {
            // Resultado rutinario (theft detection o logout ya revocaron la
            // familia): para quien llama es la misma situación que un refresh
            // token inválido, vuelve a autenticarte. RefreshTokenStore.UnknownFamilyException,
            // en cambio, NO se captura aquí: consume() ya validó esa familia,
            // así que no encontrarla es una inconsistencia interna y debe
            // subir como error de servidor, no disfrazarse de error de cliente.
            throw new AccessDeniedException("El refresh token no es válido o ya se usó.");
        }

        return new AuthenticationResult(
                emisor.issueAccessToken(grant), rotado.value(),
                emisor.accessTokenTtl(), rotado.expiresAt());
    }

    public void logout(String rawRefreshToken) {
        refrescos.consume(rawRefreshToken)
                .ifPresent(sujeto -> refrescos.revokeFamily(sujeto.familyId()));
    }

    private AuthenticationResult emitir(User usuario, App app) {
        var grant = grantDe(usuario, app);
        var refresh = refrescos.issue(usuario.id(), app.id());

        return new AuthenticationResult(
                emisor.issueAccessToken(grant), refresh.value(),
                emisor.accessTokenTtl(), refresh.expiresAt());
    }

    /**
     * @throws AccessDeniedException si el usuario no tiene ningún rol en esta
     *         app: ni el que nunca tuvo acceso, ni al que se lo quitaron por
     *         completo. Se mira roleNames() y no isEmpty(): un rol con cero
     *         permisos sigue siendo un rol asignado, y ese caso debe emitir un
     *         token sin autoridades (la renovación refleja la baja), no
     *         rechazar la renovación.
     */
    private AccessGrant grantDe(User usuario, App app) {
        var grant = AccessGrant.of(usuario, app, apps.resourceCatalogue(app.id()));
        if (grant.roleNames().isEmpty()) {
            throw new AccessDeniedException(
                    "El usuario no tiene roles en '%s'.".formatted(app.name()));
        }
        return grant;
    }

    public static class AccessDeniedException extends RuntimeException {
        public AccessDeniedException(String mensaje) {
            super(mensaje);
        }
    }
}
