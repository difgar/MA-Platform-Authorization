package com.mobileamericas.authorization.application.service;

import com.mobileamericas.authorization.application.port.*;
import com.mobileamericas.authorization.domain.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthenticationServiceTest {

    private static final UUID APP_ID = UUID.randomUUID();
    private static final App APP = new App(APP_ID, "trafficflow", "cliente-tf", null, true);
    private static final UUID USER_ID = UUID.randomUUID();

    private final Map<String, String> tokensEmitidos = new LinkedHashMap<>();
    private User usuarioEnBd;
    private AuthenticationService servicio;

    private static User usuarioCon(Set<Permission> permisos) {
        var rol = new Role(UUID.randomUUID(), "operador", APP_ID, permisos);
        return new User(USER_ID, "persona@ejemplo.com", "Persona", true, Set.of(rol));
    }

    @BeforeEach
    void preparar() {
        usuarioEnBd = usuarioCon(Set.of(Permission.parse("campanas:leer")));
        servicio = new AuthenticationService(
                idToken -> new IdentityVerifier.VerifiedIdentity("persona@ejemplo.com", "Persona", APP),
                new UserRepository() {
                    @Override public Optional<User> findByEmail(String e) { return Optional.of(usuarioEnBd); }
                    @Override public Optional<User> findById(UUID id) { return Optional.of(usuarioEnBd); }
                },
                new AppRepository() {
                    @Override public Optional<App> findByGoogleClientId(String id) { return Optional.of(APP); }
                    @Override public Optional<App> findByName(String n) { return Optional.of(APP); }
                    @Override public Optional<App> findById(UUID id) { return Optional.of(APP); }
                    @Override public Set<String> resourceCatalogue(UUID id) { return Set.of("campanas"); }
                },
                new TokenIssuer() {
                    @Override public String issueAccessToken(AccessGrant g) {
                        var token = "access-" + tokensEmitidos.size();
                        tokensEmitidos.put(token, String.join(",", new TreeSet<>(g.authorities())));
                        return token;
                    }
                    @Override public Duration accessTokenTtl() { return Duration.ofMinutes(15); }
                },
                new RefreshTokenStoreFalso());
    }

    /**
     * Almacén en memoria con la misma semántica que el real: los registros no
     * se borran al consumirse (hace falta detectar la reutilización), rotate()
     * distingue familia desconocida de familia revocada, y consumir un token ya
     * usado revoca toda la familia.
     */
    private static final class RefreshTokenStoreFalso implements RefreshTokenStore {

        private record Registro(UUID userId, UUID appId, UUID familyId, boolean usado) {}

        private final Map<String, Registro> tokens = new LinkedHashMap<>();
        private final Set<UUID> familiasRevocadas = new HashSet<>();
        private int n;

        @Override public IssuedRefreshToken issue(UUID userId, UUID appId) {
            return crear(userId, appId, UUID.randomUUID());
        }

        @Override public IssuedRefreshToken rotate(UUID familyId) {
            var previo = tokens.values().stream()
                    .filter(r -> r.familyId().equals(familyId))
                    .findFirst()
                    .orElseThrow(() -> new UnknownFamilyException(familyId));
            if (familiasRevocadas.contains(familyId)) {
                throw new RevokedFamilyException(familyId);
            }
            return crear(previo.userId(), previo.appId(), familyId);
        }

        private IssuedRefreshToken crear(UUID userId, UUID appId, UUID familyId) {
            var valor = "refresh-" + (n++);
            tokens.put(valor, new Registro(userId, appId, familyId, false));
            return new IssuedRefreshToken(valor, familyId, Instant.now().plus(Duration.ofHours(12)));
        }

        @Override public Optional<RefreshSubject> consume(String raw) {
            var registro = tokens.get(raw);
            if (registro == null) {
                return Optional.empty();
            }
            if (registro.usado() || familiasRevocadas.contains(registro.familyId())) {
                familiasRevocadas.add(registro.familyId());
                return Optional.empty();
            }
            tokens.put(raw, new Registro(registro.userId(), registro.appId(), registro.familyId(), true));
            return Optional.of(new RefreshSubject(registro.userId(), registro.appId(), registro.familyId()));
        }

        @Override public void revokeFamily(UUID familyId) {
            familiasRevocadas.add(familyId);
        }
    }

    @Test
    void autentica_y_emite_los_dos_tokens() {
        var resultado = servicio.authenticate("token-de-google");

        assertThat(resultado.accessToken()).isEqualTo("access-0");
        assertThat(resultado.refreshToken()).isEqualTo("refresh-0");
        assertThat(tokensEmitidos.get("access-0")).isEqualTo("campanas:leer");
    }

    @Test
    void rechaza_a_quien_no_tiene_ningun_rol_en_la_app() {
        usuarioEnBd = new User(USER_ID, "persona@ejemplo.com", "Persona", true, Set.of());

        assertThatThrownBy(() -> servicio.authenticate("token-de-google"))
                .isInstanceOf(AuthenticationService.AccessDeniedException.class);
    }

    @Test
    void al_renovar_los_permisos_se_releen_de_la_base_de_datos() {
        // ESTE ES EL TEST DE LA ESCALADA DE PRIVILEGIOS.
        //
        // En develop, refresh() hacía JWT.decode(accessToken) -sin verificar
        // firma- y copiaba sus claims al token nuevo. Bastaba fabricar un access
        // token con roles:[admin] y presentarlo con cualquier refresh válido.
        //
        // Aquí refresh() no recibe el access token siquiera, y los permisos
        // salen del repositorio. Si alguien degrada al usuario en la base de
        // datos, la renovación lo refleja.
        var primero = servicio.authenticate("token-de-google");
        assertThat(tokensEmitidos.get(primero.accessToken())).isEqualTo("campanas:leer");

        usuarioEnBd = usuarioCon(Set.of());   // le quitan el permiso

        var renovado = servicio.refresh(primero.refreshToken());

        assertThat(tokensEmitidos.get(renovado.accessToken()))
                .as("los permisos se releen de la BD, no se copian del token anterior")
                .isEmpty();
    }

    @Test
    void al_renovar_un_ascenso_tambien_se_refleja() {
        var primero = servicio.authenticate("token-de-google");

        usuarioEnBd = usuarioCon(Set.of(Permission.parse("*:*")));

        var renovado = servicio.refresh(primero.refreshToken());

        assertThat(tokensEmitidos.get(renovado.accessToken()))
                .isEqualTo("campanas:borrar,campanas:crear,campanas:editar,campanas:leer");
    }

    @Test
    void un_refresh_token_desconocido_se_rechaza() {
        assertThatThrownBy(() -> servicio.refresh("no-emitido"))
                .isInstanceOf(AuthenticationService.AccessDeniedException.class);
    }

    @Test
    void el_logout_revoca_la_familia() {
        var sesion = servicio.authenticate("token-de-google");

        servicio.logout(sesion.refreshToken());

        assertThatThrownBy(() -> servicio.refresh(sesion.refreshToken()))
                .isInstanceOf(AuthenticationService.AccessDeniedException.class);
    }
}
