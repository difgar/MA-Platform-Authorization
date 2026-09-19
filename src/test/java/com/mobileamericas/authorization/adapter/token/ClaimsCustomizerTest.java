package com.mobileamericas.authorization.adapter.token;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.UserRepository;
import com.mobileamericas.authorization.domain.App;
import com.mobileamericas.authorization.domain.Permission;
import com.mobileamericas.authorization.domain.Role;
import com.mobileamericas.authorization.domain.User;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.LIST;

/**
 * El punto donde el RBAC de la fase 1 se enchufa a la emisión del framework.
 * AccessGrant, Permission y Verb ya están probados aparte (AccessGrantTest):
 * aquí sólo se comprueba que ClaimsCustomizer los llama en el token correcto,
 * con el email/nombre/avatar de la resolución 16 y sin caché entre emisiones.
 */
class ClaimsCustomizerTest {

    private static final UUID APP_ID = UUID.randomUUID();
    private static final App APP = new App(
            APP_ID, "admin", "https://admin.example", true,
            List.of("https://admin.example/callback"), List.of(), null);
    private static final Set<String> CATALOGO = Set.of("usuarios", "roles");

    private static final String EMAIL = "usuario1@pendiente.local";

    private final FakeUserRepository usuarios = new FakeUserRepository();
    private final FakeAppRepository apps = new FakeAppRepository();
    private final ClaimsCustomizer customizador = new ClaimsCustomizer(usuarios, apps);

    @Test
    void el_access_token_lleva_los_permisos_expandidos_de_la_app() {
        usuarios.registrar(usuarioAdmin(EMAIL, "Persona Uno"));
        var ctx = contextoDeAccessTokenPara(EMAIL, "admin");

        customizador.customize(ctx);

        assertThat(ctx.getClaims().build().<Object>getClaim("permissions"))
                .asInstanceOf(LIST).contains("usuarios:borrar", "roles:editar");
        assertThat(ctx.getClaims().build().<Object>getClaim("roles"))
                .asInstanceOf(LIST).containsExactly("admin");
    }

    /**
     * Ruling 16: el email es el identificador que el resto de la plataforma ya
     * usa para saber quién hizo algo, así que viaja también en el access token.
     *
     * Este comentario decía que 'sub' es «un UUID opaco» y que por eso hacía
     * falta el email. Es falso desde la tarea 6: el framework pone en 'sub' el
     * nombre del principal, que es el email normalizado (ver ClaimsCustomizer,
     * y FlujoCompletoIT, que lo afirma sobre un token real). El motivo de
     * emitir 'email' sigue en pie, pero es otro: 'sub' es por contrato un
     * identificador OPACO, y un consumidor que lo lea como una dirección de
     * correo se apoya en un detalle de implementación de este emisor.
     */
    @Test
    void el_access_token_lleva_tambien_el_email_del_usuario() {
        usuarios.registrar(usuarioAdmin(EMAIL, "Persona Uno"));
        var ctx = contextoDeAccessTokenPara(EMAIL, "admin");

        customizador.customize(ctx);

        assertThat(ctx.getClaims().build().<Object>getClaim("email")).isEqualTo(EMAIL);
        assertThat(ctx.getClaims().build().<Object>getClaim("uid"))
                .as("el identificador estable va también en el access token: es con el que se audita")
                .isEqualTo(usuarios.idDe(EMAIL).toString());
    }

    /**
     * A propósito, una sola prueba con varias aserciones positivas junto a la
     * negativa: un customizador que no hiciera NADA dejaría 'permissions' en
     * null igual que uno correcto, así que esa aserción sola no discrimina.
     * Emparejarla con email/name/picture -que sólo aparecen si el código
     * realmente actúa- es lo que hace fallar la prueba si alguien la vuelve
     * un no-op.
     */
    @Test
    void el_id_token_lleva_identidad_pero_no_permisos() {
        usuarios.registrar(usuarioAdmin(EMAIL, "Persona Uno"));
        var ctx = contextoDeIdTokenPara(EMAIL, "admin", "https://google.example/avatar.png");

        customizador.customize(ctx);

        var claims = ctx.getClaims().build();
        assertThat(claims.<Object>getClaim("email")).isEqualTo(EMAIL);
        assertThat(claims.<Object>getClaim("uid")).isEqualTo(usuarios.idDe(EMAIL).toString());
        assertThat(claims.<Object>getClaim("name")).isEqualTo("Persona Uno");
        assertThat(claims.<Object>getClaim("picture")).isEqualTo("https://google.example/avatar.png");
        assertThat(claims.<Object>getClaim("permissions")).isNull();
        assertThat(claims.<Object>getClaim("roles")).isNull();
        // 'apps' son las aplicaciones donde este usuario obtendría un token, no
        // aquellas donde tiene rol: la misma regla que aplica el validador de
        // /authorize, para que el menú y la puerta no se contradigan.
        assertThat(claims.<Object>getClaim("apps"))
                .isEqualTo(List.of(Map.of("name", "admin", "url", "https://admin.example")));
    }

    /**
     * full_name es NULLABLE en el esquema; el mismo criterio que aplicaba
     * RsaTokenIssuer en la fase 1 (fix: "el emisor omite el claim name en
     * vez de fallar con nombre nulo"): un claim ausente, no null ni "".
     */
    @Test
    void el_id_token_omite_el_claim_name_si_el_usuario_no_tiene_nombre() {
        usuarios.registrar(usuarioAdmin(EMAIL, null));
        var ctx = contextoDeIdTokenPara(EMAIL, "admin", null);

        customizador.customize(ctx);

        var claims = ctx.getClaims().build();
        assertThat(claims.hasClaim("name")).as("el claim debe estar ausente, no nulo ni vacío").isFalse();
        // Discrimina el mismo no-op que el comentario de arriba: si el
        // customizador no tocara nada, 'email' tampoco aparecería.
        assertThat(claims.<Object>getClaim("email")).isEqualTo(EMAIL);
    }

    /** Si Google no manda avatar, el claim se omite, no se manda vacío ni null. */
    @Test
    void el_id_token_omite_el_claim_picture_si_google_no_lo_manda() {
        usuarios.registrar(usuarioAdmin(EMAIL, "Persona Uno"));
        var ctx = contextoDeIdTokenPara(EMAIL, "admin", null);

        customizador.customize(ctx);

        var claims = ctx.getClaims().build();
        assertThat(claims.hasClaim("picture")).as("sin avatar de Google, el claim no debe estar").isFalse();
        assertThat(claims.<Object>getClaim("name")).isEqualTo("Persona Uno");
    }

    /**
     * El mismo guardián que la fase 1: si alguien degrada al usuario, el
     * siguiente token lo refleja. Nada se cachea entre emisiones.
     */
    @Test
    void los_permisos_salen_del_repositorio_en_cada_emision() {
        usuarios.registrar(usuarioAdmin(EMAIL, "Persona Uno"));

        var ctx1 = contextoDeAccessTokenPara(EMAIL, "admin");
        customizador.customize(ctx1);
        assertThat(ctx1.getClaims().build().<Object>getClaim("permissions")).asInstanceOf(LIST).isNotEmpty();

        degradarAlUsuarioSinPermisos();

        var ctx2 = contextoDeAccessTokenPara(EMAIL, "admin");
        customizador.customize(ctx2);
        assertThat(ctx2.getClaims().build().<Object>getClaim("permissions")).asInstanceOf(LIST).isEmpty();
    }

    private void degradarAlUsuarioSinPermisos() {
        usuarios.registrar(new User(usuarios.idDe(EMAIL), EMAIL, "Persona Uno", true, Set.of()));
    }

    private static User usuarioAdmin(String email, String fullName) {
        var rol = new Role(UUID.randomUUID(), "admin", APP_ID, Set.of(Permission.parse("*:*")));
        return new User(UUID.randomUUID(), email, fullName, true, Set.of(rol));
    }

    private JwtEncodingContext contextoDeAccessTokenPara(String email, String clientId) {
        return contexto(email, clientId, OAuth2TokenType.ACCESS_TOKEN, null);
    }

    private JwtEncodingContext contextoDeIdTokenPara(String email, String clientId, String picture) {
        return contexto(email, clientId, new OAuth2TokenType(OidcParameterNames.ID_TOKEN), picture);
    }

    private JwtEncodingContext contexto(String email, String clientId, OAuth2TokenType tokenType, String picture) {
        var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://admin.example/callback")
                .scope("openid")
                .build();

        return JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256), JwtClaimsSet.builder())
                .registeredClient(registeredClient)
                .principal(new OAuth2AuthenticationToken(oidcUserDe(email, picture), List.of(), "google"))
                .tokenType(tokenType)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .build();
    }

    private static OidcUser oidcUserDe(String email, String picture) {
        var atributos = new HashMap<String, Object>();
        atributos.put("email", email);
        if (picture != null) {
            atributos.put("picture", picture);
        }
        return new OidcUserDePrueba(email, Map.copyOf(atributos));
    }

    /**
     * El OidcUser que sostiene la sesión SSO, reducido a lo que
     * ClaimsCustomizer necesita: el nombre del principal (email normalizado,
     * igual que fija UsuarioOidcService) y los atributos crudos de Google, de
     * donde sale 'picture'. getUserInfo() e getIdToken() no los toca el
     * customizador, así que no hace falta construir un OidcIdToken real.
     */
    private record OidcUserDePrueba(String email, Map<String, Object> attributes) implements OidcUser {

        @Override
        public Map<String, Object> getAttributes() {
            return attributes;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return Set.of();
        }

        @Override
        public String getName() {
            return email;
        }

        @Override
        public Map<String, Object> getClaims() {
            return attributes;
        }

        @Override
        public OidcUserInfo getUserInfo() {
            return null;
        }

        @Override
        public OidcIdToken getIdToken() {
            return null;
        }
    }

    /** En memoria y mutable a propósito: hace falta para el guardián de "sin caché". */
    private static final class FakeUserRepository implements UserRepository {

        private final Map<String, User> porEmail = new HashMap<>();

        void registrar(User usuario) {
            porEmail.put(usuario.email(), usuario);
        }

        UUID idDe(String email) {
            return porEmail.get(email).id();
        }

        @Override
        public Optional<User> findByEmail(String email) {
            return Optional.ofNullable(porEmail.get(email));
        }
    }

    private static final class FakeAppRepository implements AppRepository {

        @Override
        public Optional<App> findByName(String name) {
            return APP.name().equals(name) ? Optional.of(APP) : Optional.empty();
        }

        @Override
        public Optional<App> findById(UUID id) {
            return APP_ID.equals(id) ? Optional.of(APP) : Optional.empty();
        }

        @Override
        public Set<String> resourceCatalogue(UUID appId) {
            return APP_ID.equals(appId) ? CATALOGO : Set.of();
        }
    }
}
