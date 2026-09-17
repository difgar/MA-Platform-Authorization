package com.mobileamericas.authorization.adapter.google;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.IdentityVerifier;
import com.mobileamericas.authorization.domain.App;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GoogleIdentityVerifierTest {

    private static final String GOOGLE_ISS = "https://accounts.google.com";

    // Se lee de GoogleProperties en vez de repetir la lista literal: así el
    // decodificador de prueba nunca puede desincronizarse de lo que
    // BeansConfig monta en producción (ambas formas del 'iss' de Google).
    private static final List<String> ISS_ACEPTADOS = new GoogleProperties(null, null).acceptedIssuers();

    private static final App ADMIN =
            new App(UUID.randomUUID(), "admin", "cliente-admin", null, true);
    private static final App BETA_INACTIVA =
            new App(UUID.randomUUID(), "beta", "cliente-beta", null, false);

    private RSAKey clave;
    private GoogleIdentityVerifier verificador;

    /** Repositorio de apps mínimo, en memoria: esta capa no necesita base de datos. */
    private static AppRepository apps() {
        return new AppRepository() {
            @Override public Optional<App> findByGoogleClientId(String id) {
                return switch (id) {
                    case "cliente-admin" -> Optional.of(ADMIN);
                    case "cliente-beta" -> Optional.of(BETA_INACTIVA);
                    default -> Optional.empty();
                };
            }
            @Override public Optional<App> findByName(String n) {
                return "admin".equals(n) ? Optional.of(ADMIN) : Optional.empty();
            }
            @Override public Optional<App> findById(UUID id) {
                return ADMIN.id().equals(id) ? Optional.of(ADMIN) : Optional.empty();
            }
            @Override public Set<String> resourceCatalogue(UUID appId) { return Set.of("usuarios"); }
        };
    }

    @BeforeEach
    void preparar() throws Exception {
        clave = new RSAKeyGenerator(2048).keyID("google-falso").generate();
        // Se inyecta un decodificador con la clave del test: la suite no habla
        // con Google. En producción el decodificador apunta al JWKS de Google.
        var decodificador = NimbusJwtDecoder.withPublicKey(clave.toRSAPublicKey()).build();
        // JwtValidators.createDefault() solo comprueba exp/nbf, no el emisor.
        // Se replica aquí la misma composición de validadores que
        // BeansConfig.googleJwtDecoder monta en producción, para que los tests
        // de emisor ajeno prueben algo real y no un decodificador más permisivo
        // que el de producción.
        decodificador.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefault(),
                new JwtClaimValidator<String>("iss",
                        iss -> iss != null && ISS_ACEPTADOS.contains(iss))));
        verificador = new GoogleIdentityVerifier(decodificador, apps());
    }

    private String tokenFirmadoCon(RSAKey clave, String iss, List<String> aud, String email, Instant expira) {
        return tokenFirmadoCon(clave, iss, aud, email, expira, Boolean.TRUE);
    }

    /**
     * @param emailVerified valor del claim 'email_verified'; {@code null} lo omite
     *                       por completo (para probar el caso "claim ausente").
     */
    private String tokenFirmadoCon(RSAKey clave, String iss, List<String> aud, String email, Instant expira,
                                    Boolean emailVerified) {
        var encoder = new NimbusJwtEncoder(new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(
                new com.nimbusds.jose.jwk.JWKSet(clave)));
        var builder = JwtClaimsSet.builder()
                .issuer(iss)
                .subject("1234567890")
                // 'issuedAt' fijo en el pasado, no relativo a 'expira': el test de
                // caducidad pide un 'expiresAt' ya pasado, y JwtClaimsSet exige
                // expiresAt > issuedAt sin importar la hora actual.
                .issuedAt(Instant.now().minus(2, ChronoUnit.HOURS))
                .expiresAt(expira);
        if (aud != null && !aud.isEmpty()) {
            builder.audience(aud);
        }
        if (email != null) {
            builder.claim("email", email).claim("name", "Persona de Prueba");
            if (emailVerified != null) {
                builder.claim("email_verified", emailVerified);
            }
        }
        var header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(clave.getKeyID()).build();
        return encoder.encode(JwtEncoderParameters.from(header, builder.build())).getTokenValue();
    }

    private String tokenDeGoogleCon(String aud, String email, Instant expira) {
        return tokenFirmadoCon(clave, GOOGLE_ISS, List.of(aud), email, expira);
    }

    @Test
    void resuelve_la_app_a_partir_del_audience() {
        var token = tokenDeGoogleCon("cliente-admin", "persona@ejemplo.com",
                Instant.now().plus(1, ChronoUnit.HOURS));

        var identidad = verificador.verify(token);

        assertThat(identidad.email()).isEqualTo("persona@ejemplo.com");
        assertThat(identidad.fullName()).isEqualTo("Persona de Prueba");
        assertThat(identidad.app().name()).isEqualTo("admin");
    }

    @Test
    void resuelve_la_app_aunque_la_coincidencia_sea_la_segunda_audiencia() {
        // 'aud' puede traer varios valores; la resolución no debe mirar solo
        // el primero.
        var token = tokenFirmadoCon(clave, GOOGLE_ISS,
                List.of("cliente-desconocido", "cliente-admin"), "persona@ejemplo.com",
                Instant.now().plus(1, ChronoUnit.HOURS));

        var identidad = verificador.verify(token);

        assertThat(identidad.app().name()).isEqualTo("admin");
    }

    @Test
    void rechaza_un_audience_que_no_corresponde_a_ninguna_app() {
        var token = tokenDeGoogleCon("cliente-desconocido", "persona@ejemplo.com",
                Instant.now().plus(1, ChronoUnit.HOURS));

        assertThatThrownBy(() -> verificador.verify(token))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class)
                .hasMessageContaining("aplicación");
    }

    @Test
    void rechaza_un_token_sin_audience() {
        var token = tokenFirmadoCon(clave, GOOGLE_ISS, null, "persona@ejemplo.com",
                Instant.now().plus(1, ChronoUnit.HOURS));

        assertThatThrownBy(() -> verificador.verify(token))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class)
                .hasMessageContaining("audiencia");
    }

    @Test
    void rechaza_una_app_desactivada() {
        var token = tokenDeGoogleCon("cliente-beta", "persona@ejemplo.com",
                Instant.now().plus(1, ChronoUnit.HOURS));

        assertThatThrownBy(() -> verificador.verify(token))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class)
                .hasMessageContaining("desactivada");
    }

    @Test
    void rechaza_un_token_caducado() {
        var token = tokenDeGoogleCon("cliente-admin", "persona@ejemplo.com",
                Instant.now().minus(1, ChronoUnit.MINUTES));

        assertThatThrownBy(() -> verificador.verify(token))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class);
    }

    @Test
    void rechaza_un_token_con_firma_ajena() throws Exception {
        var otraClave = new RSAKeyGenerator(2048).keyID("google-falso").generate();
        var falso = tokenFirmadoCon(otraClave, GOOGLE_ISS, List.of("cliente-admin"),
                "intruso@ejemplo.com", Instant.now().plus(1, ChronoUnit.HOURS));

        assertThatThrownBy(() -> verificador.verify(falso))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class);
    }

    @Test
    void acepta_la_forma_sin_esquema_del_emisor_de_google() throws Exception {
        // Google emite ID token con 'iss' tanto en forma de URL
        // ('https://accounts.google.com') como en forma pelada, sin esquema
        // ('accounts.google.com'); ambas son legítimas. El fix de la ronda
        // anterior solo probaba el rechazo de un emisor ajeno usando la forma
        // CON esquema para el token válido de referencia — esta es la
        // positiva que le faltaba: que la forma SIN esquema, la razón de ser
        // del fix, se acepte de verdad.
        var sinEsquema = tokenFirmadoCon(clave, "accounts.google.com", List.of("cliente-admin"),
                "persona@ejemplo.com", Instant.now().plus(1, ChronoUnit.HOURS));

        var identidad = verificador.verify(sinEsquema);

        assertThat(identidad.email()).isEqualTo("persona@ejemplo.com");
        assertThat(identidad.app().name()).isEqualTo("admin");

        // El claim 'iss' llega como java.lang.String en tiempo de ejecución
        // para LAS DOS formas (comprobado con un decodificador aparte, sin el
        // validador de emisor, para no interferir con la aserción de arriba):
        // si el tipo difiriera entre formas, el mismo
        // JwtClaimValidator<String> no podría ser correcto para ambas y este
        // test estaría pasando por una razón distinta a la que dice probar.
        var decodificadorSinValidarEmisor = NimbusJwtDecoder.withPublicKey(clave.toRSAPublicKey()).build();
        var conEsquema = tokenFirmadoCon(clave, GOOGLE_ISS, List.of("cliente-admin"),
                "persona@ejemplo.com", Instant.now().plus(1, ChronoUnit.HOURS));
        Object issSinEsquema = decodificadorSinValidarEmisor.decode(sinEsquema).getClaim("iss");
        Object issConEsquema = decodificadorSinValidarEmisor.decode(conEsquema).getClaim("iss");
        assertThat(issSinEsquema).isInstanceOf(String.class);
        assertThat(issConEsquema).isInstanceOf(String.class);
    }

    @Test
    void rechaza_un_emisor_ajeno_aunque_la_firma_sea_valida() {
        // Firmado con la clave correcta, pero un 'iss' que no es ninguna de las
        // dos formas legítimas de Google: sin validar 'iss', este token pasaría
        // igual porque su firma y su 'aud' son válidos.
        var token = tokenFirmadoCon(clave, "https://impostor.example.com", List.of("cliente-admin"),
                "persona@ejemplo.com", Instant.now().plus(1, ChronoUnit.HOURS));

        assertThatThrownBy(() -> verificador.verify(token))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class);
    }

    @Test
    void rechaza_un_token_sin_email() {
        var sinEmail = tokenFirmadoCon(clave, GOOGLE_ISS, List.of("cliente-admin"), null,
                Instant.now().plus(1, ChronoUnit.HOURS));

        assertThatThrownBy(() -> verificador.verify(sinEmail))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class)
                .hasMessageContaining("email");
    }

    @Test
    void rechaza_un_email_no_verificado() {
        // La guía de Google sobre verificación de ID token es explícita:
        // email_verified: false significa que ese email no prueba propiedad.
        var noVerificado = tokenFirmadoCon(clave, GOOGLE_ISS, List.of("cliente-admin"),
                "persona@ejemplo.com", Instant.now().plus(1, ChronoUnit.HOURS), false);

        assertThatThrownBy(() -> verificador.verify(noVerificado))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class)
                .hasMessageContaining("verificad");
    }

    @Test
    void rechaza_un_token_sin_el_claim_email_verified() {
        // Ausente se trata como no verificado, no como verificado por omisión:
        // es la lectura más segura para el único join key con auth_user.
        var sinClaim = tokenFirmadoCon(clave, GOOGLE_ISS, List.of("cliente-admin"),
                "persona@ejemplo.com", Instant.now().plus(1, ChronoUnit.HOURS), null);

        assertThatThrownBy(() -> verificador.verify(sinClaim))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class)
                .hasMessageContaining("verificad");
    }

    @Test
    void normaliza_el_email_a_minusculas() {
        // MySQL (utf8mb4_0900_ai_ci) compara sin distinguir mayúsculas y
        // PostgreSQL sí: sin normalizar aquí, el mismo login de Google
        // autenticaría en un motor y no en el otro según cómo quedó guardado
        // el email.
        var token = tokenDeGoogleCon("cliente-admin", "Persona.Ejemplo@Gmail.COM",
                Instant.now().plus(1, ChronoUnit.HOURS));

        var identidad = verificador.verify(token);

        assertThat(identidad.email()).isEqualTo("persona.ejemplo@gmail.com");
    }
}
